/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider failback netlink helpers.
 */

#include <errno.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bondp_context_table.h"
#include "bondp_netlink.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "ub_hmap.h"
#include "ubagg_ioctl.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_provider.h"
#include "urma_types.h"

#include "bondp_failback.h"

typedef struct bondp_nl_fb_task {
    uint32_t request_id;
    uint32_t peer_node_id;
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
    uint32_t new_pjetty_id;
} bondp_nl_fb_task_t;

typedef struct bondp_nl_fb_result {
    uint32_t request_id;
    uint32_t peer_node_id;
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
    uint32_t new_pjetty_id;
    int32_t result;
} bondp_nl_fb_result_t;

typedef struct bondp_fb_task_key {
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
} bondp_fb_task_key_t;

typedef struct bondp_fb_task {
    struct ub_hmap_node hmap_node;
    urma_ref_t use_cnt;
    bondp_context_t *bond_ctx;
    bondp_worker_task_id_t worker_task_id;
    uint32_t request_id;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
} bondp_fb_task_t;

struct bondp_fb_ctx {
    struct ub_hmap task_map;
    pthread_rwlock_t task_lock;
#ifndef __cplusplus
    atomic_uint request_id;
#else
    std::atomic_uint request_id;
#endif
};

#define BONDP_FB_TASK_HASH_BASIS 0x9d4f21U
#define BONDP_FB_TASK_TABLE_SIZE 1024U

static uint32_t next_request_id(bondp_fb_ctx_t *fb_ctx)
{
    return atomic_fetch_add(&fb_ctx->request_id, 1) + 1;
}

static void init_request_id(bondp_fb_ctx_t *fb_ctx)
{
    struct timespec ts = {0};
    uint32_t seed;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        seed = (uint32_t)getpid();
    } else {
        seed = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec ^ (uint32_t)getpid();
    }

    atomic_store(&fb_ctx->request_id, seed);
}

static bool fb_task_matches_key(const struct ub_hmap_node *node, const bondp_fb_task_key_t *key)
{
    const bondp_fb_task_t *fb_task = CONTAINER_OF_FIELD(node, bondp_fb_task_t, hmap_node);

    return fb_task->vjetty_id == key->vjetty_id &&
           fb_task->pjetty_idx == key->pjetty_idx;
}

static uint32_t fb_task_hash_key(const bondp_fb_task_key_t *key)
{
    return ub_hash_bytes(key, sizeof(bondp_fb_task_key_t), BONDP_FB_TASK_HASH_BASIS);
}

static bondp_fb_ctx_t *fb_task_table_create(void)
{
    bondp_fb_ctx_t *fb_ctx = calloc(1, sizeof(*fb_ctx));
    if (fb_ctx == NULL) {
        return NULL;
    }

    if (pthread_rwlock_init(&fb_ctx->task_lock, NULL) != 0) {
        free(fb_ctx);
        return NULL;
    }

    if (ub_hmap_init(&fb_ctx->task_map, BONDP_FB_TASK_TABLE_SIZE) != 0) {
        (void)pthread_rwlock_destroy(&fb_ctx->task_lock);
        free(fb_ctx);
        return NULL;
    }

    return fb_ctx;
}

static void fb_task_free(bondp_fb_task_t *fb_task)
{
    free(fb_task);
}

static void fb_task_get(bondp_fb_task_t *fb_task)
{
    (void)atomic_fetch_add(&fb_task->use_cnt.atomic_cnt, 1);
}

static void fb_task_put(bondp_fb_task_t *fb_task)
{
    if (atomic_fetch_sub(&fb_task->use_cnt.atomic_cnt, 1) == 1) {
        fb_task_free(fb_task);
    }
}

static void fb_task_table_destroy(bondp_fb_ctx_t *fb_ctx)
{
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_t *next = NULL;

    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_SAFE (fb_task, next, hmap_node, &fb_ctx->task_map) {
        if (fb_task->worker_task_id != 0) {
            int ret = bondp_worker_cancel(fb_task->worker_task_id);
            if (ret != 0 && ret != -ENOENT) {
                URMA_LOG_WARN("Failed to cancel failback task, task_id=%lu, ret=%d.\n",
                              fb_task->worker_task_id, ret);
            }
        }
        ub_hmap_remove(&fb_ctx->task_map, &fb_task->hmap_node);
        fb_task_put(fb_task);
    }
    ub_hmap_destroy(&fb_ctx->task_map);
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    (void)pthread_rwlock_destroy(&fb_ctx->task_lock);
    free(fb_ctx);
}

static bondp_fb_task_t *fb_task_lookup(bondp_fb_ctx_t *fb_ctx, const bondp_fb_task_key_t *key)
{
    uint32_t hash = fb_task_hash_key(key);
    bondp_fb_task_t *fb_task = NULL;

    (void)pthread_rwlock_rdlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &fb_ctx->task_map) {
        if (!fb_task_matches_key(&fb_task->hmap_node, key)) {
            continue;
        }
        fb_task_get(fb_task);
        break;
    }
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    return fb_task;
}

static int fb_task_add(bondp_fb_ctx_t *fb_ctx, bondp_fb_task_t *task)
{
    bondp_fb_task_key_t key = {
        .vjetty_id = task->vjetty_id,
        .pjetty_idx = task->pjetty_idx,
    };
    uint32_t hash = fb_task_hash_key(&key);
    bondp_fb_task_t *fb_task = NULL;

    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &fb_ctx->task_map) {
        if (!fb_task_matches_key(&fb_task->hmap_node, &key)) {
            continue;
        }
        (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
        return -EEXIST;
    }
    ub_hmap_insert(&fb_ctx->task_map, &task->hmap_node, hash);
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    return 0;
}

static int fb_task_del(bondp_fb_ctx_t *fb_ctx, const bondp_fb_task_key_t *key)
{
    uint32_t hash = fb_task_hash_key(key);
    bondp_fb_task_t *fb_task = NULL;

    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &fb_ctx->task_map) {
        if (!fb_task_matches_key(&fb_task->hmap_node, key)) {
            continue;
        }

        ub_hmap_remove(&fb_ctx->task_map, &fb_task->hmap_node);
        (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
        fb_task_put(fb_task);
        return 0;
    }
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    return -ENOENT;
}

static int bondp_update_pjetty_id_mapping(
    bondp_context_t *bdp_ctx, urma_jetty_id_t old_id,
    urma_jetty_id_t new_id, bondp_comp_t *bdp_jetty)
{
    int ret = 0;

    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, old_id, JETTY);
    if (ret != 0) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete stale pjetty id mapping: " URMA_JETTY_ID_FMT ", ret=%d\n",
                     URMA_JETTY_ID_ARGS(&old_id), ret);
        return -1;
    }
    ret = bdp_p_vjetty_id_table_add_without_lock(
        &bdp_ctx->p_vjetty_id_table, new_id, JETTY, bdp_jetty->v_jetty.jetty_id.id, bdp_jetty);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to add recreated pjetty id mapping: " URMA_JETTY_ID_FMT ", ret=%d\n",
                     URMA_JETTY_ID_ARGS(&new_id), ret);
        return -1;
    }
    return 0;
}

static int bondp_rebuild_pjetty(bondp_comp_t *bdp_jetty, uint32_t local_idx)
{
    int ret;

    if (bdp_jetty == NULL || bdp_jetty->bondp_ctx == NULL ||
        local_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return -1;
    }

    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;

    urma_jetty_t *old_jetty = bdp_jetty->p_jetty[local_idx];
    if (old_jetty == NULL) {
        URMA_LOG_ERR("pjetty at idx=%u is NULL, cannot rebuild\n", local_idx);
        return -1;
    }
    urma_jetty_cfg_t p_cfg = old_jetty->jetty_cfg;
    urma_jetty_id_t old_id = old_jetty->jetty_id;

    urma_jetty_t *new_jetty = urma_create_jetty(bdp_ctx->p_ctxs[local_idx], &p_cfg);
    if (new_jetty == NULL) {
        URMA_LOG_ERR("Failed to recreate pjetty at idx=%d\n", local_idx);
        return -1;
    }

    new_jetty->remote_jetty = NULL;
    new_jetty->jetty_cfg.user_ctx = (uint64_t)bdp_jetty;
    bdp_jetty->p_jetty[local_idx] = new_jetty;

    ret = bondp_update_pjetty_id_mapping(bdp_ctx, old_id, new_jetty->jetty_id, bdp_jetty);
    if (ret != 0) {
        bdp_jetty->p_jetty[local_idx] = old_jetty;
        (void)urma_delete_jetty(new_jetty);
        return -1;
    }

    ret = urma_delete_jetty(old_jetty);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_WARN("Failed to delete old pjetty at idx=%d\n", local_idx);
    }

    atomic_store(&bdp_jetty->rebuild_done[local_idx], true);
    URMA_LOG_INFO("Failback pjetty rebuilt, idx=%d old=" URMA_JETTY_ID_FMT " new=" URMA_JETTY_ID_FMT "\n",
                  local_idx, URMA_JETTY_ID_ARGS(&old_id), URMA_JETTY_ID_ARGS(&new_jetty->jetty_id));
    return 0;
}

static bondp_comp_t *bondp_find_jetty_by_vjetty_id(bondp_context_t *bond_ctx, uint32_t vjetty_id)
{
    bondp_comp_t *bdp_jetty = NULL;

    if (bond_ctx == NULL) {
        return NULL;
    }

    pthread_rwlock_rdlock(&bond_ctx->p_vjetty_id_table.lock);
    bdp_p_vjetty_id_t *item = NULL;
    HMAP_FOR_EACH (item, hmap_node, &bond_ctx->p_vjetty_id_table.hmap) {
        if (item->key.type != JETTY || item->vjetty_id != vjetty_id) {
            continue;
        }
        bdp_jetty = item->comp;
        break;
    }
    pthread_rwlock_unlock(&bond_ctx->p_vjetty_id_table.lock);
    return bdp_jetty;
}

typedef struct bondp_fb_async_arg {
    bondp_fb_ctx_t *fb_ctx;
    bondp_fb_task_key_t key;
} bondp_fb_async_arg_t;

static void bondp_rebuild_pjetty_async(void *arg)
{
    bondp_fb_async_arg_t *arg_typed = arg;
    if (arg_typed == NULL) {
        return;
    }

    bondp_fb_ctx_t *fb_ctx = arg_typed->fb_ctx;
    if (fb_ctx == NULL) {
        goto free_arg;
    }

    bondp_fb_task_t *fb_task = fb_task_lookup(fb_ctx, &arg_typed->key);
    if (fb_task == NULL) {
        goto free_arg;
    }

    bondp_comp_t *bdp_jetty = bondp_find_jetty_by_vjetty_id(fb_task->bond_ctx, fb_task->vjetty_id);
    if (bdp_jetty == NULL) {
        URMA_LOG_ERR("Failed to rebuild failback pjetty, vjetty_id=%u, pjetty_idx=%u.\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx);
        goto put_task;
    }

    int ret = bondp_rebuild_pjetty(bdp_jetty, (int)fb_task->pjetty_idx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to rebuild failback pjetty, vjetty_id=%u, pjetty_idx=%u.\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx);
    }

put_task:
    fb_task_put(fb_task);
free_arg:
    free(arg_typed);
    return;
}

int bondp_fb_add_task(bondp_context_t *bond_ctx, uint32_t vjetty_id, uint32_t pjetty_idx)
{
    if (bond_ctx == NULL || bond_ctx->fb_ctx == NULL) {
        return -EINVAL;
    }

    bondp_fb_ctx_t *fb_ctx = bond_ctx->fb_ctx;
    bondp_fb_task_t *fb_task = calloc(1, sizeof(*fb_task));
    if (fb_task == NULL) {
        return -ENOMEM;
    }

    fb_task->bond_ctx = bond_ctx;
    fb_task->request_id = next_request_id(fb_ctx);
    fb_task->vjetty_id = vjetty_id;
    fb_task->pjetty_idx = pjetty_idx;
    atomic_init(&fb_task->use_cnt.atomic_cnt, 1);

    int ret = fb_task_add(fb_ctx, fb_task);
    if (ret != 0) {
        free(fb_task);
        return ret;
    }

    bondp_fb_task_key_t key = {
        .vjetty_id = vjetty_id,
        .pjetty_idx = pjetty_idx,
    };
    bondp_fb_async_arg_t *async_arg = calloc(1, sizeof(*async_arg));
    if (async_arg == NULL) {
        (void)fb_task_del(fb_ctx, &key);
        return -ENOMEM;
    }
    async_arg->fb_ctx = fb_ctx;
    async_arg->key = key;

    ret = bondp_worker_schedule(1, bondp_rebuild_pjetty_async, async_arg, &fb_task->worker_task_id);
    if (ret != 0) {
        free(async_arg);
        (void)fb_task_del(fb_ctx, &key);
        URMA_LOG_ERR("Failed to schedule failback task, vjetty_id=%u, pjetty_idx=%u, ret=%d.\n",
                     vjetty_id, pjetty_idx, ret);
        return ret;
    }

    return 0;
}

/* In the current failback design, send and receive jettys are user-separated.
 * Since failures are limited to send jettys, which are not imported by peers,
 * rebuilding the local pjetty does not require cluster-wide notifications.
 * The following helpers are retained solely for backward compatibility.
 */
static __attribute__((unused)) int bondp_fb_user_ctl_start(
    bondp_fb_task_t *task, uint32_t node_idx)
{
    bondp_nl_fb_task_t nl_task = {
        .request_id = task->request_id,
        .vjetty_id = task->vjetty_id,
        .pjetty_idx = task->pjetty_idx,
    };

    urma_user_ctl_in_t in = {
        .opcode = FAILBACK_START,
        .addr = (uint64_t)(uintptr_t)&nl_task,
        .len = sizeof(nl_task),
    };
    urma_user_ctl_out_t out = {0};
    urma_udrv_t udrv = {0};

    bondp_context_t *bond_ctx = task->bond_ctx;
    return urma_cmd_user_ctl(&bond_ctx->v_ctx, &in, &out, &udrv);
}

static __attribute__((unused)) int bondp_fb_user_ctl_result(
    bondp_context_t *bdp_ctx, const bondp_nl_fb_result_t *fb_result)
{
    if (bdp_ctx == NULL || fb_result == NULL) {
        return -EINVAL;
    }

    urma_user_ctl_in_t in = {
        .opcode = FAILBACK_RESULT,
        .addr = (uint64_t)(uintptr_t)fb_result,
        .len = sizeof(*fb_result),
    };
    urma_user_ctl_out_t out = {0};
    urma_udrv_t udrv = {0};

    return urma_cmd_user_ctl(&bdp_ctx->v_ctx, &in, &out, &udrv);
}

static void bondp_fb_handle_notify(const bondp_nl_fb_task_t *task)
{
    (void)task;
}

static void bondp_fb_handle_done(const bondp_nl_fb_result_t *result)
{
    (void)result;
}

void bondp_fb_handle_notify_nl_msg(struct nlattr *attrs[])
{
    if (attrs[BONDP_NL_ATTR_PAYLOAD] == NULL) {
        URMA_LOG_WARN("Missing failback notify netlink payload.\n");
        return;
    }

    void *payload = nla_data(attrs[BONDP_NL_ATTR_PAYLOAD]);
    int payload_len = nla_len(attrs[BONDP_NL_ATTR_PAYLOAD]);
    if (payload == NULL || payload_len != (int)sizeof(bondp_nl_fb_task_t)) {
        URMA_LOG_WARN("Invalid failback notify payload len=%d\n", payload_len);
        return;
    }

    bondp_nl_fb_task_t task = {0};
    (void)memcpy(&task, payload, sizeof(task));
    bondp_fb_handle_notify(&task);
}

void bondp_fb_handle_done_nl_msg(struct nlattr *attrs[])
{
    if (attrs[BONDP_NL_ATTR_PAYLOAD] == NULL) {
        URMA_LOG_WARN("Missing failback done netlink payload.\n");
        return;
    }

    void *payload = nla_data(attrs[BONDP_NL_ATTR_PAYLOAD]);
    int payload_len = nla_len(attrs[BONDP_NL_ATTR_PAYLOAD]);
    if (payload == NULL || payload_len != (int)sizeof(bondp_nl_fb_result_t)) {
        URMA_LOG_WARN("Invalid failback done payload len=%d\n", payload_len);
        return;
    }

    bondp_nl_fb_result_t result = {0};
    (void)memcpy(&result, payload, sizeof(result));
    bondp_fb_handle_done(&result);
}

int bondp_fb_init(bondp_context_t *bond_ctx)
{
    if (bond_ctx == NULL) {
        return -EINVAL;
    }

    bond_ctx->fb_ctx = fb_task_table_create();
    if (bond_ctx->fb_ctx == NULL) {
        return -ENOMEM;
    }

    init_request_id(bond_ctx->fb_ctx);
    return 0;
}

void bondp_fb_uninit(bondp_context_t *bond_ctx)
{
    if (bond_ctx == NULL || bond_ctx->fb_ctx == NULL) {
        return;
    }

    fb_task_table_destroy(bond_ctx->fb_ctx);
    bond_ctx->fb_ctx = NULL;
}
