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

#include "bondp_netlink.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "ub_hmap.h"
#include "ubagg_ioctl.h"
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

typedef struct bondp_fb_async_arg {
    bondp_fb_ctx_t *fb_ctx;
    bondp_fb_task_key_t key;
} bondp_fb_async_arg_t;

static void bondp_rebuild_jetty(void *arg)
{
    bondp_fb_async_arg_t *arg_typed = arg;

    if (arg_typed == NULL) {
        return;
    }

    if (arg_typed->fb_ctx == NULL) {
        free(arg_typed);
        return;
    }

    bondp_fb_task_t *fb_task = NULL;
    fb_task = fb_task_lookup(arg_typed->fb_ctx, &arg_typed->key);
    free(arg_typed);
    if (fb_task == NULL) {
        return;
    }

    fb_task_put(fb_task);
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

    ret = bondp_worker_schedule(1, bondp_rebuild_jetty, async_arg, &fb_task->worker_task_id);
    if (ret != 0) {
        free(async_arg);
        (void)fb_task_del(fb_ctx, &key);
        URMA_LOG_ERR("Failed to schedule failback task, vjetty_id=%u, pjetty_idx=%u, ret=%d.\n",
                     vjetty_id, pjetty_idx, ret);
        return ret;
    }

    return 0;
}

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
