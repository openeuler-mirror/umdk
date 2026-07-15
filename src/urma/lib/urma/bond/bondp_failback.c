/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider failback helpers.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bondp_context_table.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "ub_hmap.h"
#include "ubagg_ioctl.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_provider.h"
#include "urma_types.h"

#include "bondp_failback.h"

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

#define BONDP_FB_TASK_HASH_BASIS    0x9d4f21U
#define BONDP_FB_TASK_TABLE_SIZE    1024U
/* Delay (ms) before rebuilding a failed-back pjetty on the bond worker. */
#define BONDP_FB_REBUILD_DELAY_MS   2000U
/* Delay (ms) before publishing the rebuild_done flag after a rebuild; the
 * worker enforces a minimum of one tick. */
#define BONDP_FB_MARK_DONE_DELAY_MS 0U

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

static void fb_task_put(bondp_fb_task_t *fb_task)
{
    if (atomic_fetch_sub(&fb_task->use_cnt.atomic_cnt, 1) == 1) {
        fb_task_free(fb_task);
    }
}

static bondp_fb_task_t *fb_task_get(bondp_fb_ctx_t *fb_ctx, const bondp_fb_task_key_t *key)
{
    uint32_t hash = fb_task_hash_key(key);
    bondp_fb_task_t *fb_task = NULL;

    (void)pthread_rwlock_rdlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &fb_ctx->task_map) {
        if (!fb_task_matches_key(&fb_task->hmap_node, key)) {
            continue;
        }
        atomic_fetch_add(&fb_task->use_cnt.atomic_cnt, 1);
        (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
        return fb_task;
    }
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    return NULL;
}

static void fb_task_set_worker_task_id(bondp_fb_ctx_t *fb_ctx, bondp_fb_task_t *fb_task,
                                       bondp_worker_task_id_t worker_task_id)
{
    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    fb_task->worker_task_id = worker_task_id;
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
}

static int fb_task_del(bondp_fb_ctx_t *fb_ctx, const bondp_fb_task_key_t *key);

static void fb_task_table_destroy(bondp_fb_ctx_t *fb_ctx)
{
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_t *next = NULL;

    /* A rebuild task can only transition once, to a mark-done task. */
    for (uint32_t round = 0; round < 2; round++) {
        size_t task_num = 0;

        (void)pthread_rwlock_rdlock(&fb_ctx->task_lock);
        uint32_t task_count = ub_hmap_count(&fb_ctx->task_map);
        if (task_count == 0) {
            (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
            break;
        }

        bondp_worker_task_id_t *task_ids = calloc(task_count, sizeof(*task_ids));
        if (task_ids == NULL) {
            (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
            URMA_LOG_WARN("Failed to allocate failback task IDs.\n");
            break;
        }

        HMAP_FOR_EACH (fb_task, hmap_node, &fb_ctx->task_map) {
            if (fb_task->worker_task_id != 0) {
                task_ids[task_num++] = fb_task->worker_task_id;
            }
        }
        (void)pthread_rwlock_unlock(&fb_ctx->task_lock);

        int ret = task_num == 0 ? 0 : bondp_worker_cancel_batch(task_ids, task_num);
        free(task_ids);
        if (ret != 0) {
            URMA_LOG_WARN("Failed to cancel failback tasks, ret=%d.\n", ret);
            break;
        }
    }

    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_SAFE (fb_task, next, hmap_node, &fb_ctx->task_map) {
        ub_hmap_remove(&fb_ctx->task_map, &fb_task->hmap_node);
        fb_task_put(fb_task);
    }
    ub_hmap_destroy(&fb_ctx->task_map);
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    (void)pthread_rwlock_destroy(&fb_ctx->task_lock);
    free(fb_ctx);
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

typedef struct bondp_fb_mark_done_arg {
    bondp_fb_ctx_t *fb_ctx;
    bondp_fb_task_key_t key;
    bondp_fb_task_t *fb_task;
    bondp_comp_t *bdp_jetty;
    uint32_t pjetty_idx;
} bondp_fb_mark_done_arg_t;

static void bondp_mark_rebuild_done_async(bondp_worker_task_reason_t reason, void *arg)
{
    bondp_fb_mark_done_arg_t *arg_typed = arg;

    if (arg_typed == NULL) {
        return;
    }

    if (reason == BONDP_WORKER_TASK_EXECUTED && arg_typed->bdp_jetty != NULL &&
        arg_typed->pjetty_idx < URMA_UBAGG_DEV_MAX_NUM) {
        atomic_store(&arg_typed->bdp_jetty->rebuild_done[arg_typed->pjetty_idx], true);
    }

    if (arg_typed->fb_ctx != NULL) {
        (void)fb_task_del(arg_typed->fb_ctx, &arg_typed->key);
    }

    if (arg_typed->fb_task != NULL) {
        fb_task_put(arg_typed->fb_task);
    }
    free(arg_typed);
}

static void bondp_rebuild_pjetty_async(bondp_worker_task_reason_t reason, void *arg)
{
    bondp_fb_async_arg_t *arg_typed = (bondp_fb_async_arg_t *)arg;
    if (arg_typed == NULL) {
        return;
    }
    if (reason == BONDP_WORKER_TASK_CANCELED) {
        if (arg_typed->fb_ctx != NULL) {
            (void)fb_task_del(arg_typed->fb_ctx, &arg_typed->key);
        }
        goto free_arg;
    }

    bondp_fb_ctx_t *fb_ctx = arg_typed->fb_ctx;
    if (fb_ctx == NULL) {
        goto free_arg;
    }

    bondp_fb_task_t *fb_task = fb_task_get(fb_ctx, &arg_typed->key);
    if (fb_task == NULL) {
        goto free_arg;
    }
    bondp_comp_t *bdp_jetty = bondp_find_jetty_by_vjetty_id(fb_task->bond_ctx, fb_task->vjetty_id);
    if (bdp_jetty == NULL) {
        URMA_LOG_ERR("Failed to rebuild failback pjetty, vjetty_id=%u, pjetty_idx=%u.\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx);
        goto del_task;
    }

    int ret = bondp_rebuild_pjetty(bdp_jetty, (int)fb_task->pjetty_idx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to rebuild failback pjetty, vjetty_id=%u, pjetty_idx=%u.\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx);
        goto del_task;
    }

    bondp_fb_mark_done_arg_t *mark_arg = calloc(1, sizeof(*mark_arg));
    if (mark_arg == NULL) {
        URMA_LOG_ERR("Failed to alloc mark-done arg, vjetty_id=%u, pjetty_idx=%u, flag stays unset.\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx);
        goto del_task;
    }
    mark_arg->fb_ctx = fb_ctx;
    mark_arg->key = arg_typed->key;
    mark_arg->fb_task = fb_task;
    mark_arg->bdp_jetty = bdp_jetty;
    mark_arg->pjetty_idx = fb_task->pjetty_idx;

    uint64_t mark_done_task_id = 0;
    ret = bondp_worker_schedule(BONDP_FB_MARK_DONE_DELAY_MS, bondp_mark_rebuild_done_async,
                                mark_arg, &mark_done_task_id);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to schedule mark-done task, vjetty_id=%u, pjetty_idx=%u, ret=%d\n",
                     fb_task->vjetty_id, fb_task->pjetty_idx, ret);
        free(mark_arg);
        goto del_task;
    }
    fb_task_set_worker_task_id(fb_ctx, fb_task, mark_done_task_id);

    /* The mark-done task now owns fb_task; only free arg_typed and return. */
    free(arg_typed);
    return;

del_task:
    (void)fb_task_del(fb_ctx, &arg_typed->key);
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

    bondp_fb_task_key_t key = {
        .vjetty_id = vjetty_id,
        .pjetty_idx = pjetty_idx,
    };
    uint32_t hash = fb_task_hash_key(&key);
    bondp_fb_async_arg_t *async_arg = calloc(1, sizeof(*async_arg));
    if (async_arg == NULL) {
        free(fb_task);
        return -ENOMEM;
    }
    async_arg->fb_ctx = fb_ctx;
    async_arg->key = key;

    bondp_fb_task_t *existing_task = NULL;
    int ret = 0;

    (void)pthread_rwlock_wrlock(&fb_ctx->task_lock);
    HMAP_FOR_EACH_WITH_HASH (existing_task, hmap_node, hash, &fb_ctx->task_map) {
        if (fb_task_matches_key(&existing_task->hmap_node, &key)) {
            ret = -EEXIST;
            goto out_unlock;
        }
    }

    ub_hmap_insert(&fb_ctx->task_map, &fb_task->hmap_node, hash);
    ret = bondp_worker_schedule(BONDP_FB_REBUILD_DELAY_MS, bondp_rebuild_pjetty_async, async_arg,
                                &fb_task->worker_task_id);
    if (ret != 0) {
        ub_hmap_remove(&fb_ctx->task_map, &fb_task->hmap_node);
        URMA_LOG_ERR("Failed to schedule failback task, vjetty_id=%u, pjetty_idx=%u, ret=%d.\n",
                     vjetty_id, pjetty_idx, ret);
    }

out_unlock:
    (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
    if (ret != 0) {
        free(async_arg);
        fb_task_put(fb_task);
        return ret;
    }

    return 0;
}

void bondp_fb_cancel_tasks(bondp_context_t *bond_ctx, uint32_t vjetty_id)
{
    bondp_fb_ctx_t *fb_ctx;
    bondp_fb_task_t *fb_task = NULL;
    bondp_worker_task_id_t task_ids[URMA_UBAGG_DEV_MAX_NUM];
    size_t task_num = 0;

    if (bond_ctx == NULL || bond_ctx->fb_ctx == NULL) {
        return;
    }
    fb_ctx = bond_ctx->fb_ctx;

    /* A rebuild task can only transition once, to a mark-done task. */
    for (uint32_t round = 0; round < 2; round++) {
        task_num = 0;
        (void)pthread_rwlock_rdlock(&fb_ctx->task_lock);
        HMAP_FOR_EACH (fb_task, hmap_node, &fb_ctx->task_map) {
            if (fb_task->vjetty_id == vjetty_id && fb_task->worker_task_id != 0 &&
                task_num < URMA_UBAGG_DEV_MAX_NUM) {
                task_ids[task_num++] = fb_task->worker_task_id;
            }
        }
        (void)pthread_rwlock_unlock(&fb_ctx->task_lock);
        if (task_num == 0) {
            return;
        }

        int ret = bondp_worker_cancel_batch(task_ids, task_num);
        if (ret != 0) {
            URMA_LOG_WARN("Failed to cancel jetty failback tasks, vjetty_id=%u, ret=%d.\n",
                          vjetty_id, ret);
            return;
        }
        /* The second round cancels a mark-done task installed by an executing rebuild. */
    }
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
