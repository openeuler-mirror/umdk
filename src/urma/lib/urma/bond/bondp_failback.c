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
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
} bondp_fb_task_key_t;

typedef struct bondp_fb_task {
    struct ub_hmap_node hmap_node;
    urma_ref_t use_cnt;
    uint32_t request_id;
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
} bondp_fb_task_t;

#define BONDP_FB_TASK_HASH_BASIS 0x9d4f21U
#define BONDP_FB_TASK_TABLE_SIZE 1024U

static struct ub_hmap g_task_map;
static pthread_rwlock_t g_task_lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_uint g_request_id = 0;

static uint32_t next_request_id(void)
{
    return atomic_fetch_add(&g_request_id, 1) + 1;
}

static void init_request_id(void)
{
    struct timespec ts = {0};
    uint32_t seed;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        seed = (uint32_t)getpid();
    } else {
        seed = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec ^ (uint32_t)getpid();
    }

    atomic_store(&g_request_id, seed);
}

static bool fb_task_comp_f(struct ub_hmap_node *node, void *key)
{
    bondp_fb_task_t *fb_task = CONTAINER_OF_FIELD(node, bondp_fb_task_t, hmap_node);
    bondp_fb_task_key_t *fb_key = key;

    return memcmp(&fb_task->src_eid, &fb_key->src_eid, sizeof(fb_task->src_eid)) == 0 &&
           fb_task->vjetty_id == fb_key->vjetty_id &&
           fb_task->pjetty_idx == fb_key->pjetty_idx;
}

static uint32_t fb_task_hash_f(void *key)
{
    return ub_hash_bytes(key, sizeof(bondp_fb_task_key_t), BONDP_FB_TASK_HASH_BASIS);
}

static int bondp_fb_task_table_create(void)
{
    return ub_hmap_init(&g_task_map, BONDP_FB_TASK_TABLE_SIZE);
}

static void bondp_fb_task_free(bondp_fb_task_t *fb_task)
{
    free(fb_task);
}

static __attribute__((unused)) void bondp_fb_task_put(bondp_fb_task_t *fb_task)
{
    if (fb_task == NULL) {
        return;
    }

    (void)pthread_rwlock_wrlock(&g_task_lock);
    unsigned long use_cnt = atomic_fetch_sub(&fb_task->use_cnt.atomic_cnt, 1);
    (void)pthread_rwlock_unlock(&g_task_lock);
    if (use_cnt == 1) {
        bondp_fb_task_free(fb_task);
    }
}

static void bondp_fb_task_table_destroy(void)
{
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_t *next = NULL;

    (void)pthread_rwlock_wrlock(&g_task_lock);
    HMAP_FOR_EACH_SAFE (fb_task, next, hmap_node, &g_task_map) {
        ub_hmap_remove(&g_task_map, &fb_task->hmap_node);
        bondp_fb_task_free(fb_task);
    }
    ub_hmap_destroy(&g_task_map);
    (void)pthread_rwlock_unlock(&g_task_lock);
}

static __attribute__((unused)) bondp_fb_task_t *bondp_fb_task_lookup(
    const urma_eid_t *src_eid, uint32_t vjetty_id, uint32_t pjetty_idx)
{
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_key_t key = {0};
    uint32_t hash;

    if (src_eid == NULL) {
        return NULL;
    }

    key.src_eid = *src_eid;
    key.vjetty_id = vjetty_id;
    key.pjetty_idx = pjetty_idx;

    hash = fb_task_hash_f(&key);
    (void)pthread_rwlock_wrlock(&g_task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &g_task_map) {
        if (!fb_task_comp_f(&fb_task->hmap_node, &key)) {
            continue;
        }
        (void)atomic_fetch_add(&fb_task->use_cnt.atomic_cnt, 1);
        break;
    }
    (void)pthread_rwlock_unlock(&g_task_lock);
    return fb_task;
}

static __attribute__((unused)) int bondp_fb_task_add(const bondp_nl_fb_task_t *task)
{
    bondp_fb_task_t *new_task = NULL;
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_key_t key = {0};
    uint32_t hash;

    if (task == NULL) {
        return -EINVAL;
    }

    key.src_eid = task->src_eid;
    key.vjetty_id = task->vjetty_id;
    key.pjetty_idx = task->pjetty_idx;

    new_task = calloc(1, sizeof(*new_task));
    if (new_task == NULL) {
        return -ENOMEM;
    }

    new_task->request_id = next_request_id();
    new_task->src_eid = task->src_eid;
    new_task->vjetty_id = task->vjetty_id;
    new_task->pjetty_idx = task->pjetty_idx;
    atomic_init(&new_task->use_cnt.atomic_cnt, 1);

    hash = fb_task_hash_f(&key);
    (void)pthread_rwlock_wrlock(&g_task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &g_task_map) {
        if (!fb_task_comp_f(&fb_task->hmap_node, &key)) {
            continue;
        }
        (void)pthread_rwlock_unlock(&g_task_lock);
        free(new_task);
        return -EEXIST;
    }
    ub_hmap_insert(&g_task_map, &new_task->hmap_node, hash);
    (void)pthread_rwlock_unlock(&g_task_lock);
    return 0;
}

static __attribute__((unused)) int bondp_fb_task_del(
    const urma_eid_t *src_eid, uint32_t vjetty_id, uint32_t pjetty_idx)
{
    bondp_fb_task_t *fb_task = NULL;
    bondp_fb_task_key_t key = {0};
    uint32_t hash;

    if (src_eid == NULL) {
        return -EINVAL;
    }

    key.src_eid = *src_eid;
    key.vjetty_id = vjetty_id;
    key.pjetty_idx = pjetty_idx;

    hash = fb_task_hash_f(&key);
    (void)pthread_rwlock_wrlock(&g_task_lock);
    HMAP_FOR_EACH_WITH_HASH (fb_task, hmap_node, hash, &g_task_map) {
        if (!fb_task_comp_f(&fb_task->hmap_node, &key)) {
            continue;
        }

        unsigned long use_cnt = atomic_fetch_sub(&fb_task->use_cnt.atomic_cnt, 1);
        ub_hmap_remove(&g_task_map, &fb_task->hmap_node);
        (void)pthread_rwlock_unlock(&g_task_lock);
        if (use_cnt == 1) {
            bondp_fb_task_free(fb_task);
        }
        return 0;
    }
    (void)pthread_rwlock_unlock(&g_task_lock);
    return -ENOENT;
}

static __attribute__((unused)) int bondp_fb_user_ctl_start(
    bondp_context_t *bdp_ctx, const bondp_nl_fb_task_t *task)
{
    if (bdp_ctx == NULL || task == NULL) {
        return -EINVAL;
    }

    urma_user_ctl_in_t in = {
        .opcode = FAILBACK_START,
        .addr = (uint64_t)(uintptr_t)task,
        .len = sizeof(*task),
    };
    urma_user_ctl_out_t out = {0};
    urma_udrv_t udrv = {0};

    return urma_cmd_user_ctl(&bdp_ctx->v_ctx, &in, &out, &udrv);
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

int bondp_fb_init(void)
{
    if (bondp_fb_task_table_create() != 0) {
        return -ENOMEM;
    }

    init_request_id();
    return 0;
}

void bondp_fb_uninit(void)
{
    bondp_fb_task_table_destroy();
}
