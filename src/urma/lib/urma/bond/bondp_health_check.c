/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check implementation
 */

#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>

#include "ub_hash.h"
#include "urma_log.h"
#include "urma_api.h"
#include "bondp_context_table.h"
#include "bondp_datapath_convert.h"
#include "bondp_health_check.h"

#define UBAGG_MAX_EVENT 1
#define BONDP_HEALTH_CHECK_BUF_LEN (4096)
#define BONDP_HEALTH_CHECK_4K_ALIGN (4096)
#define BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS (100)

#define BONDP_HEALTH_CHECK_MAGIC            0xFF12000000000000ULL
#define BONDP_HEALTH_CHECK_MAGIC_MASK       0xFFFF000000000000ULL
#define BONDP_HEALTH_VJETTY_ID_SHIFT        32
#define BONDP_HEALTH_LOCAL_IDX_SHIFT        16
#define BONDP_HEALTH_IDX_MASK               0xFFFF

#define BONDP_HEALTH_TASK_TABLE_SIZE        64
#define BONDP_HEALTH_TASK_HASH_BASIS        0x983571U

#define BONDP_HEALTH_CHECK_ENV                        "BondHealthCheck"
#define BONDP_HEALTH_CHECK_PRIMARY_BACKUP_SWITCH      "PrimaryBackupSwitch"
#define BONDP_HEALTH_CHECK_AUTO_FALLBACK_PRIMARY      "AutoFallbackPrimary"
#define BONDP_HEALTH_CHECK_HEALTH_CHECK_START         "HealthCheckStart"
#define BONDP_HEALTH_CHECK_HEALTH_CHECK_INTERVAL      "HealthCheckInterval"
#define BONDP_HEALTH_CHECK_PRIMARY_CHECK_START        "PrimaryCheckStart"
#define BONDP_HEALTH_CHECK_PRIMARY_CHECK_INTERVAL     "PrimaryCheckInterval"
#define BONDP_HEALTH_CHECK_PRIMARY_CHECK_MAX_BACKOFF  "PrimaryCheckMaxBackoffCnt"

#define DEFAULT_PRIMARY_BACKUP_SWITCH      true
#define DEFAULT_AUTO_FALLBACK_PRIMARY      true
#define DEFAULT_HEALTH_CHECK_START_MS      2000
#define DEFAULT_HEALTH_CHECK_INTERVAL_MS   32000
#define DEFAULT_PRIMARY_CHECK_START_MS     2000
#define DEFAULT_PRIMARY_CHECK_INTERVAL_MS  1000
#define DEFAULT_PRIMARY_CHECK_MAX_BACKOFF  13

#define BONDP_HEALTH_CHECK_TIME_MS_MIN_100MS          100
#define BONDP_HEALTH_CHECK_TIME_MS_MIN_1S             1000
#define BONDP_HEALTH_CHECK_TIME_MS_MAX_60S            60000
#define BONDP_HEALTH_CHECK_TIME_MS_MAX_1H             3600000
#define BONDP_HEALTH_CHECK_CHECK_MIN_BACKOFF          1
#define BONDP_HEALTH_CHECK_CHECK_MAX_BACKOFF          100
#define BONDP_FALLBACK_CTRL_REQ                        1
#define BONDP_FALLBACK_CTRL_RESP                       2
#define BONDP_FALLBACK_CTRL_TYPE_SHIFT                 8
#define BONDP_FALLBACK_CTRL_TYPE_MASK                  0xFF
#define BONDP_FALLBACK_CTRL_SEQ_MASK                   0xFF
#define BONDP_FALLBACK_PRIMARY_INVALID_ID              UINT32_MAX

typedef struct bondp_health_ctx_node {
    bondp_context_t *bdp_ctx;
    struct ub_list node;
} bondp_health_ctx_node_t;

typedef struct bondp_health_event_node {
    bondp_health_event_t event;
    bondp_health_event_info_t info;
    struct ub_list node;
} bondp_health_event_node_t;

static uint64_t bondp_get_monotonic_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void bondp_free_health_task(bondp_health_task_t *task)
{
    if (task == NULL) {
        return;
    }
    free(task);
}

static bool bondp_valid_health_event(bondp_health_event_t event)
{
    return ((uint32_t)event < (uint32_t)BONDP_HEALTH_EVENT_MAX);
}

static bool bondp_health_event_push(bondp_context_t *bdp_ctx, bondp_health_event_t event,
    const bondp_health_event_info_t *info)
{
    bondp_health_event_node_t *node = calloc(1, sizeof(*node));
    if (node == NULL) {
        URMA_LOG_WARN("Failed to alloc health event node, event:%d\n", event);
        return false;
    }

    node->event = event;
    if (info != NULL) {
        node->info = *info;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_spin_lock(&health->event_lock);
    ub_list_push_back(&health->event_list, &node->node);
    pthread_spin_unlock(&health->event_lock);
    return true;
}

static void bondp_health_event_pop(bondp_heath_check_ctx_t *health, struct ub_list *list)
{
    pthread_spin_lock(&health->event_lock);
    ub_list_move(&health->event_list, list);
    pthread_spin_unlock(&health->event_lock);
}

static void bondp_free_health_event_list(struct ub_list *list)
{
    bondp_health_event_node_t *event = NULL;
    bondp_health_event_node_t *next = NULL;

    UB_LIST_FOR_EACH_SAFE(event, next, node, list) {
        ub_list_remove(&event->node);
        free(event);
    }
}

void bondp_notify_health_event(bondp_context_t *bdp_ctx, bondp_health_event_t event,
    const bondp_health_event_info_t *info)
{
    if (!bondp_health_check_enabled() || bdp_ctx == NULL) {
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    if (health->health_check_fd < 0) {
        return;
    }

    if (!bondp_valid_health_event(event)) {
        return;
    }

    if (!bondp_health_event_push(bdp_ctx, event, info)) {
        return;
    }

    if (eventfd_write(health->health_check_fd, 1) != 0 && errno != EAGAIN) {
        URMA_LOG_WARN("Failed to notify health event, fd:%d event:%d errno:%d\n",
            health->health_check_fd, event, errno);
    }
}

static void bondp_health_handle_ta_timeout_event(bondp_context_t *bdp_ctx, const bondp_health_event_info_t *info);

static uint64_t bondp_fallback_ctrl_encode(uint8_t ctrl_type, uint8_t req_seq)
{
    return (((uint64_t)ctrl_type & BONDP_FALLBACK_CTRL_TYPE_MASK) << BONDP_FALLBACK_CTRL_TYPE_SHIFT) |
        ((uint64_t)req_seq & BONDP_FALLBACK_CTRL_SEQ_MASK);
}

static void bondp_fallback_ctrl_decode(uint64_t ctrl_data, uint8_t *ctrl_type, uint8_t *req_seq)
{
    *ctrl_type = (uint8_t)((ctrl_data >> BONDP_FALLBACK_CTRL_TYPE_SHIFT) & BONDP_FALLBACK_CTRL_TYPE_MASK);
    *req_seq = (uint8_t)(ctrl_data & BONDP_FALLBACK_CTRL_SEQ_MASK);
}

static int bondp_get_target_idx_by_local_idx(const bondp_health_task_t *task, int local_idx, int *target_idx)
{
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            const bondp_health_sub_task_t *sub = &task->sub_tasks[i][j];
            if (!sub->valid || sub->local_idx != local_idx) {
                continue;
            }
            *target_idx = sub->target_idx;
            return 0;
        }
    }
    return -1;
}

static bool bondp_health_task_comp_f(hmap_node_t *node, void *key)
{
    bondp_health_task_t *task = CONTAINER_OF_FIELD(node, bondp_health_task_t, hmap_node);
    return task->vjetty_id == *(uint32_t *)key;
}

static void bondp_health_task_free_f(hmap_node_t *node)
{
    bondp_health_task_t *task = CONTAINER_OF_FIELD(node, bondp_health_task_t, hmap_node);
    free(task);
}

static uint32_t bondp_health_task_hash_f(void *key)
{
    return ub_hash_bytes(key, sizeof(uint32_t), BONDP_HEALTH_TASK_HASH_BASIS);
}

static uint32_t bondp_health_task_hash(uint32_t vjetty_id)
{
    return bondp_health_task_hash_f(&vjetty_id);
}

static bondp_health_task_t *bondp_find_health_task_by_tjetty_nolock(
    bondp_heath_check_ctx_t *health, bondp_target_jetty_t *bdp_tjetty)
{
    bondp_health_task_t *task = NULL;
    HMAP_FOR_EACH(task, hmap_node, &health->task_table.hmap) {
        if (task->bdp_tjetty == bdp_tjetty) {
            return task;
        }
    }
    return NULL;
}

static bondp_health_task_t *bondp_find_health_task_by_comp_nolock(
    bondp_heath_check_ctx_t *health, bondp_comp_t *bdp_jetty)
{
    if (bdp_jetty == NULL) {
        return NULL;
    }

    uint32_t vjetty_id = bdp_jetty->v_jetty.jetty_id.id;
    uint32_t hash = bondp_health_task_hash(vjetty_id);
    hmap_node_t *node = bondp_hash_table_lookup_without_lock(&health->task_table, &vjetty_id, hash);
    if (node == NULL) {
        return NULL;
    }

    bondp_health_task_t *task = CONTAINER_OF_FIELD(node, bondp_health_task_t, hmap_node);
    return (task->bondp_jetty == bdp_jetty) ? task : NULL;
}

static int bondp_register_health_ctx_global(bondp_context_t *bond_ctx)
{
    bondp_health_thread_ctx_t *thread_ctx = &g_bondp_global_ctx->health_thread_ctx;

    bondp_health_ctx_node_t *new_node = calloc(1, sizeof(bondp_health_ctx_node_t));
    if (new_node == NULL) {
        URMA_LOG_ERR("Failed to alloc health ctx node\n");
        return -1;
    }

    new_node->bdp_ctx = bond_ctx;

    pthread_rwlock_wrlock(&thread_ctx->health_ctx_lock);
    bondp_health_ctx_node_t *node = NULL;
    UB_LIST_FOR_EACH(node, node, &thread_ctx->health_ctx_list) {
        if (node->bdp_ctx == bond_ctx) {
            pthread_rwlock_unlock(&thread_ctx->health_ctx_lock);
            free(new_node);
            return 0;
        }
    }

    ub_list_push_front(&thread_ctx->health_ctx_list, &new_node->node);
    pthread_rwlock_unlock(&thread_ctx->health_ctx_lock);
    return 0;
}

static void bondp_unregister_health_ctx_global(bondp_context_t *bond_ctx)
{
    bondp_health_thread_ctx_t *thread_ctx = &g_bondp_global_ctx->health_thread_ctx;

    pthread_rwlock_wrlock(&thread_ctx->health_ctx_lock);
    bondp_health_ctx_node_t *node = NULL;
    bondp_health_ctx_node_t *next = NULL;
    UB_LIST_FOR_EACH_SAFE(node, next, node, &thread_ctx->health_ctx_list) {
        if (node->bdp_ctx == bond_ctx) {
            ub_list_remove(&node->node);
            free(node);
            break;
        }
    }
    pthread_rwlock_unlock(&thread_ctx->health_ctx_lock);
}

static bool bondp_health_read_env_bool(const char *env_name, bool default_val)
{
    const char *value = getenv(env_name);
    if (value == NULL) {
        return default_val;
    }
    if (strcmp(value, "true") == 0) {
        return true;
    }
    if (strcmp(value, "false") == 0) {
        return false;
    }
    URMA_LOG_WARN("Invalid value '%s' for env %s, using default %s\n",
        value, env_name, default_val ? "true" : "false");
    return default_val;
}

static uint64_t bondp_health_read_env_uint64(const char *env_name, uint64_t default_val,
    uint64_t min_val, uint64_t max_val)
{
    const char *value = getenv(env_name);
    if (value == NULL) {
        return default_val;
    }

    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed < (unsigned long long)min_val || parsed > (unsigned long long)max_val) {
        URMA_LOG_WARN("Invalid value '%s' for env %s (range %lu~%lu), using default %lu\n",
            value, env_name, (unsigned long)min_val, (unsigned long)max_val, (unsigned long)default_val);
        return default_val;
    }
    return (uint64_t)parsed;
}

static void bondp_read_health_check_cfg(bondp_health_check_cfg_t *cfg)
{
    cfg->primary_backup_switch = bondp_health_read_env_bool(BONDP_HEALTH_CHECK_PRIMARY_BACKUP_SWITCH,
        DEFAULT_PRIMARY_BACKUP_SWITCH);
    cfg->auto_fallback_primary = bondp_health_read_env_bool(BONDP_HEALTH_CHECK_AUTO_FALLBACK_PRIMARY,
        DEFAULT_AUTO_FALLBACK_PRIMARY);
    cfg->health_check_start_ms = bondp_health_read_env_uint64(BONDP_HEALTH_CHECK_HEALTH_CHECK_START,
        DEFAULT_HEALTH_CHECK_START_MS, BONDP_HEALTH_CHECK_TIME_MS_MIN_100MS, BONDP_HEALTH_CHECK_TIME_MS_MAX_1H);
    cfg->health_check_interval_ms = bondp_health_read_env_uint64(BONDP_HEALTH_CHECK_HEALTH_CHECK_INTERVAL,
        DEFAULT_HEALTH_CHECK_INTERVAL_MS, BONDP_HEALTH_CHECK_TIME_MS_MIN_1S, BONDP_HEALTH_CHECK_TIME_MS_MAX_1H);
    cfg->primary_check_start_ms = bondp_health_read_env_uint64(BONDP_HEALTH_CHECK_PRIMARY_CHECK_START,
        DEFAULT_PRIMARY_CHECK_START_MS, BONDP_HEALTH_CHECK_TIME_MS_MIN_100MS, BONDP_HEALTH_CHECK_TIME_MS_MAX_1H);
    cfg->primary_check_interval_ms = bondp_health_read_env_uint64(BONDP_HEALTH_CHECK_PRIMARY_CHECK_INTERVAL,
        DEFAULT_PRIMARY_CHECK_INTERVAL_MS, BONDP_HEALTH_CHECK_TIME_MS_MIN_100MS, BONDP_HEALTH_CHECK_TIME_MS_MAX_60S);
    cfg->primary_check_max_backoff_cnt = (uint32_t)bondp_health_read_env_uint64(BONDP_HEALTH_CHECK_PRIMARY_CHECK_MAX_BACKOFF,
        DEFAULT_PRIMARY_CHECK_MAX_BACKOFF, BONDP_HEALTH_CHECK_CHECK_MIN_BACKOFF, BONDP_HEALTH_CHECK_CHECK_MAX_BACKOFF);
}

static void bondp_print_health_check_cfg(const bondp_health_check_cfg_t *cfg)
{
    URMA_LOG_INFO("Health check config: PrimaryBackupSwitch=%s, AutoFallbackPrimary=%s, "
        "HealthCheckStart=%lums, HealthCheckInterval=%lums, "
        "PrimaryCheckStart=%lums, PrimaryCheckInterval=%lums, "
        "PrimaryCheckMaxBackoffCnt=%u\n",
        cfg->primary_backup_switch ? "true" : "false",
        cfg->auto_fallback_primary ? "true" : "false",
        (unsigned long)cfg->health_check_start_ms,
        (unsigned long)cfg->health_check_interval_ms,
        (unsigned long)cfg->primary_check_start_ms,
        (unsigned long)cfg->primary_check_interval_ms,
        cfg->primary_check_max_backoff_cnt);
}

bool bondp_health_check_enabled(void)
{
    return g_bondp_global_ctx->health_thread_ctx.health_check_enable;
}

void bondp_health_check_global_ctx_init(bondp_global_context_t *ctx)
{
    ctx->health_thread_ctx.health_epoll_fd = -1;
    ctx->health_thread_ctx.health_check_enable = bondp_health_read_env_bool(BONDP_HEALTH_CHECK_ENV, false);
    pthread_rwlock_init(&ctx->health_thread_ctx.health_ctx_lock, NULL);
    ub_list_init(&ctx->health_thread_ctx.health_ctx_list);
    atomic_init(&ctx->health_thread_ctx.health_thread_stop, false);
    URMA_LOG_INFO("Health check global init, enabled:%s\n",
        ctx->health_thread_ctx.health_check_enable ? "true" : "false");
}

void bondp_health_check_global_ctx_uninit(bondp_global_context_t *ctx)
{
    if (ctx->health_thread_ctx.health_epoll_fd >= 0) {
        (void)close(ctx->health_thread_ctx.health_epoll_fd);
        ctx->health_thread_ctx.health_epoll_fd = -1;
    }

    pthread_rwlock_destroy(&ctx->health_thread_ctx.health_ctx_lock);
}

void bondp_health_check_ctx_init(bondp_context_t *bond_ctx)
{
    bond_ctx->bondp_heath_check_ctx.check_buf_len = BONDP_HEALTH_CHECK_BUF_LEN;
    bond_ctx->bondp_heath_check_ctx.health_check_fd = -1;
    ub_list_init(&bond_ctx->bondp_heath_check_ctx.event_list);
}

static void bondp_unregister_health_check_seg(bondp_context_t *bond_ctx)
{
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;

    free(health->check_buf);
    health->check_buf = NULL;
}

void bondp_unregister_health_check_seg_for_jetty(bondp_comp_t *bdp_jetty)
{
    if (bdp_jetty == NULL) {
        return;
    }

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->check_tseg[i] == NULL) {
            continue;
        }

        if (urma_unregister_seg(bdp_jetty->check_tseg[i]) != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to unregister health check segment %d\n", i);
        }
        bdp_jetty->check_tseg[i] = NULL;
    }
}

int bondp_register_health_check_seg_for_jetty(bondp_context_t *bond_ctx, bondp_comp_t *bdp_jetty)
{
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;
    if (!bondp_health_check_enabled() || bond_ctx == NULL || bdp_jetty == NULL) {
        return 0;
    }

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_jetty->check_tseg[i] != NULL) {
            return 0;
        }
    }

    int ret = 0;
    pthread_rwlock_wrlock(&health->task_table.lock);

    urma_seg_cfg_t seg_cfg = {
        .va = 0,
        .len = health->check_buf_len,
        .token_id = NULL,
        .token_value = {0},
        .flag = {
            /* only used for health check cnt, using plaintext tokens, no security risk. */
            .bs.token_policy = URMA_TOKEN_NONE,
            .bs.cacheable = URMA_NON_CACHEABLE,
            .bs.access = URMA_ACCESS_WRITE | URMA_ACCESS_READ,
            .bs.reserved = 0,
        },
        .user_ctx = 0,
        .iova = 0,
    };

    if (health->check_buf == NULL) {
        health->check_buf = memalign(BONDP_HEALTH_CHECK_4K_ALIGN, health->check_buf_len);
        if (health->check_buf == NULL) {
            URMA_LOG_ERR("Failed to alloc health check buffer\n");
            pthread_rwlock_unlock(&health->task_table.lock);
            return -1;
        }
    }

    seg_cfg.va = (uint64_t)health->check_buf;

    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bond_ctx->p_ctxs[i] == NULL || bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        bdp_jetty->check_tseg[i] = urma_register_seg(bond_ctx->p_ctxs[i], &seg_cfg);
        if (bdp_jetty->check_tseg[i] == NULL) {
            URMA_LOG_ERR("Failed to register health check segment %d\n", i);
            ret = -1;
            goto ERR_UNREGISTER;
        }

        URMA_LOG_INFO("Succeed to register health check segment %d, len: %lu\n", i, health->check_buf_len);
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    return ret;

ERR_UNREGISTER:
    bondp_unregister_health_check_seg_for_jetty(bdp_jetty);
    pthread_rwlock_unlock(&health->task_table.lock);
    return ret;
}

int bondp_fill_vjetty_health_info(bondp_context_t *bond_ctx, bondp_comp_t *bdp_jetty,
    urma_bond_seg_info_out_t *health_check_seg, bool *is_health_check_enable)
{
    *is_health_check_enable = bondp_health_check_enabled();
    if (!(*is_health_check_enable)) {
        return 0;
    }

    health_check_seg->dev_num = bond_ctx->dev_num;

    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL || bdp_jetty->check_tseg[i] == NULL) {
            continue;
        }
        health_check_seg->slaves[i] = bdp_jetty->check_tseg[i]->seg;
    }

    URMA_LOG_INFO("Succeed to fill health check seg info to kernel, dev_num: %d\n", bond_ctx->dev_num);
    return 0;
}

static int import_check_tseg_by_import_result(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *rvjetty_info)
{
    bool has_valid_route = false;
    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    };

    for (uint32_t n = 0; n < bdp_tjetty->active_count; ++n) {
        uint32_t local_idx = bdp_tjetty->local_active_indices[n];
        uint32_t target_idx = bdp_tjetty->active_indices[n];

        if (local_idx >= (uint32_t)bdp_ctx->dev_num ||
            target_idx >= (uint32_t)rvjetty_info->health_check_seg.dev_num ||
            bdp_ctx->p_ctxs[local_idx] == NULL ||
            bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
            URMA_LOG_DEBUG("BONDP skip check seg route (%u %u)\n", local_idx, target_idx);
            continue;
        }

        if (bdp_tjetty->p_check_tseg[local_idx][target_idx] != NULL) {
            has_valid_route = true;
            continue;
        }

        urma_seg_t *check_seg = &rvjetty_info->health_check_seg.slaves[target_idx];
        bdp_tjetty->p_check_tseg[local_idx][target_idx] =
            urma_import_seg(bdp_ctx->p_ctxs[local_idx], check_seg, NULL, 0, flag);
        if (bdp_tjetty->p_check_tseg[local_idx][target_idx] == NULL) {
            URMA_LOG_ERR("Failed to import health check seg (%u, %u)\n", local_idx, target_idx);
            return -1;
        }

        URMA_LOG_INFO("Import health check seg [%u]("EID_FMT")<-[%u]("EID_FMT")\n", local_idx,
            EID_ARGS(bdp_ctx->p_ctxs[local_idx]->eid), target_idx,
            EID_ARGS(rvjetty_info->health_check_seg.slaves[target_idx].ubva.eid));
        has_valid_route = true;
    }

    if (!has_valid_route) {
        URMA_LOG_ERR("No valid imported route for health check seg\n");
        return -1;
    }

    URMA_LOG_INFO("Succeed to import health check segs\n");
    return 0;
}

int bondp_unimport_health_check_tseg(bondp_target_jetty_t *bdp_tjetty)
{
    int ret = URMA_SUCCESS;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            if (bdp_tjetty->p_check_tseg[i][j] == NULL) {
                continue;
            }

            if (urma_unimport_seg(bdp_tjetty->p_check_tseg[i][j]) != URMA_SUCCESS) {
                URMA_LOG_ERR("Failed to unimport health check seg (%d, %d)\n", i, j);
                ret = URMA_FAIL;
            }
            bdp_tjetty->p_check_tseg[i][j] = NULL;
        }
    }

    URMA_LOG_INFO("Finish to unimport health check segs, ret: %d\n", ret);
    return ret;
}

int bondp_import_health_check_tseg(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *rvjetty_info, urma_rjetty_t *rjetty)
{
    if (!rvjetty_info->is_health_check_enable || !bondp_health_check_enabled()) {
        return 0;
    }

    bondp_comp_t *cfg_jetty = NULL;
    if (rjetty->flag.bs.has_drv_ext) {
        const bondp_rjetty_t *bdp_rjetty = (const bondp_rjetty_t *)rjetty;
        cfg_jetty = CONTAINER_OF_FIELD(bdp_rjetty->jetty, bondp_comp_t, v_jetty);
    }

    if (!rjetty->flag.bs.has_drv_ext || cfg_jetty == NULL) {
        URMA_LOG_ERR("Invalid rjetty for health check seg import, health check disabled\n");
        return 0;
    }

    return import_check_tseg_by_import_result(bdp_ctx, bdp_tjetty, rvjetty_info);
}

static void bondp_handle_health_event(bondp_context_t *bond_ctx, bondp_health_event_t event,
    const bondp_health_event_info_t *info)
{
    switch (event) {
        case BONDP_HEALTH_EVENT_TA_TIMEOUT:
            bondp_health_handle_ta_timeout_event(bond_ctx, info);
            break;
        case BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE:
            if (info != NULL && info->bdp_tjetty != NULL) {
                bondp_health_update_active_idx(bond_ctx, info->bdp_tjetty, info->new_active_idx);
            }
            break;
        case BONDP_HEALTH_EVENT_FALLBACK_TASK_KICK:
            if (info != NULL && info->bdp_tjetty != NULL) {
                bondp_health_kick_fallback_task(bond_ctx, info->bdp_tjetty);
            }
            break;
        default:
            URMA_LOG_WARN("Unknown health event:%d, dev_name:%s eid_idx:%u\n",
                event, bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
            break;
    }
}

static void bondp_handle_health_queued_events(bondp_context_t *bond_ctx)
{
    struct ub_list event_list = UB_LIST_INITIALIZER(&event_list);
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;
    bondp_health_event_node_t *cur = NULL;
    bondp_health_event_node_t *next = NULL;

    bondp_health_event_pop(health, &event_list);

    UB_LIST_FOR_EACH_SAFE(cur, next, node, &event_list) {
        bondp_handle_health_event(bond_ctx, cur->event, &cur->info);
    }
    bondp_free_health_event_list(&event_list);
}

static void bondp_handle_epoll_event(const struct epoll_event *event)
{
    if (event == NULL) {
        return;
    }

    if ((event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        URMA_LOG_WARN("Health epoll error event:0x%x\n", event->events);
        return;
    }

    if ((event->events & EPOLLIN) == 0) {
        return;
    }

    bondp_context_t *bond_ctx = (bondp_context_t *)event->data.ptr;
    if (bond_ctx == NULL) {
        URMA_LOG_WARN("Health epoll event has NULL context\n");
        return;
    }

    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;
    while (true) {
        eventfd_t cnt = 0;
        if (eventfd_read(health->health_check_fd, &cnt) == 0) {
            continue;
        }
        if (errno == EAGAIN) {
            break;
        }
        URMA_LOG_WARN("Failed to read health eventfd, fd:%d errno:%d\n", health->health_check_fd, errno);
        break;
    }

    bondp_handle_health_queued_events(bond_ctx);
}

static uint64_t bondp_build_health_user_ctx(uint32_t vjetty_id, uint32_t local_idx, uint32_t target_idx)
{
    return BONDP_HEALTH_CHECK_MAGIC |
        ((uint64_t)(vjetty_id & BONDP_HEALTH_IDX_MASK) << BONDP_HEALTH_VJETTY_ID_SHIFT) |
        ((uint64_t)(local_idx & BONDP_HEALTH_IDX_MASK) << BONDP_HEALTH_LOCAL_IDX_SHIFT) |
        (uint64_t)(target_idx & BONDP_HEALTH_IDX_MASK);
}

static void bondp_parse_health_user_ctx(uint64_t user_ctx, uint32_t *vjetty_id,
    uint32_t *local_idx, uint32_t *target_idx)
{
    *vjetty_id = (uint32_t)((user_ctx >> BONDP_HEALTH_VJETTY_ID_SHIFT) & BONDP_HEALTH_IDX_MASK);
    *local_idx = (uint32_t)((user_ctx >> BONDP_HEALTH_LOCAL_IDX_SHIFT) & BONDP_HEALTH_IDX_MASK);
    *target_idx = (uint32_t)(user_ctx & BONDP_HEALTH_IDX_MASK);
}

static urma_status_t bondp_send_health_probe(bondp_context_t *bdp_ctx,
    bondp_target_jetty_t *bdp_tjetty, bondp_comp_t *bdp_jetty,
    bondp_health_sub_task_t *sub, uint32_t vjetty_id)
{
    int local_idx = sub->local_idx;
    int target_idx = sub->target_idx;

    urma_jetty_t *jetty = bdp_jetty->p_jetty[local_idx];
    urma_target_jetty_t *tjetty = bdp_tjetty->p_tjetty[local_idx][target_idx];
    urma_target_seg_t *tseg = bdp_tjetty->p_check_tseg[local_idx][target_idx];
    urma_target_seg_t *local_tseg = bdp_jetty->check_tseg[local_idx];

    if (jetty == NULL || tjetty == NULL || tseg == NULL || local_tseg == NULL) {
        return URMA_FAIL;
    }

    uint64_t user_ctx = bondp_build_health_user_ctx(vjetty_id, (uint32_t)local_idx, (uint32_t)target_idx);
    sub->user_ctx = user_ctx;

    urma_sge_t src_sge = {
        .addr = (uint64_t)bdp_ctx->bondp_heath_check_ctx.check_buf,
        .len = sizeof(uint64_t),
        .tseg = local_tseg,
        .user_tseg = NULL,
    };
    urma_sge_t dst_sge = {
        .addr = tseg->seg.ubva.va,
        .len = sizeof(uint64_t),
        .tseg = tseg,
        .user_tseg = NULL,
    };
    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_WRITE,
        .flag.bs.complete_enable = 1,
        .tjetty = tjetty,
        .user_ctx = user_ctx,
        .rw = {
            .src = { .sge = &src_sge, .num_sge = 1 },
            .dst = { .sge = &dst_sge, .num_sge = 1 },
        },
        .next = NULL,
    };

    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t ret = urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_WARN("Health probe write failed, lidx:%d tidx:%d ret:%d\n", local_idx, target_idx, ret);
    } else {
        URMA_LOG_DEBUG("Health probe sent, lidx:%d tidx:%d user_ctx:0x%lx\n",
            local_idx, target_idx, user_ctx);
    }
    return ret;
}

static int bondp_update_pjetty_id_mapping(
    bondp_context_t *bdp_ctx, urma_jetty_id_t old_id, urma_jetty_id_t new_id, bondp_comp_t *bdp_jetty)
{
    int ret = 0;
    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    ret = bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, old_id, JETTY);
    if (ret != 0) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to delete stale pjetty id mapping: " URMA_JETTY_ID_FMT ", ret:%d\n",
            URMA_JETTY_ID_ARGS(&old_id), ret);
        return -1;
    }
    ret = bdp_p_vjetty_id_table_add_without_lock(
        &bdp_ctx->p_vjetty_id_table, new_id, JETTY, bdp_jetty->v_jetty.jetty_id.id, bdp_jetty);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to add recreated pjetty id mapping: " URMA_JETTY_ID_FMT ", ret:%d\n",
            URMA_JETTY_ID_ARGS(&new_id), ret);
        return -1;
    }
    return 0;
}

typedef struct bondp_recv_wr_snapshot {
    urma_jfr_wr_t wr;
    uint64_t user_ctx;
} bondp_recv_wr_snapshot_t;

static void bondp_free_recv_wr_snapshot(bondp_recv_wr_snapshot_t *snapshots, uint32_t count)
{
    if (snapshots == NULL) {
        return;
    }
    for (uint32_t i = 0; i < count; ++i) {
        free_jfr_wr(&snapshots[i].wr);
    }
    free(snapshots);
}

static int bondp_snapshot_recv_wr_for_local_idx(
    bondp_comp_t *bdp_jetty, int local_idx, bondp_recv_wr_snapshot_t **snapshots, uint32_t *snapshot_cnt)
{
    *snapshots = NULL;
    *snapshot_cnt = 0;
    if (bdp_jetty->recv_jfc == NULL) {
        return 0;
    }

    wr_buf_t *wr_buf = &bdp_jetty->recv_jfc->wr_buf;
    if (wr_buf->entries == NULL || wr_buf->max_wr_num == 0) {
        return 0;
    }

    bondp_recv_wr_snapshot_t *buf = calloc(wr_buf->max_wr_num, sizeof(*buf));
    if (buf == NULL) {
        return -1;
    }

    uint32_t cnt = 0;
    jfr_wr_entry_t *entry = NULL;
    JFR_WR_BUF_FOREACH(wr_buf, idx, entry) {
        if (entry->wr_id == 0 || entry->recv_idx != (uint32_t)local_idx) {
            continue;
        }

        if (copy_jfr_wr(&entry->wr, &buf[cnt].wr, NULL) != 0) {
            bondp_free_recv_wr_snapshot(buf, cnt);
            return -1;
        }
        buf[cnt].user_ctx = entry->user_ctx;
        cnt++;
    }

    *snapshots = buf;
    *snapshot_cnt = cnt;
    return 0;
}

static int bondp_restore_recv_wr_for_local_idx(
    bondp_comp_t *bdp_jetty, urma_jetty_t *new_jetty, int local_idx,
    const bondp_recv_wr_snapshot_t *snapshots, uint32_t snapshot_cnt)
{
    if (snapshot_cnt == 0 || snapshots == NULL || bdp_jetty->recv_jfc == NULL) {
        return 0;
    }

    int fail_cnt = 0;
    wr_buf_t *wr_buf = &bdp_jetty->recv_jfc->wr_buf;
    for (uint32_t i = 0; i < snapshot_cnt; ++i) {
        jfr_wr_entry_t *entry = jfr_wr_buf_alloc(wr_buf);
        if (entry == NULL) {
            URMA_LOG_ERR("Failed to alloc recv wr entry while restoring primary idx:%d\n", local_idx);
            fail_cnt++;
            continue;
        }

        entry->user_ctx = snapshots[i].user_ctx;
        entry->bdp_comp = bdp_jetty;
        entry->recv_idx = (uint32_t)local_idx;
        if (copy_jfr_wr(&snapshots[i].wr, &entry->wr, NULL) != 0) {
            jfr_wr_buf_release(entry);
            URMA_LOG_ERR("Failed to copy recv wr while restoring primary idx:%d\n", local_idx);
            fail_cnt++;
            continue;
        }

        entry->wr.user_ctx = entry->wr_id;
        urma_jfr_wr_t *bad_wr = NULL;
        urma_status_t ret = urma_post_jetty_recv_wr(new_jetty, &entry->wr, &bad_wr);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to repost recv wr after primary rebuild, idx:%d ret:%d\n", local_idx, ret);
            free_jfr_wr(&entry->wr);
            jfr_wr_buf_release(entry);
            fail_cnt++;
            continue;
        }
        bdp_jetty->rqe_cnt[local_idx] += 1;
    }
    return (fail_cnt == 0) ? 0 : -1;
}

static void bondp_drain_primary_jetty_wr(urma_jetty_t *old_jetty, int local_idx)
{
    urma_cr_t cr_buf[URMA_UBAGG_MAX_CR_CNT_PER_DEV] = {0};
    int flushed = 0;
    do {
        flushed = urma_flush_jetty(old_jetty, URMA_UBAGG_MAX_CR_CNT_PER_DEV, cr_buf);
        if (flushed < 0) {
            URMA_LOG_WARN("Failed to flush primary pjetty before rebuild, idx:%d ret:%d\n",
                local_idx, flushed);
            break;
        }
    } while (flushed > 0);
}

static int bondp_rebuild_primary_pjetty(bondp_health_task_t *task)
{
    if (task == NULL || task->bondp_jetty == NULL) {
        return -1;
    }

    bondp_comp_t *bdp_jetty = task->bondp_jetty;
    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;
    int local_idx = task->primary_local_idx;
    if (local_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM || bdp_jetty->p_jetty[local_idx] == NULL) {
        return -1;
    }

    bondp_recv_wr_snapshot_t *recv_wr_snapshots = NULL;
    uint32_t recv_wr_snapshot_cnt = 0;
    if (bondp_snapshot_recv_wr_for_local_idx(
        bdp_jetty, local_idx, &recv_wr_snapshots, &recv_wr_snapshot_cnt) != 0) {
        URMA_LOG_ERR("Failed to snapshot recv wr before rebuilding primary idx:%d\n", local_idx);
        return -1;
    }

    urma_jetty_t *old_jetty = bdp_jetty->p_jetty[local_idx];
    bondp_drain_primary_jetty_wr(old_jetty, local_idx);

    urma_jetty_cfg_t p_cfg = bdp_jetty->v_jetty.jetty_cfg;
    bondp_jfc_t *bdp_jfs_jfc = CONTAINER_OF_FIELD(p_cfg.jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(p_cfg.shared.jfr, bondp_comp_t, base);
    bondp_jfc_t *bdp_rplc_jfc = NULL;
    if (p_cfg.shared.jfc != NULL) {
        bdp_rplc_jfc = CONTAINER_OF_FIELD(p_cfg.shared.jfc, bondp_jfc_t, v_jfc);
    }
    p_cfg.jfs_cfg.jfc = bdp_jfs_jfc->p_jfc[local_idx];
    p_cfg.shared.jfr = bdp_jfr->p_jfr[local_idx];
    if (bdp_rplc_jfc != NULL) {
        p_cfg.shared.jfc = bdp_rplc_jfc->p_jfc[local_idx];
    }

    urma_jetty_id_t old_id = old_jetty->jetty_id;
    if (urma_delete_jetty(old_jetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to delete primary pjetty at idx:%d\n", local_idx);
        bondp_free_recv_wr_snapshot(recv_wr_snapshots, recv_wr_snapshot_cnt);
        return -1;
    }

    urma_jetty_t *new_jetty = urma_create_jetty(bdp_ctx->p_ctxs[local_idx], &p_cfg);
    if (new_jetty == NULL) {
        URMA_LOG_ERR("Failed to recreate primary pjetty at idx:%d\n", local_idx);
        bondp_free_recv_wr_snapshot(recv_wr_snapshots, recv_wr_snapshot_cnt);
        return -1;
    }
    new_jetty->jetty_cfg.user_ctx = (uint64_t)bdp_jetty;
    bdp_jetty->p_jetty[local_idx] = new_jetty;
    bdp_jetty->valid[local_idx] = false;

    if (bondp_update_pjetty_id_mapping(bdp_ctx, old_id, new_jetty->jetty_id, bdp_jetty) != 0) {
        bondp_free_recv_wr_snapshot(recv_wr_snapshots, recv_wr_snapshot_cnt);
        return -1;
    }

    if (bondp_restore_recv_wr_for_local_idx(
        bdp_jetty, new_jetty, local_idx, recv_wr_snapshots, recv_wr_snapshot_cnt) != 0) {
        URMA_LOG_ERR("Failed to restore recv wr after rebuilding primary idx:%d\n", local_idx);
        bondp_free_recv_wr_snapshot(recv_wr_snapshots, recv_wr_snapshot_cnt);
        return -1;
    }

    bondp_free_recv_wr_snapshot(recv_wr_snapshots, recv_wr_snapshot_cnt);
    URMA_LOG_INFO("Primary pjetty rebuilt, idx:%d old:" URMA_JETTY_ID_FMT " new:" URMA_JETTY_ID_FMT "\n",
        local_idx, URMA_JETTY_ID_ARGS(&old_id), URMA_JETTY_ID_ARGS(&new_jetty->jetty_id));
    return 0;
}

static int bondp_send_fallback_ctrl_msg(
    bondp_context_t *bdp_ctx, bondp_health_task_t *task,
    int local_idx, int target_idx, uint8_t ctrl_type, uint8_t req_seq, uint64_t payload)
{
    if (local_idx < 0 || target_idx < 0) {
        return -1;
    }
    urma_jetty_t *jetty = task->bondp_jetty->p_jetty[local_idx];
    urma_target_jetty_t *tjetty = task->bdp_tjetty->p_tjetty[local_idx][target_idx];
    urma_target_seg_t *tseg = task->bdp_tjetty->p_check_tseg[local_idx][target_idx];
    urma_target_seg_t *local_tseg = task->bondp_jetty->check_tseg[local_idx];
    uint64_t *health_buf = (uint64_t *)bdp_ctx->bondp_heath_check_ctx.check_buf;
    if (jetty == NULL || tjetty == NULL || tseg == NULL || local_tseg == NULL || health_buf == NULL) {
        return -1;
    }
    health_buf[0] = payload;

    urma_sge_t src_sge = {
        .addr = (uint64_t)health_buf,
        .len = sizeof(uint64_t),
        .tseg = local_tseg,
        .user_tseg = NULL,
    };
    urma_sge_t dst_sge = {
        .addr = tseg->seg.ubva.va,
        .len = sizeof(uint64_t),
        .tseg = tseg,
        .user_tseg = NULL,
    };

    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_WRITE_IMM,
        .flag.bs.complete_enable = 1,
        .tjetty = tjetty,
        .user_ctx = BONDP_CTRL_USER_CTX_MASK | BONDP_HEALTH_CHECK_MAGIC,
        .rw = {
            .src = { .sge = &src_sge, .num_sge = 1 },
            .dst = { .sge = &dst_sge, .num_sge = 1 },
            .notify_data = bondp_fallback_ctrl_encode(ctrl_type, req_seq),
        },
        .next = NULL,
    };
    mark_jfs_wr_ctrl(&wr);

    urma_jfs_wr_t *bad_wr = NULL;
    urma_status_t ret = urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_WARN("Failed to send fallback ctrl msg, lidx:%d tidx:%d type:%u seq:%u ret:%d\n",
            local_idx, target_idx, ctrl_type, req_seq, ret);
        return -1;
    }
    return 0;
}

static int bondp_relink_primary_import(bondp_health_task_t *task)
{
    bondp_comp_t *bdp_jetty = task->bondp_jetty;
    bondp_context_t *bdp_ctx = bdp_jetty->bondp_ctx;
    int local_idx = task->primary_local_idx;
    int target_idx = (int)task->fallback_task.primary_target_idx;
    if (local_idx < 0 || target_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM ||
        target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return -1;
    }

    urma_target_jetty_t *old_tjetty = task->bdp_tjetty->p_tjetty[local_idx][target_idx];
    if (old_tjetty == NULL) {
        return -1;
    }

    urma_rjetty_t rjetty = {
        .jetty_id = old_tjetty->id,
        .trans_mode = old_tjetty->trans_mode,
        .policy = old_tjetty->policy,
        .type = old_tjetty->type,
        .flag = old_tjetty->flag,
        .tp_type = old_tjetty->tp_type,
    };
    rjetty.jetty_id.id = task->fallback_task.remote_primary_pjetty_id;

    if (urma_unimport_jetty(old_tjetty) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to unimport old primary ptjetty, lidx:%d tidx:%d\n", local_idx, target_idx);
        return -1;
    }
    task->bdp_tjetty->p_tjetty[local_idx][target_idx] = NULL;

    urma_target_jetty_t *new_tjetty = urma_import_jetty(bdp_ctx->p_ctxs[local_idx], &rjetty, NULL);
    if (new_tjetty == NULL) {
        URMA_LOG_ERR("Failed to import recreated primary ptjetty, local_idx:%d target_idx:%d pjetty_id:%u\n",
            local_idx, target_idx, rjetty.jetty_id.id);
        return -1;
    }
    task->bdp_tjetty->p_tjetty[local_idx][target_idx] = new_tjetty;
    task->bondp_jetty->valid[local_idx] = false;
    return 0;
}

static void bondp_process_fallback_task(bondp_context_t *bdp_ctx, bondp_health_task_t *task)
{
    bondp_fallback_task_t *fallback = &task->fallback_task;
    if (!fallback->pending) {
        return;
    }

    if (!fallback->local_rebuilt) {
        if (bondp_rebuild_primary_pjetty(task) != 0) {
            return;
        }
        fallback->local_rebuilt = true;
    }

    if (!fallback->req_sent) {
        int active_local_idx = task->active_local_idx;
        int active_target_idx = -1;
        if (bondp_get_target_idx_by_local_idx(task, active_local_idx, &active_target_idx) != 0) {
            return;
        }
        uint64_t req_payload = BONDP_FALLBACK_PRIMARY_INVALID_ID;
        int primary_local_idx = task->primary_local_idx;
        int primary_target_idx = (int)fallback->primary_target_idx;
        if (primary_local_idx >= 0 && primary_local_idx < URMA_UBAGG_DEV_MAX_NUM &&
            primary_target_idx >= 0 && primary_target_idx < URMA_UBAGG_DEV_MAX_NUM) {
            urma_target_jetty_t *primary_tjetty = task->bdp_tjetty->p_tjetty[primary_local_idx][primary_target_idx];
            if (primary_tjetty != NULL) {
                req_payload = (uint64_t)primary_tjetty->id.id;
            }
        }
        if (bondp_send_fallback_ctrl_msg(bdp_ctx, task, active_local_idx, active_target_idx,
            BONDP_FALLBACK_CTRL_REQ, fallback->req_seq, req_payload) == 0) {
            fallback->req_sent = true;
        }
        return;
    }

    if (!fallback->resp_received || fallback->relink_done ||
        fallback->remote_primary_pjetty_id == BONDP_FALLBACK_PRIMARY_INVALID_ID) {
        return;
    }

    if (bondp_relink_primary_import(task) == 0) {
        fallback->relink_done = true;
        fallback->pending = false;
        task->next_probe_ts_us = bondp_get_monotonic_us();
        URMA_LOG_INFO("Fallback relink prepared, waiting health probe to validate primary idx:%d\n",
            task->primary_local_idx);
    }
}

static void bondp_health_task_check_mode(bondp_health_task_t *task,
    const bondp_health_check_cfg_t *cfg, uint64_t now_us)
{
    bool primary_valid = task->bondp_jetty->valid[task->primary_local_idx];

    if (task->mode == HEALTH_MODE_BACKUP_CHECK && !primary_valid) {
        /* Primary link went down, switch to primary check mode */
        task->mode = HEALTH_MODE_PRIMARY_CHECK;
        task->backoff_cnt = 0;
        task->next_probe_ts_us = now_us + cfg->primary_check_start_ms * 1000ULL;
        URMA_LOG_INFO("Primary link (lidx:%d) down, switch to PRIMARY_CHECK mode, start after %lums\n",
            task->primary_local_idx, (unsigned long)cfg->primary_check_start_ms);
    } else if (task->mode == HEALTH_MODE_PRIMARY_CHECK && primary_valid) {
        /* Primary link recovered (user switched back), resume backup check */
        task->mode = HEALTH_MODE_BACKUP_CHECK;
        task->backoff_cnt = 0;
        task->next_probe_ts_us = now_us + cfg->health_check_interval_ms * 1000ULL;
        URMA_LOG_INFO("Primary link (lidx:%d) recovered, switch to BACKUP_CHECK mode\n",
            task->primary_local_idx);
    }
}

static void bondp_health_probe_sub(bondp_context_t *bdp_ctx, bondp_health_task_t *task,
    bondp_health_sub_task_t *sub)
{
    if (sub->probe_pending) {
        URMA_LOG_INFO("Health probe skipped (pending), lidx:%d tidx:%d\n", sub->local_idx, sub->target_idx);
        return;
    }

    sub->probe_pending = true;
    if (bondp_send_health_probe(bdp_ctx, task->bdp_tjetty, task->bondp_jetty, sub, task->vjetty_id) != URMA_SUCCESS) {
        sub->probe_pending = false;
        if (atomic_load(&sub->link_ok)) {
            URMA_LOG_WARN("Health probe send failed, lidx:%d tidx:%d\n", sub->local_idx, sub->target_idx);
        }
        atomic_store(&sub->link_ok, false);
        task->bondp_jetty->valid[sub->local_idx] = false;
        return;
    }
}

static void bondp_health_do_check(bondp_context_t *bdp_ctx, bondp_health_task_t *task)
{
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            bondp_health_sub_task_t *sub = &task->sub_tasks[i][j];
            if (!sub->valid || sub->local_idx == task->active_local_idx) {
                continue;
            }
            bondp_health_probe_sub(bdp_ctx, task, sub);
        }
    }
}

static uint64_t bondp_health_calc_primary_interval_us(const bondp_health_check_cfg_t *cfg, uint32_t backoff_cnt)
{
    uint64_t interval_ms = cfg->primary_check_interval_ms;
    uint32_t shift = (backoff_cnt < cfg->primary_check_max_backoff_cnt) ?
        backoff_cnt : cfg->primary_check_max_backoff_cnt;
    interval_ms <<= shift;
    return interval_ms * 1000ULL;
}

static void *bondp_health_check_thread(void *arg)
{
    bondp_global_context_t *global_ctx = (bondp_global_context_t *)arg;
    const bondp_health_check_cfg_t *cfg = &global_ctx->health_thread_ctx.cfg;
    struct epoll_event events[UBAGG_MAX_EVENT];

    if (prctl(PR_SET_NAME, "bond_health_t", 0, 0, 0) != 0) {
        URMA_LOG_WARN("Failed to set health thread name, errno: %d\n", errno);
    }

    int epoll_fd = global_ctx->health_thread_ctx.health_epoll_fd;

    while (true) {
        bool stop = atomic_load(&global_ctx->health_thread_ctx.health_thread_stop);
        if (stop) {
            break;
        }

        int event_num = epoll_wait(epoll_fd, events, UBAGG_MAX_EVENT, BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS);
        if (event_num < 0 && errno != EINTR) {
            URMA_LOG_ERR("Health check epoll_wait failed, errno: %d\n", errno);
            (void)usleep(BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS * 1000);
            continue;
        }

        if (event_num > 0) {
            for (int i = 0; i < event_num; ++i) {
                bondp_handle_epoll_event(&events[i]);
            }
        }

        uint64_t now_us = bondp_get_monotonic_us();
        pthread_rwlock_rdlock(&global_ctx->health_thread_ctx.health_ctx_lock);
        bondp_health_ctx_node_t *ctx_node = NULL;
        UB_LIST_FOR_EACH(ctx_node, node, &global_ctx->health_thread_ctx.health_ctx_list) {
            bondp_heath_check_ctx_t *health = &ctx_node->bdp_ctx->bondp_heath_check_ctx;
            pthread_rwlock_rdlock(&health->task_table.lock);
            bondp_health_task_t *task = NULL;
            HMAP_FOR_EACH(task, hmap_node, &health->task_table.hmap) {
                bondp_health_task_check_mode(task, cfg, now_us);
                if (now_us < task->next_probe_ts_us) {
                    continue;
                }
                URMA_LOG_DEBUG("Health check round mode:%s active_idx:%d primary_idx:%d backoff:%u\n",
                    task->mode == HEALTH_MODE_BACKUP_CHECK ? "BACKUP" : "PRIMARY",
                    task->active_local_idx, task->primary_local_idx, task->backoff_cnt);
                bondp_health_do_check(ctx_node->bdp_ctx, task);
                if (task->mode == HEALTH_MODE_BACKUP_CHECK) {
                    task->next_probe_ts_us = now_us + cfg->health_check_interval_ms * 1000ULL;
                } else {
                    task->next_probe_ts_us = now_us +
                        bondp_health_calc_primary_interval_us(cfg, task->backoff_cnt);
                    if (task->backoff_cnt < cfg->primary_check_max_backoff_cnt) {
                        task->backoff_cnt++;
                    }
                }
            }
            pthread_rwlock_unlock(&health->task_table.lock);
        }
        pthread_rwlock_unlock(&global_ctx->health_thread_ctx.health_ctx_lock);
    }
    return NULL;
}

int bondp_register_health_check_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty, bondp_comp_t *cfg_jetty)
{
    if (!bondp_health_check_enabled() || cfg_jetty == NULL) {
        return 0;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    const bondp_health_check_cfg_t *cfg = &g_bondp_global_ctx->health_thread_ctx.cfg;
    bondp_health_task_t *task = calloc(1, sizeof(bondp_health_task_t));
    if (task == NULL) {
        return -1;
    }
    task->bdp_tjetty = bdp_tjetty;
    task->bondp_jetty = cfg_jetty;
    task->next_probe_ts_us = bondp_get_monotonic_us() + cfg->health_check_start_ms * 1000ULL;
    task->primary_local_idx = -1;
    task->active_local_idx = -1;
    task->vjetty_id = cfg_jetty->v_jetty.jetty_id.id;
    task->mode = HEALTH_MODE_BACKUP_CHECK;
    task->backoff_cnt = 0;
    task->fallback_task.pending = false;
    task->fallback_task.local_rebuilt = false;
    task->fallback_task.req_sent = false;
    task->fallback_task.resp_received = false;
    task->fallback_task.relink_done = false;
    task->fallback_task.req_seq = 0;
    task->fallback_task.primary_target_idx = 0;
    task->fallback_task.remote_primary_pjetty_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;

    int sub_task_cnt = 0;
    for (uint32_t n = 0; n < bdp_tjetty->active_count; ++n) {
        uint32_t local_idx = bdp_tjetty->local_active_indices[n];
        uint32_t target_idx = bdp_tjetty->active_indices[n];
        if (bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL ||
            bdp_tjetty->p_check_tseg[local_idx][target_idx] == NULL) {
            continue;
        }
        if (cfg_jetty->p_jetty[local_idx] == NULL) {
            continue;
        }

        bondp_health_sub_task_t *sub = &task->sub_tasks[local_idx][target_idx];
        sub->local_idx = (int)local_idx;
        sub->target_idx = (int)target_idx;
        sub->valid = true;
        sub->probe_pending = false;
        atomic_store(&sub->link_ok, true);
        sub->user_ctx = 0;
        if (task->primary_local_idx < 0) {
            task->primary_local_idx = (int)local_idx;
            task->active_local_idx = (int)local_idx;
        }
        URMA_LOG_DEBUG("Health subtask registered lidx:%d tidx:%d\n", (int)local_idx, (int)target_idx);
        sub_task_cnt++;
    }
    if (sub_task_cnt == 0) {
        free(task);
        URMA_LOG_ERR("Failed to register health task: no valid route\n");
        return 0;
    }
    uint32_t hash = bondp_health_task_hash(task->vjetty_id);
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_hash_table_add_with_hash_without_lock(&health->task_table, &task->hmap_node, hash);
    pthread_rwlock_unlock(&health->task_table.lock);

    URMA_LOG_INFO("Health task registered, tjetty:%u sub_cnt:%d primary_idx:%d active_idx:%d start_ms:%lu\n",
        bdp_tjetty->v_tjetty.id.id, sub_task_cnt, task->primary_local_idx, task->active_local_idx,
        (unsigned long)cfg->health_check_start_ms);
    return 0;
}

void bondp_unregister_health_check_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    if (!bondp_health_check_enabled()) {
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_health_task_t *task = NULL;
    bondp_health_task_t *next = NULL;
    HMAP_FOR_EACH_SAFE(task, next, hmap_node, &health->task_table.hmap) {
        if (task->bdp_tjetty == bdp_tjetty) {
            ub_hmap_remove(&health->task_table.hmap, &task->hmap_node);
            bondp_free_health_task(task);
            URMA_LOG_INFO("Health check task unregistered, tjetty:%u\n", bdp_tjetty->v_tjetty.id.id);
            break;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
}

void bondp_health_update_active_idx(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    int new_active_idx)
{
    if (!bondp_health_check_enabled()) {
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_health_task_t *task = NULL;
    HMAP_FOR_EACH(task, hmap_node, &health->task_table.hmap) {
        if (task->bdp_tjetty != bdp_tjetty) {
            continue;
        }
        int old = task->active_local_idx;
        task->active_local_idx = new_active_idx;
        URMA_LOG_INFO("Health active link updated, tjetty:%u old_idx:%d new_idx:%d\n",
            bdp_tjetty->v_tjetty.id.id, old, new_active_idx);
        break;
    }
    pthread_rwlock_unlock(&health->task_table.lock);
}

void bondp_health_kick_fallback_task(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    if (!bondp_health_check_enabled()) {
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_health_task_t *task = bondp_find_health_task_by_tjetty_nolock(health, bdp_tjetty);
    if (task != NULL && task->active_local_idx >= 0 &&
        task->active_local_idx != task->primary_local_idx &&
        !task->fallback_task.pending) {
        task->mode = HEALTH_MODE_PRIMARY_CHECK;
        task->backoff_cnt = 0;
        task->fallback_task.pending = true;
        task->fallback_task.local_rebuilt = false;
        task->fallback_task.req_sent = false;
        task->fallback_task.resp_received = false;
        task->fallback_task.relink_done = false;
        task->fallback_task.req_seq++;
        task->fallback_task.remote_primary_pjetty_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
        int primary_target_idx = -1;
        if (bondp_get_target_idx_by_local_idx(task, task->primary_local_idx, &primary_target_idx) == 0) {
            task->fallback_task.primary_target_idx = (uint32_t)primary_target_idx;
        }
        URMA_LOG_INFO("Fallback task armed by kick, active_idx:%d primary_idx:%d seq:%u\n",
            task->active_local_idx, task->primary_local_idx, task->fallback_task.req_seq);
        bondp_process_fallback_task(bdp_ctx, task);
    }
    pthread_rwlock_unlock(&health->task_table.lock);
}

bool bondp_try_handle_fallback_cr(bondp_context_t *bdp_ctx, int local_idx, urma_cr_t *cr)
{
    if (!bondp_health_check_enabled() || !is_recv_cr(cr) || cr->opcode != URMA_CR_OPC_WRITE_WITH_IMM) {
        return false;
    }

    uint8_t ctrl_type = 0;
    uint8_t req_seq = 0;
    bondp_fallback_ctrl_decode(cr->imm_data & 0xFFFFULL, &ctrl_type, &req_seq);
    if (ctrl_type != BONDP_FALLBACK_CTRL_REQ && ctrl_type != BONDP_FALLBACK_CTRL_RESP) {
        return false;
    }

    urma_jetty_id_t pjetty_id = {
        .eid = bdp_ctx->p_ctxs[local_idx]->eid,
        .id = cr->local_id,
    };
    pthread_rwlock_rdlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_comp_t *bdp_jetty = bdp_p_vjetty_id_table_lookup_comp_without_lock(
        &bdp_ctx->p_vjetty_id_table, pjetty_id, JETTY);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    if (bdp_jetty == NULL) {
        return false;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_health_task_t *task = bondp_find_health_task_by_comp_nolock(health, bdp_jetty);
    if (task == NULL) {
        pthread_rwlock_unlock(&health->task_table.lock);
        return false;
    }

    if (ctrl_type == BONDP_FALLBACK_CTRL_REQ) {
        uint64_t *health_buf = (uint64_t *)bdp_ctx->bondp_heath_check_ctx.check_buf;
        uint32_t req_expected_primary_id = (health_buf == NULL) ?
            BONDP_FALLBACK_PRIMARY_INVALID_ID : (uint32_t)health_buf[0];
        uint32_t local_primary_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
        urma_jetty_t *local_primary_jetty = task->bondp_jetty->p_jetty[task->primary_local_idx];
        if (local_primary_jetty != NULL) {
            local_primary_id = local_primary_jetty->jetty_id.id;
        }
        bool need_rebuild = (local_primary_id == BONDP_FALLBACK_PRIMARY_INVALID_ID ||
            req_expected_primary_id != local_primary_id);
        if (need_rebuild && !task->fallback_task.local_rebuilt && bondp_rebuild_primary_pjetty(task) == 0) {
            task->fallback_task.local_rebuilt = true;
            local_primary_jetty = task->bondp_jetty->p_jetty[task->primary_local_idx];
            local_primary_id = (local_primary_jetty == NULL) ?
                BONDP_FALLBACK_PRIMARY_INVALID_ID : local_primary_jetty->jetty_id.id;
        } else if (!need_rebuild) {
            URMA_LOG_INFO("Fallback REQ matched local primary pjetty id:%u, skip rebuild\n", local_primary_id);
        }
        int resp_local_idx = task->active_local_idx;
        int resp_target_idx = -1;
        uint64_t payload = (uint64_t)local_primary_id;
        if (bondp_get_target_idx_by_local_idx(task, resp_local_idx, &resp_target_idx) == 0) {
            (void)bondp_send_fallback_ctrl_msg(bdp_ctx, task, resp_local_idx, resp_target_idx,
                BONDP_FALLBACK_CTRL_RESP, req_seq, payload);
        }
        bondp_process_fallback_task(bdp_ctx, task);
        pthread_rwlock_unlock(&health->task_table.lock);
        return true;
    }

    if (task->fallback_task.req_seq == req_seq) {
        uint64_t *health_buf = (uint64_t *)bdp_ctx->bondp_heath_check_ctx.check_buf;
        task->fallback_task.resp_received = true;
        task->fallback_task.remote_primary_pjetty_id = (health_buf == NULL) ?
            BONDP_FALLBACK_PRIMARY_INVALID_ID : (uint32_t)health_buf[0];
        bondp_process_fallback_task(bdp_ctx, task);
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    return true;
}

static void bondp_health_handle_ta_timeout_event(bondp_context_t *bdp_ctx, const bondp_health_event_info_t *info)
{
    if (info == NULL || info->local_idx < 0 || info->target_idx < 0 ||
        info->local_idx >= URMA_UBAGG_DEV_MAX_NUM || info->target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }

    uint32_t vjetty_id = 0;
    uint32_t parsed_local_idx = 0;
    uint32_t parsed_target_idx = 0;
    bondp_parse_health_user_ctx(info->user_ctx, &vjetty_id, &parsed_local_idx, &parsed_target_idx);
    if ((int)parsed_local_idx != info->local_idx || (int)parsed_target_idx != info->target_idx) {
        URMA_LOG_WARN("Health event decode mismatch, user_ctx:0x%lx local_idx:%d parsed_local:%u parsed_target:%u\n",
            info->user_ctx, info->local_idx, parsed_local_idx, parsed_target_idx);
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    bool consumed = false;
    pthread_rwlock_rdlock(&health->task_table.lock);
    uint32_t hash = bondp_health_task_hash(vjetty_id);
    hmap_node_t *node_ptr = bondp_hash_table_lookup_without_lock(&health->task_table, &vjetty_id, hash);
    if (node_ptr != NULL) {
        bondp_health_task_t *task = CONTAINER_OF_FIELD(node_ptr, bondp_health_task_t, hmap_node);
        bondp_health_sub_task_t *sub = &task->sub_tasks[info->local_idx][info->target_idx];
        if (sub->valid && sub->user_ctx == info->user_ctx && sub->local_idx == info->local_idx) {

            sub->probe_pending = false;
            bool old_ok = atomic_load(&sub->link_ok);
            bool ok = (info->cr_status == URMA_CR_SUCCESS);
            atomic_store(&sub->link_ok, ok);
            task->bondp_jetty->valid[sub->local_idx] = ok;
            if (old_ok != ok) {
                URMA_LOG_WARN("Health link state changed, tjetty:%u lidx:%d tidx:%d user_ctx:0x%lx old:%d new:%d cr_status:%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx, info->user_ctx, old_ok, ok,
                    info->cr_status);
            } else {
                URMA_LOG_DEBUG("Health CR handled, tjetty:%u lidx:%d tidx:%d user_ctx:0x%lx status:%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx, info->user_ctx, info->cr_status);
            }
            consumed = true;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    if (!consumed) {
        URMA_LOG_WARN("Health CR not matched to subtask, local_idx:%d user_ctx:0x%lx\n", info->local_idx, info->user_ctx);
    }
}

bool bondp_try_handle_health_check_cr(bondp_context_t *bdp_ctx, int local_idx, urma_cr_t *cr)
{
    if (!bondp_health_check_enabled()) {
        return false;
    }

    if ((cr->user_ctx & BONDP_HEALTH_CHECK_MAGIC_MASK) != BONDP_HEALTH_CHECK_MAGIC) {
        return false;
    }

    uint32_t cr_local_idx = 0;
    uint32_t target_idx = 0;
    uint32_t vjetty_id = 0;
    bondp_parse_health_user_ctx(cr->user_ctx, &vjetty_id, &cr_local_idx, &target_idx);
    if (cr_local_idx >= URMA_UBAGG_DEV_MAX_NUM || target_idx >= URMA_UBAGG_DEV_MAX_NUM ||
        (uint32_t)local_idx != cr_local_idx) {
        URMA_LOG_WARN("Health CR decode mismatch, user_ctx:0x%lx local_idx:%d parsed_local:%u parsed_target:%u\n",
            cr->user_ctx, local_idx, cr_local_idx, target_idx);
        return false;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    bool consumed = false;
    pthread_rwlock_rdlock(&health->task_table.lock);
    uint32_t hash = bondp_health_task_hash(vjetty_id);
    hmap_node_t *node_ptr = bondp_hash_table_lookup_without_lock(&health->task_table, &vjetty_id, hash);
    if (node_ptr != NULL) {
        bondp_health_task_t *task = CONTAINER_OF_FIELD(node_ptr, bondp_health_task_t, hmap_node);
        bondp_health_sub_task_t *sub = &task->sub_tasks[cr_local_idx][target_idx];
        if (sub->valid && sub->user_ctx == cr->user_ctx && sub->local_idx == local_idx) {
            sub->probe_pending = false;
            bool old_ok = atomic_load(&sub->link_ok);
            bool ok = (cr->status == URMA_CR_SUCCESS);
            atomic_store(&sub->link_ok, ok);
            task->bondp_jetty->valid[sub->local_idx] = ok;
            if (old_ok != ok) {
                URMA_LOG_WARN("Health link state changed, tjetty_id:%u lidx:%d tidx:%d user_ctx:0x%lx old:%d new:%d cr_status:%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, local_idx, (int)target_idx, cr->user_ctx, old_ok, ok, cr->status);
                bondp_health_event_info_t info = {
                .local_idx = (int)cr_local_idx,
                .target_idx = (int)target_idx,
                .user_ctx = cr->user_ctx,
                .cr_status = cr->status,
                .new_active_idx = -1,
                .bdp_jetty = NULL,
                .bdp_tjetty = NULL,
                };
                bondp_notify_health_event(bdp_ctx, BONDP_HEALTH_EVENT_TA_TIMEOUT, &info);
            } else {
                URMA_LOG_DEBUG("Health CR handled, tjetty_id:%u lidx:%d tidx:%d user_ctx:0x%lx status:%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, local_idx, (int)target_idx, cr->user_ctx, cr->status);
            }
            consumed = true;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    if (!consumed) {
        URMA_LOG_WARN("Health CR not matched to subtask, local_idx:%d user_ctx:0x%lx\n", local_idx, cr->user_ctx);
    }
    return consumed;
}

void bondp_stop_health_check_thread(void)
{
    bondp_global_context_t *global_ctx = g_bondp_global_ctx;
    if (!bondp_health_check_enabled()) {
        return;
    }

    if (global_ctx->health_thread_ctx.health_epoll_fd < 0) {
        return;
    }

    atomic_store(&global_ctx->health_thread_ctx.health_thread_stop, true);
    (void)pthread_join(global_ctx->health_thread_ctx.health_thread, NULL);
    atomic_store(&global_ctx->health_thread_ctx.health_thread_stop, false);

    pthread_rwlock_wrlock(&global_ctx->health_thread_ctx.health_ctx_lock);
    bondp_health_ctx_node_t *ctx_node = NULL;
    bondp_health_ctx_node_t *next = NULL;
    UB_LIST_FOR_EACH_SAFE(ctx_node, next, node, &global_ctx->health_thread_ctx.health_ctx_list) {
        ub_list_remove(&ctx_node->node);
        free(ctx_node);
    }
    pthread_rwlock_unlock(&global_ctx->health_thread_ctx.health_ctx_lock);

    URMA_LOG_INFO("Health check thread stopped.\n");
}

int bondp_start_health_check_thread(void)
{
    bondp_global_context_t *global_ctx = g_bondp_global_ctx;
    int health_epoll_fd;

    if (!bondp_health_check_enabled()) {
        return 0;
    }

    bondp_read_health_check_cfg(&global_ctx->health_thread_ctx.cfg);
    bondp_print_health_check_cfg(&global_ctx->health_thread_ctx.cfg);

    health_epoll_fd = epoll_create(UBAGG_MAX_EVENT);
    if (health_epoll_fd == -1) {
        URMA_LOG_ERR("Failed to create health epoll %s\n", ub_strerror(errno));
        return -1;
    }

    global_ctx->health_thread_ctx.health_epoll_fd = health_epoll_fd;
    atomic_store(&global_ctx->health_thread_ctx.health_thread_stop, false);
    if (pthread_create(&global_ctx->health_thread_ctx.health_thread, NULL, bondp_health_check_thread, global_ctx) != 0) {
        URMA_LOG_ERR("Failed to create health check thread\n");
        (void)close(health_epoll_fd);
        global_ctx->health_thread_ctx.health_epoll_fd = -1;
        return -1;
    }
    URMA_LOG_INFO("Health check thread started.\n");
    return 0;
}

void bondp_destroy_health_check_ctx(bondp_context_t *bond_ctx)
{
    bondp_global_context_t *global_ctx = g_bondp_global_ctx;
    bondp_heath_check_ctx_t *health = NULL;

    if (!bondp_health_check_enabled()) {
        return;
    }

    health = &bond_ctx->bondp_heath_check_ctx;
    bondp_hash_table_destroy(&health->task_table);
    bondp_unregister_health_ctx_global(bond_ctx);

    if (global_ctx->health_thread_ctx.health_epoll_fd >= 0 && health->health_check_fd >= 0) {
        (void)epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
            EPOLL_CTL_DEL, health->health_check_fd, NULL);
        (void)close(health->health_check_fd);
        health->health_check_fd = -1;
    }

    bondp_unregister_health_check_seg(bond_ctx);
    bondp_free_health_event_list(&health->event_list);
    pthread_spin_destroy(&health->event_lock);

    URMA_LOG_INFO("Health check ctx free, dev_name: %s, eid_idx: %u.\n",
        bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
}

int bondp_create_health_check_ctx(bondp_context_t *bond_ctx)
{
    bondp_global_context_t *global_ctx = g_bondp_global_ctx;
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;
    struct epoll_event ev = {0};

    if (!bondp_health_check_enabled()) {
        return 0;
    }

    if (pthread_spin_init(&health->event_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        URMA_LOG_ERR("Failed to init health event lock\n");
        return -1;
    }

    if (bondp_hash_table_create(&health->task_table, BONDP_HEALTH_TASK_TABLE_SIZE,
        bondp_health_task_comp_f, bondp_health_task_free_f, bondp_health_task_hash_f) != 0) {
        URMA_LOG_ERR("Failed to create health task table\n");
        goto ERR_EVENT_LOCK;
    }

    health->health_check_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (health->health_check_fd < 0) {
        URMA_LOG_ERR("Failed to create health_check_fd, errno: %d\n", errno);
        goto DEL_TASK_TABLE;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = (void *)bond_ctx;
    if (epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
        EPOLL_CTL_ADD, health->health_check_fd, &ev) != 0) {
        URMA_LOG_ERR("Failed to add ctx async fd to health epoll, errno: %d\n", errno);
        goto DEL_FD;
    }

    if (bondp_register_health_ctx_global(bond_ctx) != 0) {
        URMA_LOG_ERR("Failed to register health ctx globally\n");
        goto DEL_EPOLL;
    }

    URMA_LOG_INFO("Health check ctx enabled, dev_name: %s, eid_idx: %u, fd: %d.\n",
        bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index, health->health_check_fd);
    return 0;

DEL_EPOLL:
    (void)epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
        EPOLL_CTL_DEL, health->health_check_fd, NULL);
DEL_FD:
    (void)close(health->health_check_fd);
    health->health_check_fd = -1;
DEL_TASK_TABLE:
    bondp_hash_table_destroy(&health->task_table);
ERR_EVENT_LOCK:
    pthread_spin_destroy(&health->event_lock);
    return -1;
}
