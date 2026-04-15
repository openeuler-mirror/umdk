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

#include "urma_log.h"
#include "urma_api.h"
#include "bondp_health_check.h"

#define UBAGG_MAX_EVENT 1
#define BONDP_HEALTH_CHECK_BUF_LEN (4096)
#define BONDP_HEALTH_CHECK_4K_ALIGN (4096)
#define BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS (100)
#define BONDP_HEALTH_CHECK_INTERVAL_US (20000000ULL)

typedef struct bondp_health_ctx_node {
    bondp_context_t *bdp_ctx;
    struct ub_list node;
} bondp_health_ctx_node_t;

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
}

static void bondp_unregister_health_check_seg(bondp_context_t *bond_ctx)
{
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (health->check_tseg[i] == NULL) {
            continue;
        }

        if (urma_unregister_seg(health->check_tseg[i]) != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to unregister health check segment %d\n", i);
        }
        health->check_tseg[i] = NULL;
    }

    free(health->check_buf);
    health->check_buf = NULL;
}

static int bondp_register_health_check_seg(bondp_context_t *bond_ctx)
{
    bondp_heath_check_ctx_t *health = &bond_ctx->bondp_heath_check_ctx;
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

    health->check_buf = memalign(BONDP_HEALTH_CHECK_4K_ALIGN, health->check_buf_len);
    if (health->check_buf == NULL) {
        URMA_LOG_ERR("Failed to alloc health check buffer\n");
        return -1;
    }

    seg_cfg.va = (uint64_t)health->check_buf;

    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bond_ctx->p_ctxs[i] == NULL) {
            continue;
        }
        health->check_tseg[i] = urma_register_seg(bond_ctx->p_ctxs[i], &seg_cfg);
        if (health->check_tseg[i] == NULL) {
            URMA_LOG_ERR("Failed to register health check segment %d\n", i);
            bondp_unregister_health_check_seg(bond_ctx);
            return -1;
        }

        URMA_LOG_INFO("Succeed to register health check segment %d, len: %lu\n", i, health->check_buf_len);
    }
    return 0;
}

int bondp_fill_vjetty_health_info(bondp_context_t *bond_ctx, bondp_comp_t *bdp_jetty,
    urma_bond_seg_info_out_t *health_check_seg, bool *is_health_check_enable)
{
    *is_health_check_enable = bondp_health_check_enabled();
    if (!(*is_health_check_enable)) {
        return 0;
    }

    health_check_seg->dev_num = bond_ctx->dev_num;

    bondp_heath_check_ctx_t *health_ctx = &bond_ctx->bondp_heath_check_ctx;
    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL || health_ctx->check_tseg[i] == NULL) {
            continue;
        }
        health_check_seg->slaves[i] = health_ctx->check_tseg[i]->seg;
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

static void *bondp_health_check_thread(void *arg)
{
    bondp_global_context_t *global_ctx = (bondp_global_context_t *)arg;
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

        if (epoll_wait(epoll_fd, events, UBAGG_MAX_EVENT, BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS) < 0 &&
            errno != EINTR) {
            URMA_LOG_ERR("Health check epoll_wait failed, errno: %d\n", errno);
            (void)usleep(BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS * 1000);
            continue;
        }

        uint64_t now_us = bondp_get_monotonic_us();
        pthread_rwlock_rdlock(&global_ctx->health_thread_ctx.health_ctx_lock);
        bondp_health_ctx_node_t *ctx_node = NULL;
        UB_LIST_FOR_EACH(ctx_node, node, &global_ctx->health_thread_ctx.health_ctx_list) {
            bondp_heath_check_ctx_t *health = &ctx_node->bdp_ctx->bondp_heath_check_ctx;
            pthread_rwlock_rdlock(&health->task_lock);
            bondp_health_task_t *task = NULL;
            UB_LIST_FOR_EACH(task, node, &health->task_list) {
                if (now_us < task->next_probe_ts_us) {
                    continue;
                }
                for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
                    for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
                        bondp_health_sub_task_t *sub = &task->sub_tasks[i][j];
                        if (!sub->valid) {
                            continue;
                        }
                        URMA_LOG_INFO("Health check task trigger, lidx:%d tidx:%d\n", sub->local_idx, sub->target_idx);
                    }
                }
                task->next_probe_ts_us = now_us + BONDP_HEALTH_CHECK_INTERVAL_US;
            }
            pthread_rwlock_unlock(&health->task_lock);
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
    bondp_health_task_t *task = calloc(1, sizeof(bondp_health_task_t));
    if (task == NULL) {
        return -1;
    }
    task->bdp_tjetty = bdp_tjetty;
    task->bondp_jetty = cfg_jetty;
    task->next_probe_ts_us = bondp_get_monotonic_us() + BONDP_HEALTH_CHECK_INTERVAL_US;

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
        atomic_store(&sub->link_ok, true);
        sub->user_ctx = 0;
        URMA_LOG_DEBUG("Health subtask registered lidx:%d tidx:%d\n", (int)local_idx, (int)target_idx);
        sub_task_cnt++;
    }
    if (sub_task_cnt == 0) {
        free(task);
        URMA_LOG_ERR("Failed to register health task: no valid route\n");
        return -1;
    }
    pthread_rwlock_wrlock(&health->task_lock);
    ub_list_push_front(&health->task_list, &task->node);
    pthread_rwlock_unlock(&health->task_lock);

    return 0;
}

void bondp_unregister_health_check_task(bondp_target_jetty_t *bdp_tjetty)
{
    if (!bondp_health_check_enabled()) {
        return;
    }

    bondp_health_thread_ctx_t *thread_ctx = &g_bondp_global_ctx->health_thread_ctx;
    pthread_rwlock_rdlock(&thread_ctx->health_ctx_lock);
    bondp_health_ctx_node_t *ctx_node = NULL;
    UB_LIST_FOR_EACH(ctx_node, node, &thread_ctx->health_ctx_list) {
        bondp_heath_check_ctx_t *health = &ctx_node->bdp_ctx->bondp_heath_check_ctx;
        bool removed = false;
        pthread_rwlock_wrlock(&health->task_lock);
        bondp_health_task_t *task = NULL;
        bondp_health_task_t *next = NULL;
        UB_LIST_FOR_EACH_SAFE(task, next, node, &health->task_list) {
            if (task->bdp_tjetty == bdp_tjetty) {
                ub_list_remove(&task->node);
                bondp_free_health_task(task);
                removed = true;
                break;
            }
        }
        pthread_rwlock_unlock(&health->task_lock);
        if (removed) {
            URMA_LOG_INFO("Health check task unregistered, tjetty:%p\n", (void *)bdp_tjetty);
            break;
        }
    }
    pthread_rwlock_unlock(&thread_ctx->health_ctx_lock);
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

    health_epoll_fd = epoll_create(UBAGG_MAX_EVENT);
    if (health_epoll_fd == -1) {
        URMA_LOG_ERR("Failed to create health epoll %s\n", ub_strerror(errno));
        return -1;
    }

    global_ctx->health_thread_ctx.health_epoll_fd = health_epoll_fd;

    bondp_read_health_check_cfg(&global_ctx->health_thread_ctx.cfg);
    bondp_print_health_check_cfg(&global_ctx->health_thread_ctx.cfg);

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
    bondp_health_task_t *task = NULL;
    bondp_health_task_t *next = NULL;

    if (!bondp_health_check_enabled()) {
        return;
    }

    health = &bond_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_lock);
    UB_LIST_FOR_EACH_SAFE(task, next, node, &health->task_list) {
        ub_list_remove(&task->node);
        bondp_free_health_task(task);
    }
    pthread_rwlock_unlock(&health->task_lock);
    pthread_rwlock_destroy(&health->task_lock);
    bondp_unregister_health_ctx_global(bond_ctx);

    if (global_ctx->health_thread_ctx.health_epoll_fd >= 0 && health->health_check_fd >= 0) {
        (void)epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
            EPOLL_CTL_DEL, health->health_check_fd, NULL);
        (void)close(health->health_check_fd);
        health->health_check_fd = -1;
    }

    bondp_unregister_health_check_seg(bond_ctx);

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

    if (global_ctx->health_thread_ctx.health_epoll_fd < 0) {
        URMA_LOG_ERR("Health check thread is not created\n");
        return -1;
    }

    pthread_rwlock_init(&health->task_lock, NULL);
    ub_list_init(&health->task_list);

    if (bondp_register_health_check_seg(bond_ctx) != 0) {
        goto DEL_LOCK;
    }

    health->health_check_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (health->health_check_fd < 0) {
        URMA_LOG_ERR("Failed to create health_check_fd, errno: %d\n", errno);
        goto UNREGISTER_SEG;
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
UNREGISTER_SEG:
    bondp_unregister_health_check_seg(bond_ctx);
DEL_LOCK:
    pthread_rwlock_destroy(&health->task_lock);
    return -1;
}
