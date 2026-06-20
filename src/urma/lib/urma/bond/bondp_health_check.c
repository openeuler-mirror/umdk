/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check implementation
 */

#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
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
#include "bondp_link_recovery.h"
#include "bondp_netlink.h"
#include "urma_private.h"

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

#define BONDP_FALLBACK_CTRL_REQ                        1
#define BONDP_FALLBACK_CTRL_RESP                       2
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
        URMA_LOG_WARN("Failed to alloc health event node, event=%d\n", event);
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
        URMA_LOG_WARN("Failed to notify health event, fd=%d event=%d errno=%d\n",
            health->health_check_fd, event, errno);
    }
}

static void bondp_health_handle_ta_timeout_event(bondp_context_t *bdp_ctx, const bondp_health_event_info_t *info);
static void bondp_health_handle_datapath_link_fail_event(bondp_context_t *bdp_ctx,
    const bondp_health_event_info_t *info);
static bool bondp_health_handle_fallback_ctrl_rx_impl(bondp_context_t *bdp_ctx, uint32_t recv_local_id,
    uint8_t ctrl_type, uint8_t req_seq, uint32_t payload, bool silent_unmatched);

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

static int bondp_select_backup_local_idx(const bondp_health_task_t *task, int *backup_local_idx)
{
    if (task == NULL || backup_local_idx == NULL || task->bondp_jetty == NULL) {
        return -1;
    }

    const bondp_comp_t *bdp_jetty = task->bondp_jetty;
    for (uint32_t i = 0; i < bdp_jetty->active_count; ++i) {
        int local_idx = (int)bdp_jetty->active_indices[i];
        if (local_idx < 0 || local_idx >= URMA_UBAGG_DEV_MAX_NUM || local_idx == task->primary_local_idx) {
            continue;
        }
        if (bdp_jetty->p_jetty[local_idx] == NULL) {
            continue;
        }
        int target_idx = -1;
        if (bondp_get_target_idx_by_local_idx(task, local_idx, &target_idx) != 0) {
            continue;
        }
        *backup_local_idx = local_idx;
        return 0;
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

static int bondp_register_health_ctx_global(bondp_context_t *bond_ctx)
{
    bondp_health_thread_ctx_t *thread_ctx = &g_bondp_global_ctx->health_thread_ctx;

    bondp_health_ctx_node_t *new_node = calloc(1, sizeof(bondp_health_ctx_node_t));
    if (new_node == NULL) {
        URMA_LOG_ERR("Failed to alloc health ctx node, dev=%s, eid_idx=%u\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
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

static void bondp_unregister_health_ctx_global(const bondp_context_t *bond_ctx)
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

bool bondp_health_check_enabled(void)
{
    return g_bondp_global_ctx->health_thread_ctx.enable_health_check;
}

void bondp_health_check_global_ctx_init(bondp_global_context_t *ctx)
{
    ctx->health_thread_ctx.health_epoll_fd = -1;
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

        URMA_LOG_INFO("Successfully registered health check segment %d, len=%lu\n", i, health->check_buf_len);
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

    for (int i = 0; i < bond_ctx->dev_num; ++i) {
        if (bdp_jetty->p_jetty[i] == NULL || bdp_jetty->check_tseg[i] == NULL) {
            continue;
        }
        bondp_seg_to_base(&bdp_jetty->check_tseg[i]->seg, &health_check_seg->slaves[i]);
    }

    URMA_LOG_INFO("Successfully filled health check seg info to kernel, dev_num=%d\n", bond_ctx->dev_num);
    return 0;
}

static int import_check_tseg_by_import_result(const bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
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
            bdp_ctx->p_ctxs[local_idx] == NULL ||
            bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL) {
            URMA_LOG_DEBUG("BONDP skip check seg route (%u %u)\n", local_idx, target_idx);
            continue;
        }

        if (bdp_tjetty->p_check_tseg[local_idx][target_idx] != NULL) {
            has_valid_route = true;
            continue;
        }

        urma_seg_t check_seg = {0};
        bondp_seg_base_to_seg(&rvjetty_info->health_check_seg.slaves[target_idx], &check_seg);
        bdp_tjetty->p_check_tseg[local_idx][target_idx] =
            urma_import_seg(bdp_ctx->p_ctxs[local_idx], &check_seg, NULL, 0, flag);
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

    URMA_LOG_INFO("Successfully imported health check segs\n");
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

    URMA_LOG_INFO("Finish to unimport health check segs, ret=%d\n", ret);
    return ret;
}

int bondp_import_health_check_tseg(const bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    urma_bond_id_info_out_t *rvjetty_info, const urma_rjetty_t *rjetty)
{
    if (!rvjetty_info->is_health_check_enable || !bondp_health_check_enabled()) {
        return 0;
    }

    bondp_comp_t *cfg_jetty = NULL;
    if (rjetty->flag.bs.has_drv_ext) {
        const bondp_rjetty_t *bdp_rjetty = (const bondp_rjetty_t *)rjetty;
        cfg_jetty = CONTAINER_OF_FIELD(bdp_rjetty->jetty, bondp_comp_t, v_jetty);
    }

    if (rjetty->flag.bs.has_drv_ext == 0 || cfg_jetty == NULL) {
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
        case BONDP_HEALTH_EVENT_DATAPATH_LINK_FAIL:
            bondp_health_handle_datapath_link_fail_event(bond_ctx, info);
            break;
        default:
            URMA_LOG_WARN("Unknown health event=%d, dev_name=%s eid_idx=%u\n",
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
        URMA_LOG_WARN("Health epoll error event=0x%x\n", event->events);
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
        URMA_LOG_WARN("Failed to read health eventfd, fd=%d errno=%d\n", health->health_check_fd, errno);
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
        URMA_LOG_WARN("Health probe write failed, lidx=%d tidx=%d ret=%d\n", local_idx, target_idx, ret);
    } else {
        URMA_LOG_DEBUG("Health probe sent, lidx=%d tidx=%d user_ctx=0x%lx\n",
            local_idx, target_idx, user_ctx);
    }
    return ret;
}

static int bondp_rebuild_primary_pjetty(bondp_health_task_t *task)
{
    if (task == NULL) {
        return -1;
    }
    return bondp_rebuild_local_pjetty(task, task->primary_local_idx);
}

static int bondp_send_fallback_ctrl_msg(
    bondp_context_t *bdp_ctx, bondp_health_task_t *task,
    int local_idx, int target_idx, uint8_t ctrl_type, uint8_t req_seq, uint64_t payload)
{
    if (local_idx < 0 || target_idx < 0 || payload > UINT32_MAX) {
        return -1;
    }

    // Not support
    return -1;
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
        URMA_LOG_ERR("Failed to unimport old primary ptjetty, lidx=%d tidx=%d\n", local_idx, target_idx);
        return -1;
    }
    task->bdp_tjetty->p_tjetty[local_idx][target_idx] = NULL;

    urma_token_t *import_token = task->bdp_tjetty->import_token_valid ? &task->bdp_tjetty->import_token_value : NULL;
    urma_target_jetty_t *new_tjetty = urma_import_jetty(bdp_ctx->p_ctxs[local_idx], &rjetty, import_token);
    if (new_tjetty == NULL) {
        URMA_LOG_ERR("Failed to import recreated primary ptjetty, local_idx=%d target_idx=%d pjetty_id=%u\n",
            local_idx, target_idx, rjetty.jetty_id.id);
        return -1;
    }
    task->bdp_tjetty->p_tjetty[local_idx][target_idx] = new_tjetty;
    atomic_store(&task->bondp_jetty->valid[local_idx], false);
    return 0;
}

static void bondp_fallback_reset_for_new_round(bondp_health_task_t *task)
{
    task->fallback_task.pending = true;
    task->fallback_task.local_rebuilt = false;
    task->fallback_task.req_sent = false;
    task->fallback_task.resp_received = false;
    task->fallback_task.relink_done = false;
    task->fallback_task.req_seq++;
    task->fallback_task.remote_primary_pjetty_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
}

static uint64_t bondp_fallback_build_req_payload(const bondp_health_task_t *task)
{
    int primary_local_idx = task->primary_local_idx;
    if (primary_local_idx < 0 || primary_local_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return BONDP_FALLBACK_PRIMARY_INVALID_ID;
    }
    urma_jetty_t *primary_pjetty = task->bondp_jetty->p_jetty[primary_local_idx];
    if (primary_pjetty == NULL || primary_pjetty->remote_jetty == NULL) {
        return BONDP_FALLBACK_PRIMARY_INVALID_ID;
    }
    return (uint64_t)primary_pjetty->remote_jetty->id.id;
}

static int bondp_send_fallback_req(bondp_context_t *bdp_ctx, bondp_health_task_t *task)
{
    int active_local_idx = task->active_local_idx;
    int active_target_idx = -1;
    if (bondp_get_target_idx_by_local_idx(task, active_local_idx, &active_target_idx) != 0) {
        return -1;
    }
    uint64_t req_payload = bondp_fallback_build_req_payload(task);
    if (bondp_send_fallback_ctrl_msg(bdp_ctx, task, active_local_idx, active_target_idx,
        BONDP_FALLBACK_CTRL_REQ, task->fallback_task.req_seq, req_payload) != 0) {
        return -1;
    }
    return 0;
}

static bool bondp_process_fallback_task(bondp_context_t *bdp_ctx, bondp_health_task_t *task)
{
    bondp_fallback_task_t *fallback = &task->fallback_task;
    if (!fallback->pending) {
        return false;
    }

    if (!fallback->local_rebuilt) {
        if (bondp_rebuild_primary_pjetty(task) != 0) {
            return false;
        }
        fallback->local_rebuilt = true;
    }

    if (!fallback->req_sent && bondp_send_fallback_req(bdp_ctx, task) == 0) {
        fallback->req_sent = true;
        return false;
    }

    if (!fallback->resp_received || fallback->relink_done ||
        fallback->remote_primary_pjetty_id == BONDP_FALLBACK_PRIMARY_INVALID_ID) {
        return false;
    }

    if (bondp_relink_primary_import(task) == 0) {
        fallback->relink_done = true;
        fallback->pending = false;
        fallback->local_rebuilt = false;
        fallback->req_sent = false;
        fallback->resp_received = false;
        fallback->remote_primary_pjetty_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
        for (uint32_t n = 0; n < task->bdp_tjetty->active_count; ++n) {
            uint32_t local_idx = task->bdp_tjetty->local_active_indices[n];
            uint32_t target_idx = task->bdp_tjetty->active_indices[n];
            if (local_idx >= URMA_UBAGG_DEV_MAX_NUM || target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
                continue;
            }
            if (task->bondp_jetty->p_jetty[local_idx] == NULL ||
                task->bdp_tjetty->p_tjetty[local_idx][target_idx] == NULL ||
                task->bdp_tjetty->p_check_tseg[local_idx][target_idx] == NULL) {
                continue;
            }
            bondp_health_sub_task_t *sub = &task->sub_tasks[local_idx][target_idx];
            sub->local_idx = (int)local_idx;
            sub->target_idx = (int)target_idx;
            sub->valid = true;
            sub->probe_pending = false;
            atomic_store(&sub->link_ok, true);
        }
        task->next_probe_ts_us = bondp_get_monotonic_us();
        URMA_LOG_INFO(
            "Fallback relink finished, health subtasks resumed, waiting health probe to validate primary idx=%d\n",
            task->primary_local_idx);
        return true;
    }
    return false;
}

static void bondp_health_task_check_mode(bondp_health_task_t *task,
    const bondp_health_check_cfg_t *cfg, uint64_t now_us)
{
    bool primary_valid = atomic_load(&task->bondp_jetty->valid[task->primary_local_idx]);
    if (task->mode == HEALTH_MODE_BACKUP_CHECK && !primary_valid) {
        /* Primary link went down, switch to primary check mode */
        task->mode = HEALTH_MODE_PRIMARY_CHECK;
        task->backoff_cnt = 0;
        task->next_probe_ts_us = now_us + cfg->active_start_ms * 1000ULL;
        URMA_LOG_INFO("Primary link (lidx=%d) down, switch to PRIMARY_CHECK mode, start after %lums\n",
            task->primary_local_idx, (unsigned long)cfg->active_start_ms);
    } else if (task->mode == HEALTH_MODE_PRIMARY_CHECK && primary_valid) {
        /* Primary link recovered (user switched back), resume backup check */
        task->mode = HEALTH_MODE_BACKUP_CHECK;
        task->backoff_cnt = 0;
        task->next_probe_ts_us = now_us + cfg->backup_interval_ms * 1000ULL;
        URMA_LOG_INFO("Primary link (lidx=%d) recovered, switch to BACKUP_CHECK mode\n",
            task->primary_local_idx);
    }
}

static void bondp_health_probe_sub(bondp_context_t *bdp_ctx, bondp_health_task_t *task,
    bondp_health_sub_task_t *sub)
{
    bool is_balance = (task->bondp_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE);
    if (sub->probe_pending) {
        URMA_LOG_INFO("Health probe skipped (pending), lidx=%d tidx=%d\n", sub->local_idx, sub->target_idx);
        return;
    }

    sub->probe_pending = true;
    if (bondp_send_health_probe(bdp_ctx, task->bdp_tjetty, task->bondp_jetty, sub, task->vjetty_id) != URMA_SUCCESS) {
        sub->probe_pending = false;
        if (atomic_load(&sub->link_ok)) {
            URMA_LOG_WARN("Health probe send failed, lidx=%d tidx=%d\n", sub->local_idx, sub->target_idx);
        }
        atomic_store(&sub->link_ok, false);
        sub->need_check = true;
        atomic_store(&task->bondp_jetty->valid[sub->local_idx], false);
        if (is_balance) {
            bondp_health_notify_datapath_link_fail(bdp_ctx, task->bdp_tjetty, sub->local_idx, sub->target_idx);
        }
        return;
    }
}

static bool bondp_health_balance_has_pending_probe(const bondp_health_task_t *task)
{
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            const bondp_health_sub_task_t *sub = &task->sub_tasks[i][j];
            if (!sub->valid) {
                continue;
            }
            if (sub->need_check || sub->probe_pending) {
                return true;
            }
        }
    }
    return false;
}

static void bondp_health_do_check(bondp_context_t *bdp_ctx, bondp_health_task_t *task)
{
    bool is_balance = (task->bondp_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE);
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        for (int j = 0; j < URMA_UBAGG_DEV_MAX_NUM; ++j) {
            bondp_health_sub_task_t *sub = &task->sub_tasks[i][j];
            if (!sub->valid) {
                continue;
            }
            if (is_balance) {
                if (!sub->need_check) {
                    continue;
                }
            } else if (sub->local_idx == task->active_local_idx) {
                continue;
            }
            bondp_health_probe_sub(bdp_ctx, task, sub);
        }
    }
}

static uint64_t bondp_health_calc_primary_interval_us(const bondp_health_check_cfg_t *cfg, uint32_t backoff_cnt)
{
    uint64_t interval_ms = cfg->active_interval_ms;
    uint32_t shift = (backoff_cnt < cfg->active_max_backoff) ?
        backoff_cnt : cfg->active_max_backoff;
    interval_ms <<= shift;
    return interval_ms * 1000ULL;
}

static void *bondp_health_check_thread(void *arg)
{
    bondp_global_context_t *global_ctx = (bondp_global_context_t *)arg;
    const bondp_health_check_cfg_t *cfg = &global_ctx->health_thread_ctx.cfg;
    struct epoll_event events[UBAGG_MAX_EVENT];

    if (prctl(PR_SET_NAME, "bond_health_t", 0, 0, 0) != 0) {
        URMA_LOG_WARN("Failed to set health thread name, errno=%d\n", errno);
    }

    int epoll_fd = global_ctx->health_thread_ctx.health_epoll_fd;

    while (true) {
        bool stop = atomic_load(&global_ctx->health_thread_ctx.health_thread_stop);
        if (stop) {
            break;
        }

        int event_num = epoll_wait(epoll_fd, events, UBAGG_MAX_EVENT, BONDP_HEALTH_CHECK_EPOLL_TIMEOUT_MS);
        if (event_num < 0 && errno != EINTR) {
            URMA_LOG_ERR("Health check epoll_wait failed, errno=%d\n", errno);
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
                bool is_balance = (task->bondp_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE);

                if (task->bdp_tjetty->v_tjetty.trans_mode == URMA_TM_RC) {
                    URMA_LOG_DEBUG("Skip RC mode\n");
                    continue;
                }
                if (!is_balance) {
                    bondp_health_task_check_mode(task, cfg, now_us);
                }
                if (now_us < task->next_probe_ts_us) {
                    continue;
                }
                URMA_LOG_DEBUG("Health check round mode=%s active_idx=%d primary_idx=%d backoff=%u\n",
                    task->mode == HEALTH_MODE_BACKUP_CHECK ? "BACKUP" : "PRIMARY",
                    task->active_local_idx, task->primary_local_idx, task->backoff_cnt);
                bondp_health_do_check(ctx_node->bdp_ctx, task);
                if (is_balance) {
                    if (bondp_health_balance_has_pending_probe(task)) {
                        task->next_probe_ts_us = now_us + cfg->active_interval_ms * 1000ULL;
                    } else {
                        task->next_probe_ts_us = UINT64_MAX;
                    }
                } else if (task->mode == HEALTH_MODE_BACKUP_CHECK) {
                    task->next_probe_ts_us = now_us + cfg->backup_interval_ms * 1000ULL;
                } else {
                    task->next_probe_ts_us = now_us +
                        bondp_health_calc_primary_interval_us(cfg, task->backoff_cnt);
                    if (task->backoff_cnt < cfg->active_max_backoff) {
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

static bondp_health_task_t *bondp_find_health_task_by_cr_local_id_nolock(
    bondp_heath_check_ctx_t *health, uint32_t cr_local_id, int *parsed_local_idx)
{
    bondp_health_task_t *task = NULL;
    HMAP_FOR_EACH(task, hmap_node, &health->task_table.hmap) {
        for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
            urma_jetty_t *pjetty = task->bondp_jetty->p_jetty[i];
            if (pjetty == NULL) {
                continue;
            }
            if (pjetty->jetty_id.id == cr_local_id) {
                *parsed_local_idx = i;
                return task;
            }
        }
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
    task->next_probe_ts_us = (cfg_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE) ?
        UINT64_MAX : (bondp_get_monotonic_us() + cfg->backup_start_ms * 1000ULL);
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
        sub->need_check = (cfg_jetty->bondp_ctx->bonding_mode != BONDP_BONDING_MODE_BALANCE);
        atomic_store(&sub->link_ok, true);
        sub->user_ctx = 0;
        if (task->primary_local_idx < 0) {
            task->primary_local_idx = (int)local_idx;
            task->active_local_idx = (int)local_idx;
        }
        URMA_LOG_DEBUG("Health subtask registered lidx=%d tidx=%d\n", (int)local_idx, (int)target_idx);
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

    URMA_LOG_INFO("Health task registered, tjetty=%u sub_cnt=%d primary_idx=%d active_idx=%d start_ms=%lu\n",
        bdp_tjetty->v_tjetty.id.id, sub_task_cnt, task->primary_local_idx, task->active_local_idx,
        (unsigned long)cfg->backup_start_ms);
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
            URMA_LOG_INFO("Health check task unregistered, tjetty=%u\n", bdp_tjetty->v_tjetty.id.id);
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
        task->bondp_jetty->pjettys_error_done[new_active_idx] &= (uint8_t)(~PJETTY_FLUSH_ERROR_DONE);
        if (new_active_idx == task->primary_local_idx) {
            task->fallback_task.relink_done = false;
            task->fallback_task.pending = false;
            task->fallback_task.local_rebuilt = false;
            task->fallback_task.req_sent = false;
            task->fallback_task.resp_received = false;
            task->fallback_task.remote_primary_pjetty_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
            URMA_LOG_INFO("Primary active link resumed, re-enable next fallback round, tjetty=%u primary_idx=%d\n",
                bdp_tjetty->v_tjetty.id.id, task->primary_local_idx);
        }
        URMA_LOG_INFO("Health active link updated, tjetty=%u old_idx=%d new_idx=%d\n",
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
        !task->fallback_task.pending &&
        !task->fallback_task.relink_done) {
        task->mode = HEALTH_MODE_PRIMARY_CHECK;
        bondp_fallback_reset_for_new_round(task);
        int primary_target_idx = -1;
        if (bondp_get_target_idx_by_local_idx(task, task->primary_local_idx, &primary_target_idx) == 0) {
            task->fallback_task.primary_target_idx = (uint32_t)primary_target_idx;
        }
        URMA_LOG_INFO("Fallback task armed by kick, active_idx=%d primary_idx=%d seq=%u\n",
            task->active_local_idx, task->primary_local_idx, task->fallback_task.req_seq);
        (void)bondp_process_fallback_task(bdp_ctx, task);
    }
    pthread_rwlock_unlock(&health->task_table.lock);
}

static bool bondp_health_handle_fallback_ctrl_rx_impl(bondp_context_t *bdp_ctx, uint32_t recv_local_id,
    uint8_t ctrl_type, uint8_t req_seq, uint32_t payload, bool silent_unmatched)
{
    if (!bondp_health_check_enabled()) {
        return false;
    }

    if (ctrl_type != BONDP_FALLBACK_CTRL_REQ && ctrl_type != BONDP_FALLBACK_CTRL_RESP) {
        if (!silent_unmatched) {
            URMA_LOG_WARN("Invalid fallback ctrl type=%u local_id=%u\n", ctrl_type, recv_local_id);
        }
        return false;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    pthread_rwlock_wrlock(&health->task_table.lock);
    int req_recv_local_idx = -1;
    bondp_health_task_t *task = bondp_find_health_task_by_cr_local_id_nolock(
        health, recv_local_id, &req_recv_local_idx);
    if (task == NULL) {
        pthread_rwlock_unlock(&health->task_table.lock);
        if (!silent_unmatched) {
            URMA_LOG_WARN("Fallback ctrl not matched by local_id=%u\n", recv_local_id);
        }
        return false;
    }

    if (ctrl_type == BONDP_FALLBACK_CTRL_REQ) {
        uint32_t req_expected_primary_id = payload;
        uint32_t local_primary_id = BONDP_FALLBACK_PRIMARY_INVALID_ID;
        urma_jetty_t *local_primary_jetty = task->bondp_jetty->p_jetty[task->primary_local_idx];
        if (local_primary_jetty != NULL) {
            local_primary_id = local_primary_jetty->jetty_id.id;
        }
        bool need_rebuild = (local_primary_id == BONDP_FALLBACK_PRIMARY_INVALID_ID ||
            req_expected_primary_id != local_primary_id);
        if (need_rebuild && !task->fallback_task.local_rebuilt && !task->fallback_task.relink_done) {
            if (bondp_rebuild_primary_pjetty(task) != 0) {
                URMA_LOG_WARN("Fallback REQ rebuild failed, skip RESP for this round, seq=%u\n", req_seq);
                pthread_rwlock_unlock(&health->task_table.lock);
                return true;
            }
            task->fallback_task.local_rebuilt = true;
            if (task->active_local_idx == task->primary_local_idx) {
                int backup_local_idx = -1;
                if (bondp_select_backup_local_idx(task, &backup_local_idx) == 0) {
                    task->active_local_idx = backup_local_idx;
                    URMA_LOG_INFO(
                        "Fallback REQ rebuild primary active link, switch active idx to backup, old=%d new=%d\n",
                        task->primary_local_idx, backup_local_idx);
                } else {
                    URMA_LOG_WARN(
                        "Fallback REQ rebuild primary active link, but no backup route available, keep active idx=%d\n",
                        task->active_local_idx);
                }
            }
            local_primary_jetty = task->bondp_jetty->p_jetty[task->primary_local_idx];
            local_primary_id = (local_primary_jetty == NULL) ?
                BONDP_FALLBACK_PRIMARY_INVALID_ID : local_primary_jetty->jetty_id.id;
        } else if (!need_rebuild) {
            URMA_LOG_INFO("Fallback REQ matched local primary pjetty id=%u, skip rebuild\n", local_primary_id);
        }

        (void)bondp_process_fallback_task(bdp_ctx, task);

        int resp_local_idx = req_recv_local_idx;
        int resp_target_idx = -1;
        uint64_t resp_payload = (uint64_t)local_primary_id;
        if (bondp_get_target_idx_by_local_idx(task, resp_local_idx, &resp_target_idx) == 0) {
            (void)bondp_send_fallback_ctrl_msg(bdp_ctx, task, resp_local_idx, resp_target_idx,
                BONDP_FALLBACK_CTRL_RESP, req_seq, resp_payload);
        } else {
            URMA_LOG_WARN("Fallback RESP route not found for req link lidx=%d seq=%u\n",
                resp_local_idx, req_seq);
        }
        pthread_rwlock_unlock(&health->task_table.lock);
        return true;
    }

    if (task->fallback_task.req_seq == req_seq) {
        task->fallback_task.resp_received = true;
        task->fallback_task.remote_primary_pjetty_id = payload;
        URMA_LOG_INFO("Fallback RESP accepted, seq=%u remote_primary_id=%u\n",
            req_seq, task->fallback_task.remote_primary_pjetty_id);
        (void)bondp_process_fallback_task(bdp_ctx, task);
    } else {
        URMA_LOG_WARN("Fallback RESP dropped due to seq mismatch, recv_seq=%u expect_seq=%u\n",
            req_seq, task->fallback_task.req_seq);
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    return true;
}

void bondp_health_notify_fallback_ctrl_rx(bondp_context_t *bdp_ctx, uint32_t recv_local_id,
    uint8_t ctrl_type, uint8_t req_seq, uint32_t payload)
{
    (void)bondp_health_handle_fallback_ctrl_rx_impl(bdp_ctx, recv_local_id, ctrl_type, req_seq, payload, false);
}

static void bondp_health_handle_datapath_link_fail_event(bondp_context_t *bdp_ctx,
    const bondp_health_event_info_t *info)
{
    if (info == NULL || info->bdp_tjetty == NULL ||
        info->local_idx < 0 || info->target_idx < 0 ||
        info->local_idx >= URMA_UBAGG_DEV_MAX_NUM || info->target_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    const bondp_health_check_cfg_t *cfg = &g_bondp_global_ctx->health_thread_ctx.cfg;
    pthread_rwlock_wrlock(&health->task_table.lock);
    bondp_health_task_t *task = bondp_find_health_task_by_tjetty_nolock(health, info->bdp_tjetty);
    if (task != NULL && task->bondp_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE) {
        bondp_health_sub_task_t *sub = &task->sub_tasks[info->local_idx][info->target_idx];
        if (sub->valid) {
            sub->probe_pending = false;
            sub->need_check = true;
            atomic_store(&sub->link_ok, false);
            atomic_store(&task->bondp_jetty->valid[sub->local_idx], false);
            if (bondp_rebuild_local_pjetty(task, info->local_idx) != 0) {
                URMA_LOG_WARN("Balance link recover failed, tjetty=%u lidx=%d tidx=%d\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx);
            } else {
                URMA_LOG_INFO("Balance link recovered, start health check, tjetty=%u lidx=%d tidx=%d\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx);
            }
            task->next_probe_ts_us = bondp_get_monotonic_us() + cfg->active_start_ms * 1000ULL;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
}

void bondp_health_notify_datapath_link_fail(bondp_context_t *bdp_ctx, bondp_target_jetty_t *bdp_tjetty,
    int local_idx, int target_idx)
{
    if (!bondp_health_check_enabled() || bdp_ctx == NULL || bdp_tjetty == NULL) {
        return;
    }

    bondp_health_event_info_t info = {
        .local_idx = local_idx,
        .target_idx = target_idx,
        .user_ctx = 0,
        .cr_status = 0,
        .new_active_idx = -1,
        .bdp_jetty = NULL,
        .bdp_tjetty = bdp_tjetty,
    };
    bondp_notify_health_event(bdp_ctx, BONDP_HEALTH_EVENT_DATAPATH_LINK_FAIL, &info);
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
        URMA_LOG_WARN("Health event decode mismatch, user_ctx=0x%lx local_idx=%d parsed_local=%u parsed_target=%u\n",
            info->user_ctx, info->local_idx, parsed_local_idx, parsed_target_idx);
        return;
    }

    bondp_heath_check_ctx_t *health = &bdp_ctx->bondp_heath_check_ctx;
    bool consumed = false;
    bool need_kick = false;
    pthread_rwlock_wrlock(&health->task_table.lock);
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
            atomic_store(&task->bondp_jetty->valid[sub->local_idx], ok);
            if (old_ok != ok) {
                URMA_LOG_WARN(
                    "Health link state changed, tjetty=%u lidx=%d tidx=%d user_ctx=0x%lx old=%d new=%d cr_status=%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx, info->user_ctx, old_ok, ok,
                    info->cr_status);
            } else {
                URMA_LOG_DEBUG("Health CR handled, tjetty=%u lidx=%d tidx=%d user_ctx=0x%lx status=%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx, info->user_ctx,
                    info->cr_status);
            }
            if (!ok && info->local_idx != task->primary_local_idx) {
                if (bondp_rebuild_local_pjetty(task, info->local_idx) != 0) {
                    URMA_LOG_WARN("Failed to rebuild backup link by health event, tjetty=%u lidx=%d tidx=%d\n",
                        task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx);
                } else {
                    URMA_LOG_INFO("Backup link rebuilt by health event, tjetty=%u lidx=%d tidx=%d\n",
                        task->bdp_tjetty->v_tjetty.id.id, info->local_idx, info->target_idx);
                }
            }
            if (!ok && info->local_idx == task->primary_local_idx) {
                task->fallback_task.relink_done = false;
                task->fallback_task.pending = false;
                need_kick = true;
            }
            consumed = true;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    if (!consumed) {
        URMA_LOG_WARN("Health CR not matched to subtask, local_idx=%d user_ctx=0x%lx\n",
            info->local_idx, info->user_ctx);
    }
    if (need_kick) {
        bondp_health_kick_fallback_task(bdp_ctx, info->bdp_tjetty);
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
        URMA_LOG_WARN("Health CR decode mismatch, user_ctx=0x%lx local_idx=%d parsed_local=%u parsed_target=%u\n",
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
            bool is_balance = (task->bondp_jetty->bondp_ctx->bonding_mode == BONDP_BONDING_MODE_BALANCE);
            atomic_store(&sub->link_ok, ok);
            atomic_store(&task->bondp_jetty->valid[sub->local_idx], ok);
            sub->need_check = is_balance ? (!ok) : sub->need_check;
            if (ok && task->mode == HEALTH_MODE_PRIMARY_CHECK &&
                local_idx == task->primary_local_idx && task->active_local_idx != task->primary_local_idx) {
                bondp_health_event_info_t active_info = {
                    .local_idx = -1,
                    .target_idx = -1,
                    .user_ctx = 0,
                    .cr_status = 0,
                    .new_active_idx = task->primary_local_idx,
                    .bdp_jetty = NULL,
                    .bdp_tjetty = task->bdp_tjetty,
                };
                bondp_notify_health_event(bdp_ctx, BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE, &active_info);
                URMA_LOG_INFO("Primary health probe success, switch active idx back to primary, " \
                    "tjetty_id=%u old_active=%d new_active=%d\n",
                    task->bdp_tjetty->v_tjetty.id.id, task->active_local_idx, task->primary_local_idx);
            }
            if (is_balance && !ok) {
                bondp_health_notify_datapath_link_fail(bdp_ctx, task->bdp_tjetty, (int)cr_local_idx, (int)target_idx);
            } else if (old_ok != ok) {
                URMA_LOG_WARN("Health link state changed, " \
                    "tjetty_id=%u lidx=%d tidx=%d user_ctx=0x%lx old=%d new=%d cr_status=%u\n",
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
                URMA_LOG_DEBUG("Health CR handled, tjetty_id=%u lidx=%d tidx=%d user_ctx=0x%lx status=%u\n",
                    task->bdp_tjetty->v_tjetty.id.id, local_idx, (int)target_idx, cr->user_ctx, cr->status);
                bondp_health_event_info_t info = {
                .local_idx = (int)cr_local_idx,
                .target_idx = (int)target_idx,
                .user_ctx = cr->user_ctx,
                .cr_status = cr->status,
                .new_active_idx = -1,
                .bdp_jetty = NULL,
                .bdp_tjetty = task->bdp_tjetty,
                };
                bondp_notify_health_event(bdp_ctx, BONDP_HEALTH_EVENT_TA_TIMEOUT, &info);
            }
            consumed = true;
        }
    }
    pthread_rwlock_unlock(&health->task_table.lock);
    if (!consumed) {
        URMA_LOG_WARN("Health CR not matched to subtask, local_idx=%d user_ctx=0x%lx\n", local_idx, cr->user_ctx);
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

    health_epoll_fd = epoll_create(UBAGG_MAX_EVENT);
    if (health_epoll_fd == -1) {
        URMA_LOG_ERR("Failed to create health epoll %s\n", ub_strerror(errno));
        return -1;
    }

    global_ctx->health_thread_ctx.health_epoll_fd = health_epoll_fd;

    atomic_store(&global_ctx->health_thread_ctx.health_thread_stop, false);
    if (pthread_create(&global_ctx->health_thread_ctx.health_thread, NULL, bondp_health_check_thread,
        global_ctx) != 0) {
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
    bondp_unregister_health_ctx_global(bond_ctx);

    if (global_ctx->health_thread_ctx.health_epoll_fd >= 0 && health->health_check_fd >= 0) {
        (void)epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
            EPOLL_CTL_DEL, health->health_check_fd, NULL);
        (void)close(health->health_check_fd);
        health->health_check_fd = -1;
    }

    bondp_unregister_health_check_seg(bond_ctx);
    bondp_hash_table_destroy(&health->task_table);
    bondp_free_health_event_list(&health->event_list);
    pthread_spin_destroy(&health->event_lock);

    URMA_LOG_INFO("Health check ctx free, dev_name=%s, eid_idx=%u.\n",
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
        URMA_LOG_ERR("Failed to init health event lock, dev=%s, eid_idx=%u\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
        return -1;
    }

    if (bondp_hash_table_create(&health->task_table, BONDP_HEALTH_TASK_TABLE_SIZE,
        bondp_health_task_comp_f, bondp_health_task_free_f, bondp_health_task_hash_f) != 0) {
        URMA_LOG_ERR("Failed to create health task table, dev=%s, eid_idx=%u\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
        goto ERR_EVENT_LOCK;
    }

    health->health_check_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (health->health_check_fd < 0) {
        URMA_LOG_ERR("Failed to create health eventfd, dev=%s, eid_idx=%u, errno=%d\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index, errno);
        goto DEL_TASK_TABLE;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = (void *)bond_ctx;
    if (epoll_ctl(global_ctx->health_thread_ctx.health_epoll_fd,
        EPOLL_CTL_ADD, health->health_check_fd, &ev) != 0) {
        URMA_LOG_ERR("Failed to add health fd to epoll, dev=%s, eid_idx=%u, fd=%d, epoll_fd=%d, errno=%d\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index,
                     health->health_check_fd, global_ctx->health_thread_ctx.health_epoll_fd, errno);
        goto DEL_FD;
    }

    if (bondp_register_health_ctx_global(bond_ctx) != 0) {
        URMA_LOG_ERR("Failed to register health ctx globally, dev=%s, eid_idx=%u\n",
                     bond_ctx->v_ctx.dev->name, bond_ctx->v_ctx.eid_index);
        goto DEL_EPOLL;
    }

    URMA_LOG_INFO("Health check ctx enabled, dev_name=%s, eid_idx=%u, fd=%d.\n",
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
