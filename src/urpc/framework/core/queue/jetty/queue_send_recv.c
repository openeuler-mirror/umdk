/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: use jetty to realize send recv
 */

#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "cp.h"
#include "dp.h"
#include "queue.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_epoll.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "urpc_slist.h"
#include "urpc_timer.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_id_generator.h"
#include "provider_ops_jetty.h"
#include "perf.h"
#include "urpc_dbuf_stat.h"
#include "jetty_public_func.h"
#include "queue_send_recv.h"

static queue_ops_t *send_recv_get_queue_ops(void);
int send_recv_modify_queue_lockfree(queue_t *l_queue, urpc_queue_status_t status);

int rx_user_ctx_init(eslab_t *rx_user_ctx_slab, uint32_t rx_depth)
{
    // if queue depth is 0, this queue won't use ctx
    if (rx_depth == 0) {
        return URPC_SUCCESS;
    }

    uint32_t size = sizeof(rx_user_ctx_t) + sizeof(rx_user_ctx_head_t);
    char *buf = urpc_dbuf_malloc(URPC_DBUF_TYPE_QUEUE, size * rx_depth);
    if (buf == NULL) {
        URPC_LIB_LOG_ERR("calloc slab memory failed\n");
        return URPC_FAIL;
    }

    eslab_init(rx_user_ctx_slab, buf, size, rx_depth);
    return URPC_SUCCESS;
}

void rx_user_ctx_uninit(eslab_t *rx_user_ctx_slab)
{
    if (rx_user_ctx_slab->addr == NULL) {
        return;
    }

    urpc_dbuf_free(rx_user_ctx_slab->addr);
    rx_user_ctx_slab->addr = NULL;
    eslab_uninit(rx_user_ctx_slab);
}

static ALWAYS_INLINE void send_recv_destroy_transport_resource(send_recv_queue_local_t *local)
{
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)local->local_q.queue.provider;
    if (provider->urma_dev->type != URMA_TRANSPORT_UB) {
        URPC_LIB_LOG_INFO("delete jetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u\n",
            EID_ARGS(local->jetty->jetty_id.eid), local->jetty->jetty_id.id, local->jetty->jetty_id.uasid);
    } else {
        URPC_LIB_LOG_INFO("delete jetty successful, EID: " EID_FMT ", Jetty id: %u\n",
            EID_ARGS(local->jetty->jetty_id.eid), local->jetty->jetty_id.id);
    }
    (void)urma_delete_jetty(local->jetty);

    send_recv_put_jfr_ctx(&local->local_q.rq_ctx->ctx_ref, &local->local_q);
    send_recv_put_jfc_ctx(local->local_q.cq_ctx, 0);
    send_recv_put_jfc_ctx(local->local_q.tx_cq_ctx, send_recv_tx_depth_get(&local->local_q.cfg));
    if (is_interrupt_mode(&local->local_q)) {
        send_recv_put_jfce_ctx(&local->local_q.ce_ctx->ctx_ref);
    }
}

static int send_recv_create_transport_resource(jetty_provider_t *provider, send_recv_queue_local_t *send_recv_local_q,
                                               urpc_qcfg_create_t *cfg, uint32_t qid)
{
    urpc_qcfg_get_t *local_q_cfg = &send_recv_local_q->local_q.cfg;
    /* jfr & jfr's jfc can be shared between different queue */
    jfc_ctx_t *jfr_jfc_ctx = NULL;
    jfc_ctx_t *jfs_jfc_ctx = NULL;
    jfr_ctx_t *jfr_ctx = NULL;
    jfce_ctx_t *jfce_ctx = NULL;
    urma_jfce_t *jfce = NULL;

    if (is_interrupt_mode(&send_recv_local_q->local_q)) {
        jfce_ctx = send_recv_get_jfce_ctx(provider, cfg);
        if (jfce_ctx == NULL) {
            URPC_LIB_LOG_ERR("create jfce failed\n");
            return URPC_FAIL;
        }
        jfce = jfce_ctx->jfce;
    }

    jfs_jfc_ctx = send_recv_get_jfs_jfc_ctx(provider, local_q_cfg, cfg, jfce);
    if (jfs_jfc_ctx == NULL) {
        URPC_LIB_LOG_ERR("create jfs_jfc failed\n");
        goto PUT_JFCE;
    }

    jfr_jfc_ctx = send_recv_get_jfr_jfc_ctx(provider, local_q_cfg, cfg, jfce);
    if (jfr_jfc_ctx == NULL) {
        URPC_LIB_LOG_ERR("create jfr_jfc context failed\n");
        goto PUT_JFS_JFC;
    }

    if (is_interrupt_mode(&send_recv_local_q->local_q) &&
        !send_recv_rearm_jfc(provider, jfs_jfc_ctx->jfc, jfr_jfc_ctx->jfc)) {
        goto PUT_JFS_JFC;
    }

    create_jetty_cfg_t create_jetty_cfg = {
        .jfs_jfc = jfs_jfc_ctx->jfc,
        .jfr_jfc = jfr_jfc_ctx->jfc
    };
    jfr_ctx = send_recv_get_jfr_ctx(provider, local_q_cfg, cfg, &create_jetty_cfg);
    if (jfr_ctx == NULL) {
        URPC_LIB_LOG_ERR("create jfr context failed\n");
        goto PUT_JFR_JFC;
    }

    send_recv_local_q->jetty = send_recv_create_jetty(provider, local_q_cfg, &create_jetty_cfg, jfr_ctx->jfr);
    if (send_recv_local_q->jetty == NULL) {
        URPC_LIB_LOG_ERR("create jetty failed\n");
        goto PUT_JFR;
    }

    if (provider->urma_dev->type != URMA_TRANSPORT_UB) {
        URPC_LIB_LOG_INFO("create jetty successful, EID: " EID_FMT ", Jetty id: %u, Uasid: %u, Queue id: %u\n",
            EID_ARGS(send_recv_local_q->jetty->jetty_id.eid), send_recv_local_q->jetty->jetty_id.id,
            send_recv_local_q->jetty->jetty_id.uasid, qid);
    } else {
        URPC_LIB_LOG_INFO("create jetty successful, EID: " EID_FMT ", Jetty id: %u, Queue id: %u\n",
            EID_ARGS(send_recv_local_q->jetty->jetty_id.eid), send_recv_local_q->jetty->jetty_id.id, qid);
    }
    __sync_fetch_and_add(&jfr_ctx->ctx.ready_cnt, 1);
    send_recv_local_q->local_q.cq_ctx = (cq_ctx_t *)(uintptr_t)jfr_jfc_ctx;
    send_recv_local_q->local_q.tx_cq_ctx = (cq_ctx_t *)(uintptr_t)jfs_jfc_ctx;
    send_recv_local_q->local_q.rq_ctx = (rq_ctx_t *)(uintptr_t)jfr_ctx;
    send_recv_local_q->local_q.ce_ctx = (ce_ctx_t *)(uintptr_t)jfce_ctx;
    send_recv_local_q->jfs_jfc = jfs_jfc_ctx->jfc;
    send_recv_local_q->jfr_jfc = jfr_jfc_ctx->jfc;
    send_recv_local_q->jfce = jfce;

    return URPC_SUCCESS;

PUT_JFR:
    send_recv_put_jfr_ctx(&jfr_ctx->ctx.ctx_ref, NULL);

PUT_JFR_JFC:
    send_recv_put_jfc_ctx(&jfr_jfc_ctx->ctx, 0);

PUT_JFS_JFC:
    send_recv_put_jfc_ctx(&jfs_jfc_ctx->ctx, send_recv_tx_depth_get(local_q_cfg));

PUT_JFCE:
    if (jfce_ctx != NULL) {
        send_recv_put_jfce_ctx(&jfce_ctx->ctx.ctx_ref);
    }
    return URPC_FAIL;
}

static queue_t *send_recv_create_local_queue(queue_create_option_t *option, uint16_t flag)
{
    urpc_qcfg_create_t *cfg = option->cfg;
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)get_provider(NULL);
    if (provider == NULL) {
        URPC_LIB_LOG_ERR("get provider failed\n");
        return NULL;
    }

    if (local_queue_normal_cfg_invalid(provider, cfg)) {
        return NULL;
    }

    send_recv_queue_local_t *send_recv_local_q = (send_recv_queue_local_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_QUEUE,
        1, sizeof(send_recv_queue_local_t));
    if (send_recv_local_q == NULL) {
        URPC_LIB_LOG_ERR("calloc local queue failed\n");
        return NULL;
    }

    int ret =
        send_recv_set_local_queue_normal_cfg(provider, &send_recv_local_q->local_q.cfg, cfg, QUEUE_TRANS_MODE_JETTY);
        if (ret != URPC_SUCCESS) {
        goto FREE_LOCAL;
    }

    if (send_recv_create_transport_resource(provider, send_recv_local_q, cfg, option->qid) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("create transport resource failed\n");
        goto FREE_LOCAL;
    }
    send_recv_local_q_init(send_recv_local_q, provider, send_recv_get_queue_ops(), flag, option->qid);
    queue_list_push(&send_recv_local_q->local_q);

    return &send_recv_local_q->local_q.queue;

FREE_LOCAL:
    urpc_dbuf_free(send_recv_local_q);
    return NULL;
}

static inline int validate_local_queue_flush_done(queue_local_t *local_q)
{
    if (local_q->tx_wr_cnt == 0 &&
        (local_q->rx_flush_done == URPC_TRUE || local_q->rq_ctx->rx_wr_cnt == 0 || local_q->rq_ctx->ready_cnt != 0)) {
        return URPC_SUCCESS;
    }
    URPC_LIB_LOG_INFO("the number[%u]/[%u] of tx/rx queue wr has not been drained, jfr ready cnt[%u]\n",
        local_q->tx_wr_cnt, local_q->rq_ctx->rx_wr_cnt, local_q->rq_ctx->ready_cnt);
    return -URPC_ERR_EAGAIN;
}

static int send_recv_delete_lq_validate(send_recv_queue_local_t *local_queue)
{
    queue_local_t *local_q = &local_queue->local_q;
    if (URPC_LIKELY(atomic_exchange(&local_queue->in_restore_process, 1) == 1)) {
        /* already in restore process */
        URPC_LIB_LOG_ERR("modify queue failed, processing\n");
        return -URPC_ERR_EBUSY;
    }

    int ret;
    if (local_q->queue.status == QUEUE_STATUS_ERR) {
        if (local_queue->local_q.err_timestamp + URPC_UB_FLUSH_TIMEOUT_S <= get_timestamp()) {
            URPC_LIB_LOG_ERR("flush timeout, queue will be forcibly deleted\n");
            return URPC_SUCCESS;
        }
        ret = validate_local_queue_flush_done(local_q);
        atomic_store(&local_queue->in_restore_process, 0);
        return ret;
    }

    urpc_queue_status_t queue_status = local_q->queue.status;
    switch (local_q->queue.status) {
        case QUEUE_STATUS_RESET: {
            if (validate_local_queue_flush_done(local_q) == URPC_SUCCESS) {
                atomic_store(&local_queue->in_restore_process, 0);
                // if queue status is reset, and recv flush done, it can delete
                return URPC_SUCCESS;
            }
            local_q->is_damage = URPC_TRUE;
            atomic_store(&local_queue->in_restore_process, 0);
            URPC_LIB_LOG_ERR(
                "err queue must receive flush done in order to modify reset, queue not availablen");
            return -URPC_ERR_JETTY_ERROR;
        }
        case QUEUE_STATUS_FAULT:
        case QUEUE_STATUS_READY:
            queue_status = QUEUE_STATUS_ERR;
            break;
        default: {
            atomic_store(&local_queue->in_restore_process, 0);
            URPC_LIB_LOG_ERR("this state[%u] is not supported\n", queue_status);
            return -URPC_ERR_EINVAL;
        }
    }

    ret = send_recv_modify_queue_lockfree(&local_q->queue, queue_status);
    if (ret != URPC_SUCCESS) {
        atomic_store(&local_queue->in_restore_process, 0);
        URPC_LIB_LOG_ERR("modify queue to state[%u] failed\n", queue_status);
        return ret;
    }
    ret = validate_local_queue_flush_done(local_q);
    atomic_store(&local_queue->in_restore_process, 0);
    return ret;
}

static int send_recv_delete_local_queue(queue_t *l_queue, delete_queue_callback_t delete_queue_cb)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    send_recv_queue_local_t *local = CONTAINER_OF_FIELD(local_q, send_recv_queue_local_t, local_q);
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)l_queue->provider;
    int ret;
    if (is_manager_queue(&l_queue->flag)) {
        ret = send_recv_flush_jetty(local_q, local->jetty, local->jfs_jfc, true, NULL);
        if (ret != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("flush jetty failed, ret[%d]\n", ret);
        }
    } else if (!local_q->is_damage && provider != NULL && provider->urma_dev->type == URMA_TRANSPORT_UB) {
        ret = send_recv_delete_lq_validate(local);
        if (ret != URPC_SUCCESS) {
            URPC_LIB_LOG_ERR("delete queue conditions not met, ret[%d]\n", ret);
            return ret;
        }
    }

    if (delete_queue_cb != NULL) {
        delete_queue_cb(l_queue);
    }

    if (local_q->is_binded == URPC_TRUE) {
        (void)local_q->queue.ops->unbind_queue(&local_q->queue);
    }
    queue_slab_uninit(local_q);
    queue_list_pop(&local->local_q);
    send_recv_destroy_transport_resource(local);

    urpc_dbuf_free(local);

    return URPC_SUCCESS;
}

static int send_recv_bind_queue(queue_t *l_queue, queue_t *r_queue)
{
    /* send_recv local queue can only advise send_recv remote queue currently */
    if (r_queue->ops->mode != QUEUE_TRANS_MODE_JETTY) {
        return URPC_SUCCESS;
    }

    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    send_recv_queue_remote_t *imported_queue = (send_recv_queue_remote_t *)(uintptr_t)r_queue;
    urma_status_t status = urma_bind_jetty(local_queue->jetty, imported_queue->tjetty);
    if (status != URMA_SUCCESS && status != URMA_EEXIST) {
        URPC_LIB_LOG_ERR("advise jetty failed, status:%d\n", (int)status);
        return URPC_FAIL;
    }

    local_queue->local_q.remote_jetty_id = imported_queue->tjetty->id;
    local_queue->local_q.is_binded = URPC_TRUE;
    return URPC_SUCCESS;
}

static int send_recv_unbind_queue(queue_t *l_queue)
{
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    if (urma_unbind_jetty(local_queue->jetty) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("unadvise jetty failed\n");
        return URPC_FAIL;
    }
    local_queue->local_q.is_binded = URPC_FALSE;
    return URPC_SUCCESS;
}

static ALWAYS_INLINE int send_recv_poll_tx(send_recv_queue_local_t *local_queue, queue_msg_t *msg, int cr_cnt)
{
    int msg_idx = 0;
    urma_cr_t cr[cr_cnt];
    uint64_t poll_tx_start = urpc_perf_record_begin(PERF_RECORD_POINT_TRANSPORT_POLL);
    int tx_cr_cnt = urma_poll_jfc(local_queue->jfs_jfc, cr_cnt, cr);
    urpc_perf_record_end(PERF_RECORD_POINT_TRANSPORT_POLL, poll_tx_start);
    if (URPC_UNLIKELY(tx_cr_cnt < 0)) {
        URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA TX reports tx_cr_cnt[%d], jetty[%u]\n",
            tx_cr_cnt, local_queue->jetty->jetty_id.id);
        return tx_cr_cnt;
    }

    for (int i = 0; i < tx_cr_cnt; i++) {
        if (URPC_LIKELY(cr[i].status == URMA_CR_SUCCESS && cr[i].user_ctx == 0)) {
            /* The successful CR without the user context does not meet the expectation.
             * Set queue in error status, directly. */
            URPC_LIB_LOG_ERR("[DP] UDMA(UB)/URMA TX reports success cqe with no data(fatal)\n");
            continue;
        } else if (URPC_LIKELY(cr[i].status == URMA_CR_WR_SUSPEND_DONE)) {
            // suppend done not use sqe, need to be subtracted from wr cnt.
            msg[msg_idx].ev = TX_SEND;
            msg[msg_idx++].status = trans_urma_cr_status_to_urpc(cr[i].status);
            continue;
        } else if (URPC_LIKELY(cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE)) {
            URPC_LIB_LIMIT_LOG_DEBUG("[DP] UDMA(UB)/URMA TX report tx flush err done\n");
            continue;
        }
        msg_idx += send_recv_process_tx_cr(&msg[msg_idx], &cr[i]);
        tx_wr_cnt_dec(&local_queue->local_q, (tx_ctx_t *)(uintptr_t)cr[i].user_ctx);
    }

    return msg_idx;
}

static ALWAYS_INLINE int send_recv_poll_rx(send_recv_queue_local_t *local_queue, queue_msg_t *msg, int cr_cnt)
{
    if (URPC_UNLIKELY(cr_cnt == 0 || local_queue->local_q.rq_ctx == NULL ||
        local_queue->local_q.rq_ctx->rx_wr_cnt == 0)) {
        return 0;
    }

    urma_cr_t cr[cr_cnt];
    uint64_t poll_rx_start = urpc_perf_record_begin(PERF_RECORD_POINT_TRANSPORT_POLL);
    int rx_cr_cnt = urma_poll_jfc(local_queue->jfr_jfc, cr_cnt, cr);
    urpc_perf_record_end(PERF_RECORD_POINT_TRANSPORT_POLL, poll_rx_start);
    if (URPC_UNLIKELY(rx_cr_cnt < 0)) {
        URPC_LIB_LIMIT_LOG_ERR("[DP] UDMA(UB)/URMA RX reports rx_cr_cnt[%d], jetty[%u]\n",
            rx_cr_cnt, local_queue->jetty->jetty_id.id);
        return rx_cr_cnt;
    }

    for (int i = 0; i < rx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS && cr[i].status != URMA_CR_WR_FLUSH_ERR) {
            atomic_fetch_add(&local_queue->local_q.err_msg_num, 1);
        }
        send_recv_process_rx_cr(local_queue, &msg[i], &cr[i]);
    }

    return rx_cr_cnt;
}

static int send_recv_poll(queue_t *l_queue, queue_msgs_t *msgs, urpc_poll_direction_t poll_direction)
{
    int total_msg_cnt = 0;
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    // manage queue use wait() outside
    if (URPC_UNLIKELY(!is_manager_queue(&l_queue->flag) && is_interrupt_mode(&local_queue->local_q) &&
                      send_recv_wait(l_queue, 1) < 0)) {
        goto JFC_ERR;
    }

    int msg_cnt;
    if (poll_direction == POLL_DIRECTION_TX) {
        msg_cnt = send_recv_poll_tx(local_queue, msgs->msg, msgs->msg_num);
    } else if (poll_direction == POLL_DIRECTION_RX) {
        msg_cnt = send_recv_poll_rx(local_queue, msgs->msg, msgs->msg_num);
    } else {
        /* if msg num is greater than 1, half for TX and half for RX. Otherwise, try TX first, then RX. */
        int tx_poll_max = (msgs->msg_num > 1) ? (msgs->msg_num >> 1) : 1;
        msg_cnt = send_recv_poll_tx(local_queue, msgs->msg, tx_poll_max);
        if (URPC_UNLIKELY(msg_cnt < 0)) {
            URPC_LIB_LIMIT_LOG_ERR("poll tx failed, tx_msg_cnt[%d] less than 0\n", msg_cnt);
            goto JFC_ERR;
        }
        total_msg_cnt = msg_cnt;
        msg_cnt = send_recv_poll_rx(local_queue, &msgs->msg[msg_cnt], msgs->msg_num - msg_cnt);
    }
    if (URPC_UNLIKELY(msg_cnt < 0)) {
        URPC_LIB_LIMIT_LOG_ERR("poll rx failed, rx_msg_cnt[%d] less than 0\n", msg_cnt);
        goto JFC_ERR;
    }
    total_msg_cnt += msg_cnt;

    if (total_msg_cnt < msgs->msg_num) {
        total_msg_cnt += send_recv_poll_flush_done(&local_queue->local_q, msgs->msg + total_msg_cnt);
    }

    /* concurrency protection is not required here. try to restore jetty during the next poll operation is fine. */
    if (URPC_LIKELY((atomic_load(&local_queue->local_q.err_msg_num) == 0) || (total_msg_cnt >= msgs->msg_num))) {
        return total_msg_cnt;
    }

    msgs->msg[total_msg_cnt].status = l_queue->err_code;
    msgs->msg[total_msg_cnt++].ev = QUEUE_ERR;
    atomic_fetch_sub(&local_queue->local_q.err_msg_num, 1);
    return total_msg_cnt;

JFC_ERR:
    queue_error_stats_record(l_queue, ERR_STATS_TYPE_POLL);
    msgs->msg[total_msg_cnt].status = URPC_ERR_JFC_ERROR;
    msgs->msg[total_msg_cnt++].ev = QUEUE_ERR;
    return total_msg_cnt;
}

static int send_recv_get_interrupt_fd(queue_t *l_queue)
{
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    if (local_queue->jfce == NULL) {
        URPC_LIB_LOG_ERR("get interrupt fd error, jfce is NULL\n");
        return -URPC_ERR_EINVAL;
    }

    return local_queue->jfce->fd;
}

static int send_recv_mapping_queue_fe_idx(queue_t *queue, uint32_t fe_idx)
{
    send_recv_queue_local_t *l_queue = (send_recv_queue_local_t *)(void *)queue;
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)queue->provider;

    urpc_mapping_jetty_fe_idx_in_t urpc_in = {
        .fe_idx = fe_idx,
        .jetty_id = l_queue->jetty->jetty_id.id,
    };

    urpc_mapping_jetty_fe_idx_out_t urpc_out = {0};

    urma_user_ctl_in_t urma_in = {
        .addr = (uint64_t)(uintptr_t)&urpc_in,
        .len = sizeof(urpc_mapping_jetty_fe_idx_in_t),
        .opcode = USER_CTL_MAPPING_JETTY_FE_IDX,
    };

    urma_user_ctl_out_t urma_out = {
        .addr = (uint64_t)(uintptr_t)&urpc_out,
        .len  = sizeof(urpc_mapping_jetty_fe_idx_out_t),
    };

    int ret = urma_user_ctl(provider->urma_ctx, &urma_in, &urma_out);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("urpc mapping jetty %u fe_idx %u failed, ret %d\n", l_queue->jetty->jetty_id.id, fe_idx, ret);
        return ret;
    }

    URPC_LIB_LOG_INFO("urpc mapping jetty %u fe_idx %u success\n", l_queue->jetty->jetty_id.id, fe_idx);
    return URPC_SUCCESS;
}

static ALWAYS_INLINE bool send_recv_queue_state_machine_validate(
        urpc_queue_status_t old_status, urpc_queue_status_t new_status)
{
    switch (old_status) {
        case QUEUE_STATUS_RESET:
            return (new_status == QUEUE_STATUS_READY);
        case QUEUE_STATUS_READY:
            return (new_status == QUEUE_STATUS_ERR);
        case QUEUE_STATUS_FAULT:
            return ((new_status == QUEUE_STATUS_READY) || (new_status == QUEUE_STATUS_ERR));
        case QUEUE_STATUS_ERR:
            return (new_status == QUEUE_STATUS_RESET);
        default:
            return false;
    }
}

int send_recv_modify_queue_lockfree(queue_t *l_queue, urpc_queue_status_t status)
{
    jetty_provider_t *provider = (jetty_provider_t *)(uintptr_t)l_queue->provider;
    if (provider == NULL) {
        URPC_LIB_LOG_ERR("provider is NULL\n");
        return -URPC_ERR_EINVAL;
    }
    if (provider->urma_dev->type != URMA_TRANSPORT_UB) {
        URPC_LIB_LOG_ERR("mofify queue not support urma dev type %u\n", provider->urma_dev->type);
        return -URPC_ERR_EINVAL;
    }

    urma_jetty_state_t jetty_state;
    urma_jfr_state_t jfr_state = URMA_JFR_STATE_READY;
    switch (status) {
        case QUEUE_STATUS_RESET:
            jetty_state = URMA_JETTY_STATE_RESET;
            jfr_state = URMA_JFR_STATE_RESET;
            break;
        case QUEUE_STATUS_READY:
            jetty_state = URMA_JETTY_STATE_READY;
            jfr_state = URMA_JFR_STATE_READY;
            break;
        case QUEUE_STATUS_FAULT:
            jetty_state = URMA_JETTY_STATE_SUSPENDED;
            break;
        case QUEUE_STATUS_ERR:
            jetty_state = URMA_JETTY_STATE_ERROR;
            jfr_state = URMA_JFR_STATE_ERROR;
            break;
        default:
            URPC_LIB_LOG_ERR("this state[%u] is not supported\n", status);
            return -URPC_ERR_EINVAL;
    }

    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    if (!send_recv_queue_state_machine_validate(l_queue->status, status)) {
        URPC_LIB_LOG_ERR("validate queue state machine failed\n");
        return -URPC_ERR_EINVAL;
    }

    uint32_t ready_ref_cnt = 1; // reset and fault not set jfr
    if (status == QUEUE_STATUS_ERR) {
        ready_ref_cnt = __sync_fetch_and_sub(&local_queue->local_q.rq_ctx->ready_cnt, 1);
        ready_ref_cnt--; // modify err use new cnt
    } else if (status == QUEUE_STATUS_READY) {
        ready_ref_cnt = __sync_fetch_and_add(&local_queue->local_q.rq_ctx->ready_cnt, 1);
    } else if (status == QUEUE_STATUS_RESET && (local_queue->local_q.tx_wr_cnt != 0 ||
        (local_queue->local_q.rq_ctx->ready_cnt == 0 && local_queue->local_q.rq_ctx->rx_wr_cnt != 0))) {
        URPC_LIB_LOG_ERR("err queue must receive flush done in order to modify reset\n");
        return -URPC_ERR_EINVAL;
    }

    urma_jfr_state_t old_jfr_state;
    if (ready_ref_cnt == 0 &&
        send_recv_jfr_state_validate_and_set(l_queue, jfr_state, &old_jfr_state) != URPC_SUCCESS) {
        local_queue->local_q.is_damage = URPC_TRUE;
        URPC_LIB_LOG_ERR("modify jfr to %u failed\n", jfr_state);
        return -URPC_ERR_JETTY_ERROR;
    }

    urma_jetty_attr_t attr = {
        .mask = JETTY_STATE,
        .state = jetty_state
    };
    urma_status_t urma_status = urma_modify_jetty(local_queue->jetty, &attr);
    if (urma_status != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("modify queue to state[%u] failed[%u], jetty eid: "EID_FMT", id: %u\n",
            status, urma_status, EID_ARGS(local_queue->jetty->jetty_id.eid), local_queue->jetty->jetty_id.id);
        goto RECOVER_JFR_STATE;
    }

    if (status == QUEUE_STATUS_READY) {
        local_queue->local_q.tx_flush_done = URPC_FALSE;
        local_queue->local_q.rx_flush_done = URPC_FALSE;
    } else if (status == QUEUE_STATUS_ERR) {
        local_queue->local_q.err_timestamp = get_timestamp();
    }

    l_queue->status = status;
    local_queue->local_q.is_damage = URPC_FALSE;
    return URPC_SUCCESS;

RECOVER_JFR_STATE:
    if (ready_ref_cnt == 0 &&
        send_recv_jfr_state_validate_and_set(l_queue, old_jfr_state, NULL) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("recover jfr to %u failed\n", old_jfr_state);
    }

    if (status == QUEUE_STATUS_ERR) {
        __sync_fetch_and_add(&local_queue->local_q.rq_ctx->ready_cnt, 1);
    } else if (status == QUEUE_STATUS_READY) {
        __sync_fetch_and_sub(&local_queue->local_q.rq_ctx->ready_cnt, 1);
    }
    local_queue->local_q.is_damage = URPC_TRUE;
    return -URPC_ERR_JETTY_ERROR;
}

int send_recv_modify_queue(queue_t *l_queue, urpc_queue_status_t status)
{
    send_recv_queue_local_t *local_queue = (send_recv_queue_local_t *)(uintptr_t)l_queue;
    if (URPC_LIKELY(atomic_exchange(&local_queue->in_restore_process, 1) == 1)) {
        /* already in restore process */
        URPC_LIB_LOG_ERR("modify queue to state[%u] failed, processing\n", status);
        return -URPC_ERR_EBUSY;
    }

    int ret = send_recv_modify_queue_lockfree(l_queue, status);
    atomic_store(&local_queue->in_restore_process, 0);
    return ret;
}

queue_ops_t g_urpc_send_recv_ops = { // not use static just for ut
    .mode = QUEUE_TRANS_MODE_JETTY,
    .mem_seg_token_get = send_recv_mem_seg_token_get,
    .create_local_queue = send_recv_create_local_queue,
    .delete_local_queue = send_recv_delete_local_queue,
    .query_local_queue = send_recv_query_local_queue,
    .query_trans_info = send_recv_query_trans_info,
    .create_remote_queue = send_recv_create_remote_queue,
    .delete_remote_queue = send_recv_delete_remote_queue,
    .import_remote_queue = send_recv_import_remote_queue,
    .unimport_remote_queue = send_recv_unimport_queue,
    .update_queue_status = send_recv_update_queue_status,
    .modify_queue = send_recv_modify_queue,
    .is_same_queue = send_recv_is_same_queue,
    .bind_queue = send_recv_bind_queue,
    .unbind_queue = send_recv_unbind_queue,
    .get_interrupt_fd = send_recv_get_interrupt_fd,
    .send = send_recv_send,
    .read = send_recv_read,
    .poll = send_recv_poll,
    .post = send_recv_post,
    .wait = send_recv_wait,
    .mapping_queue_fe_idx = send_recv_mapping_queue_fe_idx,
};

static queue_ops_t *send_recv_get_queue_ops(void)
{
    return &g_urpc_send_recv_ops;
}

URPC_CONSTRUCTOR(send_recv_queue_register, CONSTRUCTOR_PRIORITY_DRIVER)
{
    queue_register_ops(&g_urpc_send_recv_ops);

    queue_ctx_info_t ctx_infos[] = {
        {
            .type = QUEUE_CTX_TYPE_QSRC,
            .direction = QUEUE_CTX_RX,
            .size = sizeof(qsrc_ctx_t),
        },
    };

    queue_ctx_infos_set(ctx_infos, sizeof(ctx_infos) / sizeof(queue_ctx_info_t));
}
