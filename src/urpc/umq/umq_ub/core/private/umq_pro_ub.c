/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB PRO
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#include "urma_api.h"
#include "perf.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_imm_data.h"
#include "umq_qbuf_pool.h"
#include "umq_ub_private.h"

int rx_buf_ctx_list_init(ub_queue_t *queue)
{
    rx_buf_ctx_list_t *rx_buf_ctx_list = &queue->jfr_ctx->rx_buf_ctx_list;
    uint32_t num = queue->rx_depth;

    rx_buf_ctx_list->addr = calloc(num, sizeof(rx_buf_ctx_t));
    urpc_list_init(&rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_init(&rx_buf_ctx_list->used_rx_buf_ctx_list);

    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)rx_buf_ctx_list->addr;
    if (rx_buf_ctx == NULL) {
        UMQ_VLOG_ERR("rx buf ctx list calloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    for (uint32_t i = 0; i < num; i++) {
        urpc_list_push_back(&rx_buf_ctx_list->idle_rx_buf_ctx_list, &rx_buf_ctx->node);
        rx_buf_ctx = rx_buf_ctx + 1;
    }
    return UMQ_SUCCESS;
}

void rx_buf_ctx_list_uninit(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    // empty the idle/used rx buf ctx list
    urpc_list_init(&rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_init(&rx_buf_ctx_list->used_rx_buf_ctx_list);
    // release the memory of rx buf ctx list
    free(rx_buf_ctx_list->addr);
    rx_buf_ctx_list->addr = NULL;
}

static rx_buf_ctx_t *queue_rx_buf_ctx_get(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    if (urpc_list_is_empty(&rx_buf_ctx_list->idle_rx_buf_ctx_list)) {
        return NULL;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    URPC_LIST_FIRST_NODE(rx_buf_ctx, node, &rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_remove(&rx_buf_ctx->node);
    urpc_list_push_back(&rx_buf_ctx_list->used_rx_buf_ctx_list, &rx_buf_ctx->node);
    return rx_buf_ctx;
}

static void queue_rx_buf_ctx_put(rx_buf_ctx_list_t *rx_buf_ctx_list, rx_buf_ctx_t *rx_buf_ctx)
{
    if (rx_buf_ctx == NULL) {
        return;
    }
    urpc_list_remove(&rx_buf_ctx->node);
    urpc_list_push_back(&rx_buf_ctx_list->idle_rx_buf_ctx_list, &rx_buf_ctx->node);
}

rx_buf_ctx_t *queue_rx_buf_ctx_flush(rx_buf_ctx_list_t *rx_buf_ctx_list)
{
    if (rx_buf_ctx_list == NULL) {
        return NULL;
    }
    rx_buf_ctx_t *rx_buf_ctx;
    URPC_LIST_FIRST_NODE(rx_buf_ctx, node, &rx_buf_ctx_list->used_rx_buf_ctx_list);
    queue_rx_buf_ctx_put(rx_buf_ctx_list, rx_buf_ctx);
    return rx_buf_ctx;
}

static inline umq_buf_t *umq_get_buf_by_user_ctx(ub_queue_t *queue, uint64_t user_ctx)
{
    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)user_ctx;
    umq_buf_t *buf = rx_buf_ctx->buffer;
    queue_rx_buf_ctx_put(&queue->jfr_ctx->rx_buf_ctx_list, rx_buf_ctx);
    return buf;
}

static uint16_t umq_ub_tx_failed_num(urma_jfs_wr_t *urma_wr, uint16_t wr_index, umq_buf_t *bad)
{
    for (uint16_t i = 0; i < wr_index; i++) {
        if (urma_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            return wr_index - i;
        }
    }
    return 0;
}

int umq_ub_fill_wr(ub_queue_t *queue, umq_buf_t *buffer, urma_jfs_wr_t *urma_wr_ptr, urma_sge_t *sges_ptr,
                          uint32_t sge_num, urma_sge_t *src_sge, urma_sge_t *dst_sge)
{
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
    uint8_t mempool_id = buf_pro->remote_sge.mempool_id;
    switch (buf_pro->opcode) {
        case UMQ_OPC_READ:
            if (buf_pro->remote_sge.length > buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR("local buffer size[%u] is smaller than remote buffer size[%u]\n",
                                   buffer->total_data_size, buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM || queue->imported_tseg_list[mempool_id] == NULL) {
                UMQ_LIMIT_VLOG_ERR("mempool_id invalid or remote tseg has not been imported, mempool_id %u\n",
                                   mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            src_sge->addr = buf_pro->remote_sge.addr;
            src_sge->len = buf_pro->remote_sge.length;
            src_sge->tseg = queue->imported_tseg_list[mempool_id];
            urma_wr_ptr->rw.src.sge = src_sge;
            urma_wr_ptr->rw.src.num_sge = 1;
            urma_wr_ptr->rw.dst.sge = sges_ptr;
            urma_wr_ptr->rw.dst.num_sge = sge_num;
            break;
        case UMQ_OPC_WRITE_IMM:
            urma_wr_ptr->rw.notify_data = buf_pro->imm_data & UMQ_UB_IMM_WITHOUT_PRIVATE_BITS;
            /* fall through */
        case UMQ_OPC_WRITE:
            if (buf_pro->remote_sge.length < buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR("local buffer size[%u] is larger than remote buffer size[%u]\n",
                                   buffer->total_data_size, buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM || queue->imported_tseg_list[mempool_id] == NULL) {
                UMQ_LIMIT_VLOG_ERR("mempool_id invalid or remote tseg has not been imported, mempool_id %u\n",
                                   mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            dst_sge->addr = buf_pro->remote_sge.addr;
            dst_sge->len = buf_pro->remote_sge.length;
            dst_sge->tseg = queue->imported_tseg_list[mempool_id];
            urma_wr_ptr->rw.dst.sge = dst_sge;
            urma_wr_ptr->rw.dst.num_sge = 1;
            urma_wr_ptr->rw.src.sge = sges_ptr;
            urma_wr_ptr->rw.src.num_sge = sge_num;
            break;
        case UMQ_OPC_SEND_IMM:
            urma_wr_ptr->send.imm_data = buf_pro->imm_data & UMQ_UB_IMM_WITHOUT_PRIVATE_BITS;
            /* fall through */
        case UMQ_OPC_SEND:
            urma_wr_ptr->send.src.sge = sges_ptr;
            urma_wr_ptr->send.src.num_sge = sge_num;
            break;
        default:
            break;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE urma_opcode_t transform_op_code(umq_opcode_t opcode)
{
    static const urma_opcode_t opcode_map[UMQ_OPC_LAST] = {
        [UMQ_OPC_WRITE]     = URMA_OPC_WRITE,
        [UMQ_OPC_WRITE_IMM] = URMA_OPC_WRITE_IMM,
        [UMQ_OPC_READ]      = URMA_OPC_READ,
        [UMQ_OPC_SEND]      = URMA_OPC_SEND,
        [UMQ_OPC_SEND_IMM]  = URMA_OPC_SEND_IMM,
    };

    uint32_t opcode_index = (uint32_t)opcode;
    if (opcode_index < UMQ_OPC_LAST) {
        urma_opcode_t code = opcode_map[opcode_index];
        if (code == 0 && (opcode_index != UMQ_OPC_WRITE)) {
            return URMA_OPC_SEND;
        }
        return code;
    }
    return URMA_OPC_SEND;
}

int umq_ub_post_tx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    int ret = UMQ_SUCCESS;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR("umq has not been binded\n");
        *bad_qbuf = qbuf;
        return -UMQ_ERR_ENODEV;
    }
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    uint32_t max_sge_num = queue->max_tx_sge;
    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    urma_jfs_wr_t *urma_wr_ptr = urma_wr;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_sge_t src_sge, dst_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint16_t wr_index = 0;
    uint16_t max_tx = 0;
    bool opcode_consume_rqe = false;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;

    *bad_qbuf = NULL;
    while (buffer) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        umq_opcode_t opcode = buf_pro->opcode;
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > max_send_size && (opcode == UMQ_OPC_SEND || opcode == UMQ_OPC_SEND_IMM)) {
            UMQ_LIMIT_VLOG_ERR("total data size[%u] exceed max send size[%u]\n", rest_size, max_send_size);
            ret = -UMQ_ERR_EINVAL;
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        sges_ptr = sges[wr_index];
        uint32_t sge_num = 0;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        umq_buf_t *tmp_buf = buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together tx buffer, rest size is negative\n");
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough tx buffer\n");
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_ENOMEM;
            goto ERROR;
        }
        ret = umq_ub_fill_wr(queue, tmp_buf, urma_wr_ptr, sges[wr_index], sge_num, &src_sge, &dst_sge);
        if (ret != UMQ_SUCCESS) {
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->opcode = transform_op_code(opcode);
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        opcode_consume_rqe = (opcode == UMQ_OPC_SEND || opcode == UMQ_OPC_SEND_IMM ||
                              opcode == UMQ_OPC_WRITE_IMM);
        umq_ub_fill_tx_imm(&queue->flow_control, urma_wr_ptr, buf_pro);
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR("wr count exceeds %d, not supported\n", UMQ_BATCH_SIZE);
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_EINVAL;
            goto ERROR;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    max_tx = opcode_consume_rqe ? umq_ub_window_dec(&queue->flow_control, queue, wr_index) : wr_index;
    if (max_tx == 0) {
        *bad_qbuf = qbuf;
        ret = -UMQ_ERR_EAGAIN;
        goto ERROR;
    } else if (max_tx < wr_index) {
        urma_wr[max_tx - 1].next = NULL;
    }

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty, urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        ret = -(int)status;
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_send_wr failed, status %d, local eid: " EID_FMT ", "
                           "local jetty_id: %u, remote eid: " EID_FMT ", remote jetty_id: %u\n", (int)status,
                           EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id,
                           EID_ARGS(tjetty->id.eid), tjetty->id.id);
        goto RECOVER_WINDOW;
    }

    if (max_tx < wr_index) {
        *bad_qbuf = (umq_buf_t *)(uintptr_t)urma_wr[max_tx].user_ctx;
        umq_ub_recover_tx_imm(queue, urma_wr, wr_index, *bad_qbuf);
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        return -UMQ_ERR_EAGAIN;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    return UMQ_SUCCESS;

RECOVER_WINDOW:
    if (opcode_consume_rqe) {
        umq_ub_window_inc(&queue->flow_control, umq_ub_tx_failed_num(urma_wr, max_tx, *bad_qbuf));
    }

ERROR:
    umq_ub_recover_tx_imm(queue, urma_wr, wr_index, *bad_qbuf);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

static ALWAYS_INLINE void process_bad_wr(ub_queue_t *queue, urma_jfr_wr_t *bad_wr, umq_buf_t *end_buf)
{
    umq_buf_t *last_fail_end = NULL;
    urma_jfr_wr_t *wr = bad_wr;
    while (wr) { // tranverse bad wr, add qbuf chain back
        rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)wr->user_ctx;
        umq_buf_t *fail = rx_buf_ctx->buffer;

        // if last fail end is not null, set its qbuf next to current qbuf
        if (last_fail_end != NULL) {
            last_fail_end->qbuf_next = fail;
        }

        // find last qbuf of current wr, and record it in last_fail_end
        while (fail->qbuf_next) {
            fail = fail->qbuf_next;
        }

        queue_rx_buf_ctx_put(&queue->jfr_ctx->rx_buf_ctx_list, rx_buf_ctx);
        last_fail_end = fail;
        wr = wr->next;
    }

    if (last_fail_end != NULL) {
        last_fail_end->qbuf_next = end_buf;
    }
}

static uint16_t umq_ub_post_rx_failed_num(urma_jfr_wr_t *recv_wr, uint16_t num, umq_buf_t *bad)
{
    for (uint16_t i = 0; i < num; i++) {
        if (recv_wr[i].user_ctx == (uint64_t)(uintptr_t)bad) {
            return num - i;
        }
    }

    return 0;
}

int umq_ub_post_rx_inner_impl(ub_queue_t *queue, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    uint32_t max_sge_num = queue->max_rx_sge;
    urma_jfr_wr_t recv_wr[UMQ_POST_POLL_BATCH] = {0};
    urma_jfr_wr_t *recv_wr_ptr = recv_wr;

    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_sge_t *sges_ptr;
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    urma_jfr_wr_t *bad_wr = NULL;
    umq_buf_t *buffer = qbuf;
    uint16_t wr_index = 0;
    *bad_qbuf = NULL;
    rx_buf_ctx_t *rx_buf_ctx = NULL;
    umq_buf_t *wr_last_buf = NULL;  // record last qbuf of current wr
    while (buffer) {
        uint32_t rest_size = buffer->total_data_size;
        uint32_t sge_num = 0;

        rx_buf_ctx = queue_rx_buf_ctx_get(&queue->jfr_ctx->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            UMQ_LIMIT_VLOG_ERR("rx buf ctx is used up\n");
            goto PUT_ALL_RX_CTX;
        }
        rx_buf_ctx->buffer = buffer;
        uint64_t user_ctx = (uint64_t)(uintptr_t)rx_buf_ctx;
        sges_ptr = sges[wr_index];
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR("sge num exceed max sge num[%u]\n", max_sge_num);
                goto PUT_CUR_RX_CTX;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR("cannot put together rx buffer, rest size is negative\n");
                goto PUT_CUR_RX_CTX;
            } else if (rest_size == buffer->data_size) {
                wr_last_buf = buffer;
            }
            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR("cannot put together enough rx buffer\n");
            goto PUT_CUR_RX_CTX;
        }

        wr_last_buf->qbuf_next = NULL;  // last buffer of current wr
        recv_wr_ptr->src.sge = sges[wr_index];
        recv_wr_ptr->src.num_sge = sge_num;
        recv_wr_ptr->user_ctx = user_ctx;
        recv_wr_ptr++;
        (recv_wr_ptr - 1)->next = recv_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR("wr count exceeds %d, not supported\n", UMQ_BATCH_SIZE);
            goto PUT_ALL_RX_CTX;
        }
    }
    (recv_wr_ptr - 1)->next = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    if (urma_post_jetty_recv_wr(queue->jetty, recv_wr, &bad_wr) != URMA_SUCCESS) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        UMQ_LIMIT_VLOG_ERR("urma_post_jetty_recv_wr failed, eid: " EID_FMT ", jetty_id: %u\n",
                           EID_ARGS(queue->jetty->jetty_id.eid), queue->jetty->jetty_id.id);
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        umq_ub_rq_posted_notifier_update(&queue->flow_control, queue,
                                         umq_ub_post_rx_failed_num(recv_wr, wr_index, *bad_qbuf));
        // if fails, add chain of qbuf back for rx
        process_bad_wr(queue, bad_wr, NULL);
        return -UMQ_ERR_EAGAIN;
    }
    umq_ub_rq_posted_notifier_update(&queue->flow_control, queue, wr_index);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp, queue->dev_ctx->feature);
    return UMQ_SUCCESS;

PUT_CUR_RX_CTX:
    buffer = rx_buf_ctx->buffer;
    // put rx buf ctx that was not added to recv wr
    queue_rx_buf_ctx_put(&queue->jfr_ctx->rx_buf_ctx_list, rx_buf_ctx);

PUT_ALL_RX_CTX:
    // put rx buf in recv wr
    if (wr_index > 0) {
        (recv_wr_ptr - 1)->next = NULL;
        *bad_qbuf = ((rx_buf_ctx_t *)(uintptr_t)recv_wr->user_ctx)->buffer;
        process_bad_wr(queue, recv_wr, buffer);
    } else {
        *bad_qbuf = qbuf;
    }
    return UMQ_FAIL;
}

int umq_ub_post_rx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    int ret = umq_ub_post_rx_inner_impl(queue, qbuf, bad_qbuf);
    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return ret;
}

static int umq_ub_on_rx_done(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t *rx_buf, umq_buf_status_t *qbuf_status)
{
    if (cr->opcode != URMA_CR_OPC_SEND_WITH_IMM) {
        return UMQ_SUCCESS;
    }

    /* only sub umq need set umq_ctx */
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
    buf_pro->umq_ctx = queue->dev_ctx->umq_ctx_jetty_table[cr->local_id];

    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (imm.bs.umq_private == 0) {
        buf_pro->imm_data = imm.value;
        return UMQ_SUCCESS;
    }

    switch (imm.bs.type) {
        case IMM_TYPE_FLOW_CONTROL:
            umq_ub_window_inc(&queue->flow_control, imm.flow_control.window);
            *qbuf_status = UMQ_BUF_FLOW_CONTROL_UPDATE;
            if (imm.flow_control.in_user_buf == UMQ_UB_IMM_IN_USER_BUF) {
                umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
                buf_pro->opcode = UMQ_OPC_SEND;
                buf_pro->imm_data = 0;
                return UMQ_SUCCESS;
            }
            break;
        case IMM_TYPE_MEM:
            if (imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT) {
                if (umq_ub_data_plan_import_mem((uint64_t)(uintptr_t)queue, rx_buf, 0) != UMQ_SUCCESS) {
                    *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                    break;
                }
                *qbuf_status = UMQ_MEMPOOL_UPDATE_SUCCESS;
            }
            break;
        default:
            break;
    }

    return UMQ_SUCCESS;
}

static int process_rx_msg(urma_cr_t *cr, umq_buf_t *buf, ub_queue_t *queue, umq_buf_status_t *qbuf_status)
{
    int ret = 0;
    *qbuf_status = (umq_buf_status_t)cr->status;
    switch (cr->opcode) {
        case URMA_CR_OPC_WRITE_WITH_IMM: {
            if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
                /* on condition of base feature, write imm is used for ubmm event notify,
                 * and it counsumes one rqe, so fill rx buffer here.
                 * on condition of pro feature, report it to user.
                */
                umq_buf_t *write_qbuf = umq_get_buf_by_user_ctx(queue, cr->user_ctx);
                umq_buf_t *bad_qbuf = NULL;
                if (umq_ub_post_rx_inner_impl(queue, write_qbuf, &bad_qbuf) != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR("ub post rx failed\n");
                    umq_buf_free(write_qbuf);
                }
                ret = UMQ_CONTINUE_FLAG;
            } else {
                umq_ub_imm_t imm = {.value = cr->imm_data};
                if (imm.bs.umq_private == 0) {
                    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
                    buf_pro->imm_data = imm.value;
                    return UMQ_SUCCESS;
                }

                if (imm.mem_import.type == IMM_TYPE_MEM && imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT_DONE) {
                    if (imm.mem_import.mempool_id >= UMQ_MAX_TSEG_NUM) {
                        UMQ_LIMIT_VLOG_ERR("mempool id exceed maxinum\n");
                        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                        return UMQ_SUCCESS;
                    }

                    if (queue->bind_ctx == NULL) {
                        UMQ_LIMIT_VLOG_ERR("queue has been unbind\n");
                        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                        return UMQ_SUCCESS;
                    }

                    queue->dev_ctx->remote_imported_info->
                        tesg_imported[queue->bind_ctx->remote_eid_id][imm.mem_import.mempool_id] = true;
                    *qbuf_status = UMQ_MEMPOOL_UPDATE_SUCCESS;
                    return UMQ_SUCCESS;
                }
                ret = UMQ_SUCCESS;
            }
            break;
        }
        case URMA_CR_OPC_SEND_WITH_IMM: {
            ret = umq_ub_on_rx_done(queue, cr, buf, qbuf_status);
            break;
        }
        case URMA_CR_OPC_SEND: {
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
            buf_pro->umq_ctx = queue->dev_ctx->umq_ctx_jetty_table[cr->local_id];
            break;
        }
        default:
            break;
    }
    return ret;
}

static int umq_report_incomplete_rx(ub_queue_t *queue, uint32_t max_rx_ctx, umq_buf_t **buf)
{
    int buf_cnt = 0;
    if (!queue->tx_flush_done || queue->rx_flush_done ||
        queue->state != QUEUE_STATE_ERR || queue->jfr_ctx->jfr->jfr_cfg.trans_mode != URMA_TM_RC) {
        return buf_cnt;
    }

    rx_buf_ctx_t *rx_buf_ctx;
    for (buf_cnt = 0; buf_cnt < (int)max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->jfr_ctx->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            break;
        }
        buf[buf_cnt] = rx_buf_ctx->buffer;
        buf[buf_cnt]->io_direction = UMQ_IO_RX;
        buf[buf_cnt]->status = UMQ_BUF_WR_FLUSH_ERR;
    }

    if (buf_cnt == 0) {
        queue->rx_flush_done = true;
    }

    return buf_cnt;
}

static inline void umq_perf_record_write_poll(umq_perf_record_type_t type, uint64_t start, uint32_t feature, int cr_cnt)
{
    if ((feature & UMQ_FEATURE_ENABLE_PERF) == 0) {
        return;
    }
    if (cr_cnt > 0) {
        umq_perf_record_write(type, start);
    } else {
        umq_perf_record_write(type + UMQ_PERF_RECORD_TRANSPORT_POLL_EMPTY_OFFSET, start);
    }
}

int umq_ub_poll_rx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    int32_t qbuf_cnt = 0;
    if (queue->state == QUEUE_STATE_ERR) {
        qbuf_cnt = umq_report_incomplete_rx(queue, max_batch, buf);
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        return qbuf_cnt;
    }

    urma_cr_t cr[max_batch];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_ctx->jfr_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, queue->dev_ctx->feature, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("UB RX reports rx_cr_cnt[%d]\n", rx_cr_cnt);
        return rx_cr_cnt;
    }

    int ret = 0;
    umq_buf_status_t qbuf_status;
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx);
        ret = process_rx_msg(&cr[i], buf[qbuf_cnt], queue, &qbuf_status);
        if (ret == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = qbuf_status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB RX reports cr[%d] status[%d], remote eid " EID_FMT ", remote jetty_id %u\n", i,
                               cr[i].status, EID_ARGS(cr[i].remote_id.eid), cr[i].remote_id.id);
        } else {
            umq_buf_t *tmp_buf = buf[qbuf_cnt];
            uint32_t total_data_size = cr[i].completion_len;
            tmp_buf->total_data_size = total_data_size;
            while (tmp_buf != NULL && total_data_size > 0) {
                tmp_buf->data_size = total_data_size > tmp_buf->data_size ? tmp_buf->data_size : total_data_size;
                total_data_size -= tmp_buf->data_size;
                tmp_buf = tmp_buf->qbuf_next;
            }
        }
        ++qbuf_cnt;
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return qbuf_cnt;
}

static void umq_ub_on_tx_done(ub_flow_control_t *fc, umq_buf_t *buf, bool failed)
{
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
    bool opcode_consume_rqe =
        buf_pro->opcode == UMQ_OPC_SEND || buf_pro->opcode == UMQ_OPC_SEND_IMM || buf_pro->opcode == UMQ_OPC_WRITE_IMM;
    if (failed && opcode_consume_rqe) {
        umq_ub_window_inc(fc, 1);
    }

    if (buf_pro->opcode != UMQ_OPC_SEND_IMM) {
        return;
    }

    umq_ub_imm_t imm = {.value = buf_pro->imm_data};
    if (imm.bs.umq_private == 0 || imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
        return;
    }

    if (failed) {
        umq_ub_rq_posted_notifier_inc(fc, imm.flow_control.window);
    }
    buf_pro->opcode = UMQ_OPC_SEND;
    buf_pro->imm_data = 0;
}

static int process_tx_msg(umq_buf_t *buf, ub_queue_t *queue)
{
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
    umq_ub_imm_t imm = {.value = buf_pro->imm_data};
    if (imm.bs.umq_private == 0) {
        return UMQ_SUCCESS;
    }

    switch (buf_pro->opcode) {
        case UMQ_OPC_WRITE_IMM:
            if (imm.bs.type == IMM_TYPE_MEM && imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT_DONE) {
                return UMQ_CONTINUE_FLAG;
            }
            break;
        case UMQ_OPC_SEND_IMM:
            if (imm.bs.type == IMM_TYPE_MEM && imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT) {
                umq_buf_free(buf);
                return UMQ_CONTINUE_FLAG;
            }
            break;
        default:
            break;
    }
    return UMQ_SUCCESS;
}

static int umq_ub_flush_sqe(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count)
{
    urma_cr_t cr[buf_count];
    int cnt = 0;
    int cr_cnt = urma_flush_jetty(queue->jetty, buf_count, cr);
    for (int i = 0; i < cr_cnt; i++) {
        if (cr[i].status == URMA_CR_WR_SUSPEND_DONE || cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE ||
            cr[i].user_ctx <= UINT16_MAX) {
            continue;
        }

        buf[cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[cnt]->io_direction = UMQ_IO_TX;
        buf[cnt]->status = (umq_buf_status_t)cr[i].status;
        cnt++;
    }

    if (cr_cnt > 0) {
        UMQ_VLOG_INFO("jetty flush %d sqe, cr_cnt %d\n", cnt, cr_cnt);
    }

    return cnt;
}

int umq_ub_poll_tx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    umq_inc_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);

    urma_cr_t cr[max_batch];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, queue->dev_ctx->feature, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
        UMQ_LIMIT_VLOG_ERR("UB TX reports tx_cr_cnt[%d]\n", tx_cr_cnt);
        return tx_cr_cnt;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR("UB TX reports cr[%d] status[%d] jetty_id[%u]\n", i, cr[i].status, cr[i].local_id);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                continue;
            }

            // recover flow control window and rx_posted
            if (cr[i].user_ctx == 0) {
                queue->flow_control.remote_get = false;
                UMQ_LIMIT_VLOG_ERR("get remote window post read failed\n");
                continue;
            } else if (cr[i].user_ctx <= UINT16_MAX) {
                umq_ub_window_inc(&queue->flow_control, 1);
                umq_ub_rq_posted_notifier_inc(&queue->flow_control, (uint16_t)cr[i].user_ctx);
                continue;
            }
        }

        if (cr[i].user_ctx == 0) {
            // window read ok
            uint16_t *remote_win =
                (uint16_t *)(uintptr_t)(umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL) + sizeof(uint16_t));
            if (*remote_win == 0) {
                queue->flow_control.remote_get = false;
                umq_ub_window_read(&queue->flow_control, queue);
            } else {
                UMQ_VLOG_DEBUG("umq ub flow control update initial window %d\n", *remote_win);
                umq_ub_window_inc(&queue->flow_control, *remote_win);
                queue->state = QUEUE_STATE_READY;
            }
            continue;
        } else if (cr[i].user_ctx <= UINT16_MAX) {
            continue;
        }
        buf[qbuf_cnt] = (umq_buf_t *)(uintptr_t)cr[i].user_ctx;
        buf[qbuf_cnt]->io_direction = UMQ_IO_TX;
        buf[qbuf_cnt]->status = (umq_buf_status_t)cr[i].status;
        umq_ub_on_tx_done(&queue->flow_control, buf[qbuf_cnt], (cr[i].status != URMA_CR_SUCCESS));
        if (process_tx_msg(buf[qbuf_cnt], queue) == UMQ_SUCCESS) {
            ++qbuf_cnt;
        }
    }

    if (queue->state == QUEUE_STATE_ERR && queue->tx_flush_done && (int)buf_count > qbuf_cnt) {
        tx_cr_cnt = umq_ub_flush_sqe(queue, &buf[qbuf_cnt], buf_count - qbuf_cnt);
        if (tx_cr_cnt > 0) {
            qbuf_cnt += tx_cr_cnt;
        }
    }

    umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->ref_cnt, 1);
    return qbuf_cnt;
}
