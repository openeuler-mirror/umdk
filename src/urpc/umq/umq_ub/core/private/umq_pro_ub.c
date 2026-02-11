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

#define UMQ_FAKE_BUF_FC_UPDATE_SIZE 64

int rx_buf_ctx_list_init(rx_buf_ctx_list_t *rx_buf_ctx_list, uint32_t ctx_num)
{
    void *addr = calloc(ctx_num, sizeof(rx_buf_ctx_t));
    if (addr == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "rx buf ctx list addr calloc failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)addr;
    urpc_list_init(&rx_buf_ctx_list->idle_rx_buf_ctx_list);
    urpc_list_init(&rx_buf_ctx_list->used_rx_buf_ctx_list);

    for (uint32_t i = 0; i < ctx_num; i++) {
        urpc_list_push_back(&rx_buf_ctx_list->idle_rx_buf_ctx_list, &rx_buf_ctx->node);
        rx_buf_ctx = rx_buf_ctx + 1;
    }

    rx_buf_ctx_list->addr = addr;
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

umq_buf_t *umq_get_buf_by_user_ctx(ub_queue_t *queue, uint64_t user_ctx, ub_queue_jetty_index_t jetty_index)
{
    rx_buf_ctx_t *rx_buf_ctx = (rx_buf_ctx_t *)(uintptr_t)user_ctx;
    umq_buf_t *buf = rx_buf_ctx->buffer;
    queue_rx_buf_ctx_put(&queue->jfr_ctx[jetty_index]->rx_buf_ctx_list, rx_buf_ctx);
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
    uint16_t mempool_id = buf_pro->remote_sge.mempool_id;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    switch (buf_pro->opcode) {
        case UMQ_OPC_READ:
            if (buf_pro->remote_sge.length > buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, local buffer size[%u] is smaller than "
                    "remote buffer size[%u]\n", EID_ARGS(*eid), id, buffer->total_data_size,
                    buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM || queue->imported_tseg_list[mempool_id] == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id invalid or remote tseg has "
                    "not been imported, mempool_id %u\n", EID_ARGS(*eid), id, mempool_id);
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
            /* fall-through */
        case UMQ_OPC_WRITE:
            if (buf_pro->remote_sge.length < buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, local buffer size[%u] is larger than "
                    "remote buffer size[%u]\n", EID_ARGS(*eid), id, buffer->total_data_size,
                    buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM || queue->imported_tseg_list[mempool_id] == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id invalid or remote tseg has "
                    "not been imported, mempool_id %u\n", EID_ARGS(*eid), id, mempool_id);
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
            /* fall-through */
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
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq has not been binded\n", EID_ARGS(*eid), id);
        *bad_qbuf = qbuf;
        return -UMQ_ERR_ENODEV;
    }
    ub_flow_control_t *fc = &queue->flow_control;
    umq_ub_credit_check_and_request_send(fc, queue);
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_jfs_wr_t urma_wr[UMQ_POST_POLL_BATCH];
    urma_jfs_wr_t *urma_wr_ptr = urma_wr;
    urma_sge_t sges[UMQ_POST_POLL_BATCH][max_sge_num];
    urma_sge_t src_sge, dst_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
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
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, total data size[%u] exceed max send size[%u]"
                "\n", EID_ARGS(*eid), id, rest_size, max_send_size);
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
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sge num exceed max sge num[%u]\n", 
                    EID_ARGS(*eid), id, max_sge_num);
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
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together tx buffer, rest size"
                    " is negative\n", EID_ARGS(*eid), id);
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together enough tx buffer\n",
                EID_ARGS(*eid), id);
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
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, wr count exceeds %d, not supported\n",
                EID_ARGS(*eid), id, UMQ_BATCH_SIZE);
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
        umq_ub_shared_credit_req_send(queue);
        goto ERROR;
    } else if (max_tx < wr_index) {
        urma_wr[max_tx - 1].next = NULL;
    }

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], urma_wr, &bad_wr);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp, queue->dev_ctx->feature);
    if (status != URMA_SUCCESS) {
        ret = umq_status_convert(status);
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_post_jetty_send_wr failed, status: %d\n",
            EID_ARGS(*eid), id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
        goto RECOVER_WINDOW;
    }

    if (max_tx < wr_index) {
        *bad_qbuf = (umq_buf_t *)(uintptr_t)urma_wr[max_tx].user_ctx;
        umq_ub_shared_credit_req_send(queue);
        return -UMQ_ERR_EAGAIN;
    }

    return UMQ_SUCCESS;

RECOVER_WINDOW:
    if (opcode_consume_rqe) {
        umq_ub_window_inc(&queue->flow_control, umq_ub_tx_failed_num(urma_wr, max_tx, *bad_qbuf));
    }

ERROR:
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

        queue_rx_buf_ctx_put(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->rx_buf_ctx_list, rx_buf_ctx);
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
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    while (buffer) {
        uint32_t rest_size = buffer->total_data_size;
        uint32_t sge_num = 0;

        rx_buf_ctx = queue_rx_buf_ctx_get(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->rx_buf_ctx_list);
        if (rx_buf_ctx == NULL) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, rx buf ctx is used up\n", EID_ARGS(*eid), id);
            goto PUT_ALL_RX_CTX;
        }
        rx_buf_ctx->buffer = buffer;
        uint64_t user_ctx = (uint64_t)(uintptr_t)rx_buf_ctx;
        sges_ptr = sges[wr_index];
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sge num exceed max sge num[%u]\n",
                    EID_ARGS(*eid), id, max_sge_num);
                goto PUT_CUR_RX_CTX;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together rx buffer, rest size"
                " is negative\n", EID_ARGS(*eid), id);
                goto PUT_CUR_RX_CTX;
            } else if (rest_size == buffer->data_size) {
                wr_last_buf = buffer;
            }
            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, cannot put together enough rx buffer\n",
                EID_ARGS(*eid), id);
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
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, wr count exceeds %d, not supported\n",
                EID_ARGS(*eid), id, UMQ_BATCH_SIZE);
            goto PUT_ALL_RX_CTX;
        }
    }
    (recv_wr_ptr - 1)->next = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_recv_wr(queue->jetty[UB_QUEUE_JETTY_IO], recv_wr, &bad_wr);
    if (status != URMA_SUCCESS) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_recv_wr failed, "
            "status: %d\n", EID_ARGS(*eid), id, (int)status);
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
            bad_wr = recv_wr;
        }
        umq_ub_shared_credit_recharge(queue, wr_index - umq_ub_post_rx_failed_num(recv_wr, wr_index, *bad_qbuf));
        // if fails, add chain of qbuf back for rx
        process_bad_wr(queue, bad_wr, NULL);
        return -UMQ_ERR_EAGAIN;
    }
    umq_ub_shared_credit_recharge(queue, wr_index);
    umq_perf_record_write_with_feature(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp, queue->dev_ctx->feature);
    return UMQ_SUCCESS;

PUT_CUR_RX_CTX:
    buffer = rx_buf_ctx->buffer;
    // put rx buf ctx that was not added to recv wr
    queue_rx_buf_ctx_put(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->rx_buf_ctx_list, rx_buf_ctx);

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
    return umq_ub_post_rx_inner_impl(queue, qbuf, bad_qbuf);
}

static int umq_ub_on_rx_done(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t *rx_buf, umq_buf_status_t *qbuf_status)
{
    if (cr->opcode != URMA_CR_OPC_SEND_WITH_IMM) {
        return UMQ_SUCCESS;
    }

    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
    ub_queue_t *real_queue = (ub_queue_t *)(uintptr_t)queue->dev_ctx->umq_ctx_jetty_table[cr->local_id];
    if (real_queue != NULL) {
        umq_inc_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
        buf_pro->umq_ctx = real_queue->umq_ctx;
    } else {
        buf_pro->umq_ctx = 0;
    }
    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (imm.bs.umq_private == 0) {
        buf_pro->imm_data = imm.value;
        goto OUT;
    }

    switch (imm.bs.type) {
        case IMM_TYPE_MEM:
            if (imm.mem_import.sub_type == IMM_TYPE_MEM_IMPORT) {
                if (umq_ub_data_plan_import_mem((uint64_t)(uintptr_t)real_queue, rx_buf, 0, false) != UMQ_SUCCESS) {
                    *qbuf_status = UMQ_IMPORT_TSEG_FAILED;
                    break;
                }
                *qbuf_status = UMQ_IMPORT_TSEG_SUCCESS;
            }
            break;
        default:
            break;
    }

OUT:
    if (real_queue != NULL) {
        umq_dec_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
    }
    return UMQ_SUCCESS;
}

static int process_rx_msg(urma_cr_t *cr, umq_buf_t *buf, ub_queue_t *queue, umq_buf_status_t *qbuf_status)
{
    int ret = UMQ_SUCCESS;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    *qbuf_status = (umq_buf_status_t)cr->status;
    switch (cr->opcode) {
        case URMA_CR_OPC_WRITE_WITH_IMM: {
            if ((queue->dev_ctx->feature & UMQ_FEATURE_API_PRO) == 0) {
                /* on condition of base feature, write imm is used for ubmm event notify,
                 * and it counsumes one rqe, so fill rx buffer here.
                 * on condition of pro feature, report it to user.
                */
                umq_buf_t *write_qbuf = umq_get_buf_by_user_ctx(queue, cr->user_ctx, UB_QUEUE_JETTY_IO);
                umq_buf_t *bad_qbuf = NULL;
                ret = umq_ub_post_rx_inner_impl(queue, write_qbuf, &bad_qbuf);
                if (ret != UMQ_SUCCESS) {
                    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, ub post rx failed, status: %d\n",
                        EID_ARGS(*eid), id, ret);
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
                        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool id exceed maxinum\n",
                            EID_ARGS(*eid), id);
                        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                        return UMQ_SUCCESS;
                    }

                    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
                    ub_queue_t *real_queue = (ub_queue_t *)(uintptr_t)queue->dev_ctx->umq_ctx_jetty_table[cr->local_id];
                    if (real_queue == NULL) {
                        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sub queue has been destroy\n",
                            EID_ARGS(*eid), id);
                        buf_pro->umq_ctx = 0;
                        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                        return UMQ_SUCCESS;
                    }

                    buf_pro->umq_ctx = real_queue->umq_ctx;
                    umq_inc_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
                    if (real_queue->bind_ctx == NULL) {
                        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue has been unbind\n",
                            EID_ARGS(*eid), real_queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
                        umq_dec_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
                        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
                        return UMQ_SUCCESS;
                    }

                    real_queue->dev_ctx->remote_imported_info->
                        tesg_imported[real_queue->bind_ctx->remote_eid_id][imm.mem_import.mempool_id] = true;
                    *qbuf_status = UMQ_MEMPOOL_UPDATE_SUCCESS;
                    umq_dec_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
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
            ub_queue_t *real_queue = (ub_queue_t *)(uintptr_t)queue->dev_ctx->umq_ctx_jetty_table[cr->local_id];
            if (real_queue != NULL) {
                buf_pro->umq_ctx = real_queue->umq_ctx;
            } else {
                buf_pro->umq_ctx = 0;
            }
            break;
        }
        default:
            break;
    }
    return ret;
}

static uint32_t umq_report_incomplete_rx(ub_queue_t *queue, uint32_t max_rx_ctx, umq_buf_t **buf)
{
    uint32_t buf_cnt = 0;
    if (!queue->tx_flush_done || queue->rx_flush_done || queue->state != QUEUE_STATE_ERR) {
        return buf_cnt;
    }

    rx_buf_ctx_t *rx_buf_ctx;
    for (buf_cnt = 0; buf_cnt < max_rx_ctx; buf_cnt++) {
        rx_buf_ctx = queue_rx_buf_ctx_flush(&queue->jfr_ctx[UB_QUEUE_JETTY_IO]->rx_buf_ctx_list);
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

    umq_ub_idle_credit_flush(queue, buf_cnt);
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

static uint32_t umq_ub_process_fc_msg(ub_queue_t *queue, umq_ub_imm_t imm, umq_buf_t **buf)
{
    if (imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
        return 0;
    }
    umq_buf_t *fc_buf = NULL;
    uint32_t ret = 0;
    switch (imm.flow_control.sub_type) {
        case IMM_TYPE_FC_CREDIT_REQ:
            umq_ub_shared_credit_req_handle(queue, &imm);
            break;
        case IMM_TYPE_FC_CREDIT_REP:
            fc_buf = umq_buf_alloc(UMQ_FAKE_BUF_FC_UPDATE_SIZE, 1, 0, NULL);
            umq_ub_shared_credit_resp_handle(queue, &imm);
            fc_buf->io_direction = UMQ_IO_RX;
            fc_buf->status = UMQ_FAKE_BUF_FC_UPDATE;
            buf[0] = fc_buf;
            ret = 1;
            break;
        default:
            break;
    }
    return ret;
}

static void umq_ub_fill_rx_buff_post_process(ub_queue_t *queue, umq_ub_imm_t imm)
{
    if (imm.bs.type != IMM_TYPE_FLOW_CONTROL) {
        return;
    }
    ub_flow_control_t *fc = &queue->flow_control;
    switch (imm.flow_control.sub_type) {
        case IMM_TYPE_FC_CREDIT_REP:
             umq_ub_permission_release(fc);
            break;
        default:
            break;
    }
    return;
}

uint32_t umq_ub_poll_fc_rx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count)
{
    urma_cr_t cr[UMQ_UB_FLOW_CONTORL_JETTY_DEPTH];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int rx_cr_cnt =
        urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc, UMQ_UB_FLOW_CONTORL_JETTY_DEPTH, cr);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, queue->dev_ctx->feature, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, rx_cr_cnt);
        return 0;
    }

    if (rx_cr_cnt > 0) {
        queue->interrupt_ctx.rx_fc_interrupt = false;
        umq_ub_fc_packet_stats(&queue->flow_control, (uint32_t)rx_cr_cnt, UB_PACKET_STATS_TYPE_RECV);
    }
    uint32_t qbuf_cnt = 0;
    for (int i = 0; i < rx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            (void)umq_ub_fill_fc_rx_buf(queue);
            umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_RECV_ERROR);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ""
                ", remote jetty_id: %u, urma_poll_jfc reports rx cr[%d] status: %d\n", EID_ARGS(*eid), id,
                EID_ARGS(cr[i].remote_id.eid), cr[i].remote_id.id, i, (int)cr[i].status);
            continue;
        }
        umq_ub_imm_t imm = {.value = cr[i].imm_data};
        qbuf_cnt += umq_ub_process_fc_msg(queue, imm, &buf[qbuf_cnt]);
        (void)umq_ub_fill_fc_rx_buf(queue);
        (void)umq_ub_fill_rx_buff_post_process(queue, imm);
    }
    return qbuf_cnt;
}

int umq_ub_fill_fc_rx_buf(ub_queue_t *queue)
{
    urma_jfr_wr_t recv_wr = {0};
    urma_jfr_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_status_t status = urma_post_jetty_recv_wr(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL], &recv_wr, &bad_wr);
    if (status != URMA_SUCCESS) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_recv_wr failed, "
            "status: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, (int)status);
        return umq_status_convert(status);
    }
    return UMQ_SUCCESS;
}

int umq_ub_poll_rx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    int ret;
    uint32_t qbuf_cnt = 0;
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (queue->flow_control.enabled && (queue->mode == UMQ_MODE_POLLING || queue->interrupt_ctx.rx_fc_interrupt)) {
        qbuf_cnt += umq_ub_poll_fc_rx(queue, buf, max_batch);
    }

    if (queue->wait_ack_import.wait_ack_idx > 0) {
        umq_ub_ack_import_tseg(queue);
    }

    max_batch -= qbuf_cnt;
    urma_cr_t cr[max_batch];
    if (max_batch == 0 || (queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0) {
        goto OUT;
    }

    if (queue->state == QUEUE_STATE_ERR) {
        // only main queue in error state can report incomplete rx
        if (!(queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ)) {
            qbuf_cnt += umq_report_incomplete_rx(queue, max_batch, &buf[qbuf_cnt]);
        }
        goto OUT;
    }

    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int rx_cr_cnt = urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, queue->dev_ctx->feature, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, rx_cr_cnt);
        goto OUT;
    }

    umq_buf_status_t qbuf_status;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    if (queue->flow_control.enabled && rx_cr_cnt != 0) {
        (void)credit->ops.allocated_credit_dec(credit, rx_cr_cnt);
    }
    for (int i = 0; i < rx_cr_cnt; i++) {
        buf[qbuf_cnt] = umq_get_buf_by_user_ctx(queue, cr[i].user_ctx, UB_QUEUE_JETTY_IO);
        umq_ub_rx_consumed_inc(
            queue->dev_ctx->io_lock_free, &queue->dev_ctx->rx_consumed_jetty_table[cr[i].local_id], 1);
        ret = process_rx_msg(&cr[i], buf[qbuf_cnt], queue, &qbuf_status);
        if (ret == UMQ_CONTINUE_FLAG) {
            continue;
        }
        buf[qbuf_cnt]->io_direction = UMQ_IO_RX;
        buf[qbuf_cnt]->status = qbuf_status;
        if (cr[i].status != URMA_CR_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "local eid: " EID_FMT ", local jetty_id: %u, remote eid " EID_FMT ","
                " remote jetty_id %u, urma_poll_jfc reports rx cr[%d] status: %d\n", EID_ARGS(*eid), id,
                EID_ARGS(cr[i].remote_id.eid), cr[i].remote_id.id, i, (int)cr[i].status);
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

OUT:
    return (int)qbuf_cnt;
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
    int cr_cnt = urma_flush_jetty(queue->jetty[UB_QUEUE_JETTY_IO], buf_count, cr);
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
        UMQ_VLOG_INFO(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_flush_jetty flush %d sqe, cr_cnt %d\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid), queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id, cnt,
            cr_cnt);
    }

    return cnt;
}

static void umq_ub_fc_process_tx(ub_queue_t *queue, umq_ub_fc_user_ctx_t *obj)
{
    uint32_t type = obj->bs.type;
    umq_ub_fc_info_t *fc_info = NULL;
    uint16_t remote_win;
    switch (type) {
        case IMM_TYPE_FC_CREDIT_INIT:
            // window read ok
            fc_info = (umq_ub_fc_info_t *)(uintptr_t)(umq_ub_notify_buf_addr_get(queue, OFFSET_FLOW_CONTROL));
            remote_win = fc_info->fc.remote_window;
            if (fc_info->fc.remote_rx_depth != UMQ_UB_FLOW_CONTORL_JETTY_DEPTH) {
                queue->flow_control.remote_get = false;
                umq_ub_window_read(&queue->flow_control, queue);
            } else {
                UMQ_VLOG_DEBUG(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq ub flow control update initial window %d"
                    "\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid), 
                    queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, remote_win);
                umq_ub_window_inc(&queue->flow_control, remote_win);
                queue->state = QUEUE_STATE_READY;
            }
            break;
        default:
            break;
    }
}

static void umq_ub_fc_process_tx_error(ub_queue_t *queue, umq_ub_fc_user_ctx_t *obj)
{
    uint32_t type = obj->bs.type;
    ub_flow_control_t *fc = &queue->flow_control;
    uint16_t notify;
    ub_credit_pool_t *credit = &queue->jfr_ctx[UB_QUEUE_JETTY_IO]->credit;
    switch (type) {
        case IMM_TYPE_FC_CREDIT_INIT:
            fc->remote_get = false;
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, get remote window post read failed\n",
                EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
                queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
            break;
        case IMM_TYPE_FC_CREDIT_REP:
            notify = obj->bs.notify;
            (void)credit->ops.available_credit_return(credit, notify);
            (void)fc->ops.local_rx_allocated_dec(fc, notify);
            break;
        case IMM_TYPE_FC_CREDIT_REQ:
            umq_ub_permission_release(fc);
            break;
        default:
            break;
    }
}

int umq_ub_poll_fc_tx(ub_queue_t *queue)
{
    urma_cr_t cr[UMQ_UB_FLOW_CONTORL_JETTY_DEPTH];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL], UMQ_UB_FLOW_CONTORL_JETTY_DEPTH, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, queue->dev_ctx->feature, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return UMQ_FAIL;
    }

    if (tx_cr_cnt > 0) {
        queue->interrupt_ctx.tx_fc_interrupt = false;
    }

    uint32_t success_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        umq_ub_fc_user_ctx_t  obj = {.value = cr[i].user_ctx};
        if (cr[i].status != URMA_CR_SUCCESS) {
            umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND_ERROR);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE || cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                UMQ_LIMIT_VLOG_INFO(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx "
                    "cr[%d] status[%d] local_id[%u]\n", EID_ARGS(*eid), id, i, (int)cr[i].status, cr[i].local_id);
                continue;
            }
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status[%d] local_id[%u]\n", EID_ARGS(*eid), id, i, (int)cr[i].status, cr[i].local_id);
            umq_ub_fc_process_tx_error(queue, &obj);
            continue;
        }
        success_cnt++;
        umq_ub_fc_process_tx(queue, &obj);
    }

    if (success_cnt > 0) {
        umq_ub_fc_packet_stats(&queue->flow_control, success_cnt, UB_PACKET_STATS_TYPE_SEND_SUCCESS);
    }

    return UMQ_SUCCESS;
}

int umq_ub_poll_tx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    uint32_t max_batch = buf_count > UMQ_POST_POLL_BATCH ? UMQ_POST_POLL_BATCH : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;

    if (queue->flow_control.enabled && (queue->mode == UMQ_MODE_POLLING || queue->interrupt_ctx.tx_fc_interrupt)) {
        (void)umq_ub_poll_fc_tx(queue);
    }

    urma_cr_t cr[max_batch];
    uint64_t start_timestmap = umq_perf_get_start_timestamp_with_feature(queue->dev_ctx->feature);
    int tx_cr_cnt = urma_poll_jfc(queue->jfs_jfc[UB_QUEUE_JETTY_IO], max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, queue->dev_ctx->feature, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return tx_cr_cnt;
    }

    int32_t qbuf_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE) {
                UMQ_LIMIT_VLOG_INFO(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx "
                    "cr[%d] status: %d local_id: %u\n", EID_ARGS(*eid), id, i, cr[i].status, cr[i].local_id);
                if (queue->state == QUEUE_STATE_ERR) {
                    queue->tx_flush_done = true;
                }
                continue;
            }
            if (cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                UMQ_LIMIT_VLOG_INFO(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports "
                "tx cr[%d] status: %d local_id: %u\n", EID_ARGS(*eid), id, i, cr[i].status, cr[i].local_id);
                continue;
            }
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status: %d local_id: %u\n", EID_ARGS(*eid), id, i, cr[i].status, cr[i].local_id);
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

    return qbuf_cnt;
}
