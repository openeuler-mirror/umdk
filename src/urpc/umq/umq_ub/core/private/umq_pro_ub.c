/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UMQ UB PRO
 * Create: 2025-12-22
 * Note:
 * History: 2025-12-22
 */

#include <sys/eventfd.h>

#include "urma_api.h"
#include "umq_symbol_private.h"
#include "perf.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "umq_ub_flow_control.h"
#include "umq_ub_flow_control_sge.h"
#include "umq_ub_imm_data.h"
#include "umq_qbuf_pool.h"
#include "umq_ub_private.h"

#define UMQ_UB_FC_UNDATE_FAKE_BUF_SIZE 128 // in combind mode, buffer size more than umq_buf_t needs to be allocated
#define UMQ_UB_FC_POLL_COUNT_MAX 1 // the upper limit of the number of flow control buffers for poll

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
    if (rx_buf_ctx_list->addr != NULL) {
        free(rx_buf_ctx_list->addr);
        rx_buf_ctx_list->addr = NULL;
    }
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
    urma_target_seg_t *tseg = NULL;

    umq_ub_imm_t imm_data = {
        .io_imm.type = IMM_TYPE_USER_WITHOUT_IMM,
        .io_imm.umq_id = queue->remote_umq_id,
        .io_imm.user_data = 0
    };
    switch (buf_pro->opcode) {
        case UMQ_OPC_READ:
            if (!umq_ub_enable_import_remote_mem(queue->dev_ctx->feature)) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, "
                    "UMQ_FEATURE_ENABLE_REMOTE_MEM_ACCESS is not enabled, read is not supported\n",
                    EID_ARGS(*eid), id);
                return -UMQ_ERR_EPERM;
            }
            if (buf_pro->remote_sge.length > buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, local buffer size[%u] is smaller than "
                    "remote buffer size[%u]\n", EID_ARGS(*eid), id, buffer->total_data_size,
                    buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id %u invalid\n",
                    EID_ARGS(*eid), id, mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            tseg = umq_ub_tseg_lookup(queue->bind_ctx->tseg_table, mempool_id);
            if (tseg == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id %u has not been imported\n",
                    EID_ARGS(*eid), id, mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            src_sge->addr = buf_pro->remote_sge.addr;
            src_sge->len = buf_pro->remote_sge.length;
            src_sge->tseg = tseg;
            urma_wr_ptr->rw.src.sge = src_sge;
            urma_wr_ptr->rw.src.num_sge = 1;
            urma_wr_ptr->rw.dst.sge = sges_ptr;
            urma_wr_ptr->rw.dst.num_sge = sge_num;
            break;
        case UMQ_OPC_WRITE_IMM:
            buf_pro->imm.rsvd0 = 0;
            urma_wr_ptr->rw.notify_data = buf_pro->imm_data;
            /* fall-through */
        case UMQ_OPC_WRITE:
            if (!umq_ub_enable_import_remote_mem(queue->dev_ctx->feature)) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, "
                    "UMQ_FEATURE_ENABLE_REMOTE_MEM_ACCESS is not enabled, write or write imm is not supported\n",
                    EID_ARGS(*eid), id);
                return -UMQ_ERR_EPERM;
            }
            if (buf_pro->remote_sge.length < buffer->total_data_size) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, local buffer size[%u] is larger than "
                    "remote buffer size[%u]\n", EID_ARGS(*eid), id, buffer->total_data_size,
                    buf_pro->remote_sge.length);
                return -UMQ_ERR_EINVAL;
            }
            if (mempool_id >= UMQ_MAX_TSEG_NUM) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id %u invalid\n",
                    EID_ARGS(*eid), id, mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            tseg = umq_ub_tseg_lookup(queue->bind_ctx->tseg_table, mempool_id);
            if (tseg == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool_id %u has not been imported\n",
                    EID_ARGS(*eid), id, mempool_id);
                return -UMQ_ERR_ETSEG_NON_IMPORTED;
            }
            dst_sge->addr = buf_pro->remote_sge.addr;
            dst_sge->len = buf_pro->remote_sge.length;
            dst_sge->tseg = tseg;
            urma_wr_ptr->rw.dst.sge = dst_sge;
            urma_wr_ptr->rw.dst.num_sge = 1;
            urma_wr_ptr->rw.src.sge = sges_ptr;
            urma_wr_ptr->rw.src.num_sge = sge_num;
            break;
        case UMQ_OPC_SEND_IMM:
            buf_pro->imm.rsvd0 = 0;
            imm_data.io_imm.type = IMM_TYPE_USER;
            imm_data.io_imm.user_data = buf_pro->imm.user_data;
            /* fall-through */
        case UMQ_OPC_SEND:
            urma_wr_ptr->send.src.sge = sges_ptr;
            urma_wr_ptr->send.src.num_sge = sge_num;
            urma_wr_ptr->send.imm_data = imm_data.value;
            urma_wr_ptr->opcode = URMA_OPC_SEND_IMM;
            buf_pro->umq_ctx = queue->umq_ctx;
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

static ALWAYS_INLINE void umq_ub_tx_eagain_cnt(int ret, bool user_send_imm, ub_queue_t *queue, uint16_t eagain_wr_cnt,
                                               umq_buf_t *qbuf)
{
    if (ret != -UMQ_ERR_EAGAIN) {
        return;
    }

    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_EAGAIN, eagain_wr_cnt, queue->dev_ctx->io_lock_free);
    if (user_send_imm) {
        umq_io_perf_process(UMQ_PERF_RECORD_TRANSPORT_POST_SEND_EAGAIN, qbuf);
    }
}

int umq_ub_post_tx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    int ret = UMQ_SUCCESS;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    uint32_t wr_cnt_limit = UMQ_BATCH_SIZE;
    if (queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), umq has not been binded\n", queue->umq_id);
        *bad_qbuf = qbuf;
        return -UMQ_ERR_ENODEV;
    }
    ub_flow_control_t *fc = &queue->flow_control;
    ret = umq_ub_credit_check_and_request_send(fc, queue);
    if (ret != UMQ_SUCCESS) {
        *bad_qbuf = qbuf;
        return ret;
    }
    uint32_t max_sge_num = queue->max_tx_sge;
    urma_jfs_wr_t urma_wr[UMQ_BATCH_SIZE];
    urma_jfs_wr_t *urma_wr_ptr = urma_wr;
    urma_sge_t sges[UMQ_BATCH_SIZE][max_sge_num];
    urma_sge_t src_sge, dst_sge;
    urma_target_jetty_t *tjetty = queue->bind_ctx->tjetty[UB_QUEUE_JETTY_IO];
    urma_target_seg_t **tseg_list = queue->dev_ctx->tseg_list;
    urma_sge_t *sges_ptr;
    umq_buf_t *buffer = qbuf;
    uint16_t wr_index = 0;
    uint16_t max_tx = 0;
    bool opcode_consume_rqe = false;
    bool user_send_imm = false;
    uint32_t max_send_size =
        (queue->remote_rx_buf_size > queue->tx_buf_size) ? queue->tx_buf_size : queue->remote_rx_buf_size;
    uint32_t failed_num = 0;

    *bad_qbuf = NULL;
    umq_buf_t *real_buf = NULL;
    while (buffer) {
        umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buffer->qbuf_ext;
        umq_opcode_t opcode = buf_pro->opcode;
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size > max_send_size && (opcode == UMQ_OPC_SEND || opcode == UMQ_OPC_SEND_IMM)) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), total data size[%u] exceed max send size[%u]\n",
                queue->umq_id, rest_size, max_send_size);
            ret = -UMQ_ERR_EINVAL;
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        if (!user_send_imm) {
            user_send_imm = (opcode == UMQ_OPC_SEND_IMM);
        }
        sges_ptr = sges[wr_index];
        uint32_t sge_num = 0;
        uint64_t user_ctx = (uint64_t)(uintptr_t)buffer;
        umq_buf_t *tmp_buf = buffer;
        while (buffer && rest_size > 0) { // try to add up to total_size
            if (sge_num++ >= max_sge_num) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), sge num exceed max sge num[%u]\n",
                    queue->umq_id, max_sge_num);
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }
            sges_ptr->addr = (uint64_t)(uintptr_t)buffer->buf_data;
            sges_ptr->len = buffer->data_size;
            sges_ptr->user_tseg = NULL;
            if (buffer->mempool_without_data == 1) {
                real_buf = umq_data_to_head(buffer->buf_data);
                if (real_buf == NULL) {
                    UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), get real buf failed\n", queue->umq_id);
                    ret = -UMQ_ERR_EINVAL;
                    goto ERROR;
                }
            } else {
                real_buf = buffer;
            }

            if (real_buf->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), ub only supports using pooled memory\n", queue->umq_id);
                ret = -UMQ_ERR_EFAULT;
                goto ERROR;
            }

            sges_ptr->tseg = tseg_list[real_buf->mempool_id];
            if (sges_ptr->tseg == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), mempool %u tseg not exist\n",
                    queue->umq_id, real_buf->mempool_id);
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }
            sges_ptr++;

            if (rest_size < buffer->data_size) { // if cannot add up to total_size, return fail
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), cannot put together tx buffer, rest size"
                    " is negative\n", queue->umq_id);
                *bad_qbuf = qbuf;
                ret = -UMQ_ERR_EINVAL;
                goto ERROR;
            }

            rest_size -= buffer->data_size;
            buffer = QBUF_LIST_NEXT(buffer);
        }

        if (rest_size != 0) { // if cannot add up to total_size, return fail
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), cannot put together enough tx buffer\n", queue->umq_id);
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_ENOMEM;
            goto ERROR;
        }
        urma_wr_ptr->opcode = transform_op_code(opcode);
        ret = umq_ub_fill_wr(queue, tmp_buf, urma_wr_ptr, sges[wr_index], sge_num, &src_sge, &dst_sge);
        if (ret != UMQ_SUCCESS) {
            *bad_qbuf = qbuf;
            goto ERROR;
        }
        urma_wr_ptr->user_ctx = user_ctx;
        urma_wr_ptr->flag.value = buf_pro->flag.value;
        urma_wr_ptr->tjetty = tjetty;
        opcode_consume_rqe = (opcode == UMQ_OPC_SEND || opcode == UMQ_OPC_SEND_IMM ||
                              opcode == UMQ_OPC_WRITE_IMM);
        urma_wr_ptr++;
        (urma_wr_ptr - 1)->next = urma_wr_ptr;

        wr_index++;
        if (wr_index == UMQ_BATCH_SIZE && buffer != NULL) {
            // wr count exceed UMQ_BATCH_SIZE
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u), wr count exceeds %d, not supported\n",
                queue->umq_id, UMQ_BATCH_SIZE);
            *bad_qbuf = qbuf;
            ret = -UMQ_ERR_EINVAL;
            goto ERROR;
        }
    }
    (urma_wr_ptr - 1)->next = NULL;
    max_tx = opcode_consume_rqe ? umq_ub_window_dec(&queue->flow_control, queue, wr_index) : wr_index;
    if (max_tx == 0) {
        *bad_qbuf = qbuf;
        ret = umq_ub_shared_credit_req_send(queue);
        ret = (ret != UMQ_SUCCESS) ? ret : -UMQ_ERR_EAGAIN;
        umq_ub_tx_eagain_cnt(ret, user_send_imm, queue, wr_index, qbuf);
        goto ERROR;
    } else if (max_tx < wr_index) {
        urma_wr[max_tx - 1].next = NULL;
    }

    failed_num = max_tx;
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        ret = umq_ub_get_jetty_node(queue, 0);
        if (ret != UMQ_SUCCESS) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "UMQ(ID:%u) get jetty node failed\n", queue->umq_id);
            *bad_qbuf = qbuf;
            goto RECOVER_WINDOW;
        }
        wr_cnt_limit = queue->jetty_node->borrow_limit - queue->jetty_node->borrow_count;
    }

    wr_cnt_limit = wr_cnt_limit < max_tx ? wr_cnt_limit : max_tx;
    if (wr_cnt_limit == 0) {
        *bad_qbuf = qbuf;
        ret = -UMQ_ERR_ENOBUFS;
        goto RECOVER_JETTY_NODE;
    } else if (wr_cnt_limit < max_tx) {
        urma_wr[wr_cnt_limit - 1].next = NULL;
    }
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        (void)__atomic_add_fetch(&queue->jetty_node->tx_outstanding, wr_cnt_limit, __ATOMIC_ACQ_REL);
        if (queue->jetty_node->is_jetty_err) {
            ret = -UMQ_ERR_EINVAL;
            goto RECOVER_JETTY_NODE;
        }
    }

    urma_jfs_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    if (user_send_imm) {
        umq_io_perf_process(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, qbuf);
    }
    urma_status_t status =
        umq_symbol_urma()->urma_post_jetty_send_wr(queue->jetty[UB_QUEUE_JETTY_IO], urma_wr, &bad_wr);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_SEND, start_timestamp);
    if (status != URMA_SUCCESS) {
        ret = umq_status_convert(status);
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
        }
        failed_num = umq_ub_tx_failed_num(urma_wr, wr_cnt_limit, *bad_qbuf);
        queue->jetty_node->borrow_count += wr_cnt_limit - failed_num;
        urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
        uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
            "remote jetty_id: %u, urma_post_jetty_send_wr failed, status: %d\n",
            EID_ARGS(*eid), id, EID_ARGS(tjetty->id.eid), tjetty->id.id, (int)status);
        goto RECOVER_JETTY_NODE;
    }

    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND, wr_cnt_limit, queue->dev_ctx->io_lock_free);
    // Logic UMQ: update borrow_count and store umq_ref after successful post
    if (is_umq_ub_logic_queue(queue->create_flag)) {
        queue->jetty_node->borrow_count += wr_cnt_limit;
        __atomic_store_n(&queue->jetty_node->umq_ref, (uint64_t)(uintptr_t)queue, __ATOMIC_RELEASE);
    }

    if (max_tx < wr_index) {
        *bad_qbuf = (umq_buf_t *)(uintptr_t)urma_wr[max_tx].user_ctx;
        ret = umq_ub_shared_credit_req_send(queue);
        ret = (ret != UMQ_SUCCESS) ? ret : -UMQ_ERR_EAGAIN;
        umq_ub_tx_eagain_cnt(ret, user_send_imm, queue, wr_index - max_tx, qbuf);
    }

    if (wr_cnt_limit < max_tx) {
        if (opcode_consume_rqe) {
            umq_ub_window_inc(&queue->flow_control, max_tx - wr_cnt_limit);
        }
        *bad_qbuf = (umq_buf_t *)(uintptr_t)urma_wr[wr_cnt_limit].user_ctx;
        ret = -UMQ_ERR_ENOBUFS;
    }

    return UMQ_SUCCESS;

RECOVER_JETTY_NODE:
    umq_ub_post_release_jetty_node(queue, failed_num);

RECOVER_WINDOW:
    if (opcode_consume_rqe) {
        umq_ub_window_inc(&queue->flow_control, umq_ub_tx_failed_num(urma_wr, max_tx, *bad_qbuf));
    }
    umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND,
        max_tx - umq_ub_tx_failed_num(urma_wr, max_tx, *bad_qbuf), queue->dev_ctx->io_lock_free);

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

static void umq_ub_rqe_posted_cnt_inc(ub_queue_t *queue, uint16_t count)
{
    if (queue->prefill_done) {
        umq_ub_shared_credit_recharge(queue, count);
        return;
    }

    uint32_t total_prefill = __atomic_add_fetch(&queue->prefill_rqe_cnt, count, __ATOMIC_RELAXED);
    if (total_prefill >= queue->rqe_post_factor * queue->rx_depth) {
        umq_ub_shared_credit_recharge(queue, queue->rx_depth);
        queue->prefill_done = true;
    }
}

int umq_ub_post_rx_inner_impl(ub_queue_t *queue, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    uint32_t max_sge_num = queue->max_rx_sge;
    urma_jfr_wr_t recv_wr[UMQ_BATCH_SIZE] = {0};
    urma_jfr_wr_t *recv_wr_ptr = recv_wr;

    urma_sge_t sges[UMQ_BATCH_SIZE][max_sge_num];
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
    int ret = UMQ_FAIL;
    while (buffer) {
        uint32_t rest_size = buffer->total_data_size;
        if (rest_size == 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
                "eid: " EID_FMT ", jetty_id: %u, buffer total data size invalid\n", EID_ARGS(*eid), id);
            goto PUT_ALL_RX_CTX;
        }

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

            if (buffer->mempool_id == QBUF_POOL_MEMPOOL_ID_MAX) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, ub only supports using pooled memory\n",
                    EID_ARGS(*eid), id);
                ret = -UMQ_ERR_EFAULT;
                goto PUT_CUR_RX_CTX;
            }

            sges_ptr->tseg = tseg_list[buffer->mempool_id];
            if (sges_ptr->tseg == NULL) {
                UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n",
                    EID_ARGS(*eid), id, buffer->mempool_id);
                goto PUT_CUR_RX_CTX;
            }
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
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status;

    bool post_jfr = is_umq_ub_main_queue(queue->create_flag);
    if (post_jfr) {
        status = umq_symbol_urma()->urma_post_jfr_wr(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr, recv_wr, &bad_wr);
    } else {
        status = umq_symbol_urma()->urma_post_jetty_recv_wr(queue->jetty[UB_QUEUE_JETTY_IO], recv_wr, &bad_wr);
    }
    if (status != URMA_SUCCESS) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        if (post_jfr) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jfr_wr failed, "
                                                  "status: %d\n", EID_ARGS(*eid), id, (int)status);
        } else {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_recv_wr failed, "
                                                  "status: %d\n", EID_ARGS(*eid), id, (int)status);
        }
        if (bad_wr != NULL) {
            *bad_qbuf = (umq_buf_t *)(uintptr_t)bad_wr->user_ctx;
        } else {
            *bad_qbuf = qbuf;
            bad_wr = recv_wr;
        }
        umq_ub_rqe_posted_cnt_inc(queue, wr_index - umq_ub_post_rx_failed_num(recv_wr, wr_index, *bad_qbuf));
        // if fails, add chain of qbuf back for rx
        process_bad_wr(queue, bad_wr, NULL);
        return umq_status_convert(status);
    }
    umq_ub_rqe_posted_cnt_inc(queue, wr_index);
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
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
    return ret;
}

int umq_ub_post_rx(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    return umq_ub_post_rx_inner_impl(queue, qbuf, bad_qbuf);
}

static ALWAYS_INLINE ub_queue_t *umq_ub_get_real_queue_by_cr(ub_queue_t *queue, const urma_cr_t *cr)
{
    umq_ub_imm_t imm = {.value = cr->imm_data};
    if (imm.io_imm.umq_id >= UMQ_ID_ALLOC_SIZE) {
        return NULL;
    }
    return (ub_queue_t *)(uintptr_t)queue->dev_ctx->umq_ctx_table[imm.io_imm.umq_id];
}

static void process_rx_mem_import_done(umq_ub_imm_t imm, ub_queue_t *queue, ub_queue_t *real_queue,
                                       umq_buf_pro_t *buf_pro, umq_buf_status_t *qbuf_status)
{
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    if (imm.mem_import.mempool_id >= UMQ_MAX_TSEG_NUM) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, mempool id exceed maxinum\n",
                           EID_ARGS(*eid), id);
        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
        return;
    }

    if (real_queue == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, sub queue has been destroyed\n",
                           EID_ARGS(*eid), id);
        buf_pro->umq_ctx = 0;
        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
        return;
    }

    buf_pro->umq_ctx = real_queue->umq_ctx;
    if (real_queue->bind_ctx == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, queue has been unbind\n",
                           EID_ARGS(*eid), real_queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id);
        *qbuf_status = UMQ_MEMPOOL_UPDATE_FAILED;
        return;
    }

    urpc_bitmap_set1(real_queue->bind_ctx->tseg_imported, imm.mem_import.mempool_id);
    *qbuf_status = UMQ_MEMPOOL_UPDATE_SUCCESS;
}

static void umq_ub_extend_imm_on_rx_done(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t *rx_buf,
                                         umq_buf_status_t *qbuf_status, ub_queue_t *real_queue)
{
    umq_ub_imm_t imm = {.value = cr->imm_data};
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
    switch (imm.bs_ext.extend_type) {
        case IMM_TYPE_EXTEND_MEM_IMPORT:
            if (umq_ub_data_plan_import_mem((uint64_t)(uintptr_t)real_queue, rx_buf, 0, false) != UMQ_SUCCESS) {
                *qbuf_status = UMQ_IMPORT_TSEG_FAILED;
                break;
            }
            *qbuf_status = UMQ_IMPORT_TSEG_SUCCESS;
            break;
        case IMM_TYPE_EXTEND_MEM_IMPORT_DONE:
            process_rx_mem_import_done(imm, queue, real_queue, buf_pro, qbuf_status);
            break;
        default:
            break;
    }
}

static int umq_ub_on_rx_done(ub_queue_t *queue, urma_cr_t *cr, umq_buf_t *rx_buf, umq_buf_status_t *qbuf_status)
{
    if (cr->opcode != URMA_CR_OPC_SEND_WITH_IMM) {
        return UMQ_SUCCESS;
    }

    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)rx_buf->qbuf_ext;
    buf_pro->opcode = UMQ_OPC_SEND_IMM;
    ub_queue_t *real_queue = umq_ub_get_real_queue_by_cr(queue, cr);
    if (real_queue != NULL) {
        umq_inc_ref(real_queue->dev_ctx->io_lock_free, &real_queue->ref_cnt, 1);
        buf_pro->umq_ctx = real_queue->umq_ctx;
    } else {
        buf_pro->umq_ctx = 0;
    }
    
    umq_ub_imm_t imm = {.value = cr->imm_data};
    switch (imm.bs.type) {
        case IMM_TYPE_USER:
            buf_pro->opcode = UMQ_OPC_SEND_IMM;
            buf_pro->imm.user_data = imm.io_imm.user_data;
            umq_io_perf_process(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, rx_buf);
            break;
        case IMM_TYPE_USER_WITHOUT_IMM:
            buf_pro->opcode = UMQ_OPC_SEND;
            break;
        case IMM_TYPE_CONTROL_MSG:
            umq_ub_extend_imm_on_rx_done(queue, cr, rx_buf, qbuf_status, real_queue);
            break;
        default:
            break;
    }

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
                if (imm.bs_ext.type == IMM_TYPE_USER) {
                    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
                    buf_pro->opcode = UMQ_OPC_WRITE_IMM;
                    buf_pro->imm_data = imm.value;
                    return UMQ_SUCCESS;
                }
            }
            break;
        }
        case URMA_CR_OPC_SEND_WITH_IMM: {
            ret = umq_ub_on_rx_done(queue, cr, buf, qbuf_status);
            break;
        }
        case URMA_CR_OPC_SEND: {
            umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)buf->qbuf_ext;
            buf_pro->opcode = UMQ_OPC_SEND;
            ub_queue_t *real_queue = umq_ub_get_real_queue_by_cr(queue, cr);
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

static inline void umq_perf_record_write_poll(umq_perf_record_type_t type, uint64_t start, int cr_cnt)
{
    if (cr_cnt > 0) {
        umq_perf_record_write(type, start);
    } else {
        umq_perf_record_write(type + UMQ_PERF_RECORD_TRANSPORT_POLL_EMPTY_OFFSET, start);
    }
}

static uint32_t umq_ub_fill_fc_buf(ub_queue_t *queue, umq_buf_t **buf, umq_buf_status_t status)
{
    uint32_t request = (umq_qbuf_mode_get() == UMQ_BUF_SPLIT) ? 0 : UMQ_UB_FC_UNDATE_FAKE_BUF_SIZE;
    umq_buf_t *fc_buf = umq_buf_alloc(request, 1, UMQ_INVALID_HANDLE, NULL);
    if (fc_buf == NULL) {
        return 0;
    }
    fc_buf->io_direction = UMQ_IO_RX;
    fc_buf->status = status;
    umq_buf_pro_t *buf_pro = (umq_buf_pro_t *)fc_buf->qbuf_ext;
    buf_pro->opcode = UMQ_OPC_SEND;
    buf_pro->umq_ctx = ((queue == NULL) ? 0 : queue->umq_ctx);
    *buf = fc_buf;
    return 1;
}

static ALWAYS_INLINE uint8_t umq_ub_fc_seq_inc(uint8_t seq)
{
    uint8_t next = seq + 1;
    return (next == 0) ? 1 : next;
}

static uint32_t umq_ub_process_fc_msg(ub_queue_t *queue, umq_ub_flow_control_data_t *flow_control_data,
    umq_buf_t **buf)
{
    uint32_t ret = 0;
    int umq_errno = 0;
    ub_flow_control_t *fc = &queue->flow_control;
    switch (flow_control_data->bs.type) {
        case IMM_TYPE_FC_CREDIT_REQ: {
            umq_errno = umq_ub_shared_credit_req_handle(queue, flow_control_data);
            if (umq_errno == -UMQ_ERR_EMLINK) {
                ret = umq_ub_fill_fc_buf(queue, buf, UMQ_FAKE_BUF_FC_EMLINK);
            } else if (umq_errno != UMQ_SUCCESS) {
                ret = umq_ub_fill_fc_buf(queue, buf, UMQ_FAKE_BUF_FC_ERR);
            }
            break;
        }
        case IMM_TYPE_FC_CREDIT_REP:
            ret = umq_ub_fill_fc_buf(queue, buf, UMQ_FAKE_BUF_FC_UPDATE);
            umq_ub_shared_credit_resp_handle(queue, flow_control_data);
            fc->local_req_seq = umq_ub_fc_seq_inc(fc->local_req_seq);
            break;
        case IMM_TYPE_FC_CREDIT_RETURN_REQ: {
            if (umq_ub_shared_credit_return_req_handle(queue, flow_control_data) != UMQ_SUCCESS) {
                ret = umq_ub_fill_fc_buf(queue, buf, UMQ_FAKE_BUF_FC_ERR);
            }
            break;
        }
        case IMM_TYPE_FC_CREDIT_RETURN_ACK: {
            fc->peer_ratio = flow_control_data->bs.ratio;
            fc->local_req_seq = umq_ub_fc_seq_inc(fc->local_req_seq);
            break;
        }
        default:
            break;
    }
    return ret;
}

static void umq_ub_fill_rx_buff_post_process(ub_queue_t *queue,
    umq_ub_flow_control_data_t *flow_control_data)
{
    ub_flow_control_t *fc = &queue->flow_control;
    switch (flow_control_data->bs.type) {
        case IMM_TYPE_FC_CREDIT_REP:
            umq_ub_permission_release(fc);
            break;
        case IMM_TYPE_FC_CREDIT_RETURN_ACK:
            umq_ub_permission_release(fc);
            break;
        default:
            break;
    }
    return;
}

static bool is_umq_ub_flow_control_msg_duplicate(ub_queue_t *real_queue, umq_ub_flow_control_data_t *flow_control_data)
{
    ub_flow_control_t *fc = &real_queue->flow_control;

    switch (flow_control_data->bs.type) {
        case IMM_TYPE_FC_CREDIT_REQ:
        case IMM_TYPE_FC_CREDIT_RETURN_REQ:
            if (flow_control_data->bs.seq != fc->remote_expect_seq) {
                umq_ub_fc_packet_stats(fc, 1, UB_PACKET_STATS_TYPE_RECV_DUP_REQ);
                return true;
            }
            fc->remote_expect_seq = umq_ub_fc_seq_inc(fc->remote_expect_seq);
            __atomic_store_n((uint64_t *)&fc->imm[UB_QUEUE_FC_MSG_TYPE_REQ],
                             flow_control_data->value, __ATOMIC_RELEASE);
            return false;

        case IMM_TYPE_FC_CREDIT_REP:
        case IMM_TYPE_FC_CREDIT_RETURN_ACK:
            if (flow_control_data->bs.seq != fc->local_req_seq) {
                umq_ub_fc_packet_stats(fc, 1, UB_PACKET_STATS_TYPE_RECV_DUP_RSP);
                return true;
            }
            __atomic_store_n((uint64_t *)&fc->imm[UB_QUEUE_FC_MSG_TYPE_RSP],
                             flow_control_data->value, __ATOMIC_RELEASE);
            return false;

        default:
            return false;
    }
}

static int main_umq_ub_poll_fc_rx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count)
{
    umq_ub_imm_t imm;
    umq_ub_fc_sge_data_t *sge_data;
    umq_ub_flow_control_data_t fc_data;
    urma_cr_t cr[UMQ_UB_FC_POLL_COUNT_MAX];
    uint32_t poll_count = (buf_count >= UMQ_UB_FC_POLL_COUNT_MAX) ? UMQ_UB_FC_POLL_COUNT_MAX : buf_count;
    uint64_t start_timestmap = umq_perf_get_start_timestamp();
    int rx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc,
                                                     poll_count, cr);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, rx_cr_cnt);
        return UMQ_FAIL;
    }

    if (rx_cr_cnt > 0) {
        umq_ub_fc_packet_stats(&queue->flow_control, (uint32_t)rx_cr_cnt, UB_PACKET_STATS_TYPE_RECV);
    }

    int32_t qbuf_cnt = 0;
    ub_queue_t *real_queue;
    for (int i = 0; i < rx_cr_cnt; i++) {
        imm.value = cr[i].imm_data;
        if (cr[i].user_ctx == 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, user_ctx is NULL\n", EID_ARGS(*eid), id);
            continue;
        }
        sge_data = (umq_ub_fc_sge_data_t *)(uintptr_t)cr[i].user_ctx;
        fc_data.bs.type = sge_data->bs.type;
        fc_data.bs.window = sge_data->bs.window;
        fc_data.bs.ratio = sge_data->bs.ratio;
        fc_data.bs.seq = imm.flow_control.seq;
        if (umq_ub_fill_fc_rx_buf(queue, cr[i].user_ctx) != UMQ_SUCCESS) {
            qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_ERR);
            /* fall through: current FC msg is valid, must process it */
        }
        real_queue = umq_ub_get_real_queue_by_umq_id(queue, imm.flow_control.umq_id);
        if (real_queue == NULL) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, umq_id: %u, sub queue has been destroyed\n",
                EID_ARGS(*eid), id, imm.flow_control.umq_id);
            continue;
        }

        if (cr[i].status != URMA_CR_SUCCESS) {
            umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_RECV_ERROR);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE,
                "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                "remote jetty_id: %u, urma_poll_jfc reports rx cr[%d] status: %d\n",
                EID_ARGS(*eid), id, EID_ARGS(cr[i].remote_id.eid), cr[i].remote_id.id, i, (int)cr[i].status);
            qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(real_queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_ERR);
            umq_ub_put_real_queue(real_queue, imm.flow_control.umq_id);
            continue;
        }

        // Flow control messages sent to the main umq are processed directly.
        if (real_queue == queue) {
            if (is_umq_ub_flow_control_msg_duplicate(queue, &fc_data)) {
                umq_ub_put_real_queue(real_queue, imm.flow_control.umq_id);
                continue;
            }
            qbuf_cnt += (int32_t)umq_ub_process_fc_msg(queue, &fc_data, &buf[qbuf_cnt]);
            umq_ub_fill_rx_buff_post_process(queue, &fc_data);
            umq_ub_put_real_queue(real_queue, imm.flow_control.umq_id);
            continue;
        }

        if (is_umq_ub_flow_control_msg_duplicate(real_queue, &fc_data)) {
            // Duplicate packet, discard
            umq_ub_put_real_queue(real_queue, imm.flow_control.umq_id);
            continue;
        }

        qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(real_queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_MSG);
        umq_ub_put_real_queue(real_queue, imm.flow_control.umq_id);
    }
    return qbuf_cnt;
}

static int sub_umq_ub_poll_fc_rx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count)
{
    uint32_t qbuf_cnt = 0;
    uint32_t ret = 0;
    for (uint16_t i = 0; i < UB_QUEUE_FC_MSG_TYPE_MAX && qbuf_cnt < buf_count; i++) {
        umq_ub_flow_control_data_t fc_data;
        fc_data.value = __atomic_exchange_n((uint64_t *)&queue->flow_control.imm[i], 0, __ATOMIC_ACQUIRE);
        if (fc_data.value == 0) {
            continue;
        }
        ret = umq_ub_process_fc_msg(queue, &fc_data, &buf[qbuf_cnt]);
        if (ret > 0 && (buf[qbuf_cnt]->status == UMQ_FAKE_BUF_FC_EMLINK)) {
            __atomic_store_n((uint64_t *)&queue->flow_control.imm[i], fc_data.value, __ATOMIC_RELEASE);
        }
        qbuf_cnt += ret;
        (void)umq_ub_fill_rx_buff_post_process(queue, &fc_data);
    }
    return (int)qbuf_cnt;
}

static int umq_ub_poll_fc_rx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count)
{
    umq_ub_imm_t imm;
    umq_ub_fc_sge_data_t *sge_data;
    umq_ub_flow_control_data_t fc_data;
    urma_cr_t cr[UMQ_UB_FLOW_CONTORL_JETTY_DEPTH];
    uint64_t start_timestmap = umq_perf_get_start_timestamp();
    /* If buf is NULL, poll max depth; otherwise poll min(buf_count, max_depth) */
    uint32_t poll_count = (buf == NULL || buf_count >= UMQ_UB_FLOW_CONTORL_JETTY_DEPTH) ?
        UMQ_UB_FLOW_CONTORL_JETTY_DEPTH : buf_count;
    int rx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr_jfc,
                                                     poll_count, cr);
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, rx_cr_cnt);
    if (rx_cr_cnt < 0) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports rx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, rx_cr_cnt);
        return UMQ_FAIL;
    }

    if (rx_cr_cnt > 0) {
        queue->interrupt_ctx.rx_fc_interrupt = false;
        umq_ub_fc_packet_stats(&queue->flow_control, (uint32_t)rx_cr_cnt, UB_PACKET_STATS_TYPE_RECV);
    }
    int ret = UMQ_SUCCESS;
    int32_t qbuf_cnt = 0;

    for (int i = 0; i < rx_cr_cnt; i++) {
        imm.value = cr[i].imm_data;
        if (cr[i].user_ctx == 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "eid: " EID_FMT ", jetty_id: %u, user_ctx is NULL\n", EID_ARGS(*eid), id);
            continue;
        }
        sge_data = (umq_ub_fc_sge_data_t *)(uintptr_t)cr[i].user_ctx;
        fc_data.bs.type = sge_data->bs.type;
        fc_data.bs.window = sge_data->bs.window;
        fc_data.bs.ratio = sge_data->bs.ratio;
        fc_data.bs.seq = imm.flow_control.seq;
        if (umq_ub_fill_fc_rx_buf(queue, cr[i].user_ctx) != UMQ_SUCCESS) {
            ret = -UMQ_ERR_EFLOWCTL;
            if (buf != NULL) {
                qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_ERR);
            }
            /* fall through: current FC msg is valid, must process it */
        }
        if (cr[i].status != URMA_CR_SUCCESS) {
            umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_RECV_ERROR);
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE,
                "local eid: " EID_FMT ", local jetty_id: %u, remote eid: " EID_FMT ", "
                "remote jetty_id: %u, urma_poll_jfc reports rx cr[%d] status: %d\n", EID_ARGS(*eid), id,
                EID_ARGS(cr[i].remote_id.eid), cr[i].remote_id.id, i, (int)cr[i].status);
            ret = -UMQ_ERR_EFLOWCTL;
            if (buf != NULL) {
                qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_ERR);
            }
            continue;
        }
        if (is_umq_ub_flow_control_msg_duplicate(queue, &fc_data)) {
            continue;
        }
        qbuf_cnt += (int32_t)umq_ub_process_fc_msg(queue, &fc_data, &buf[qbuf_cnt]);
        umq_ub_fill_rx_buff_post_process(queue, &fc_data);
    }
    /* If buf is not NULL, return qbuf_cnt (0 if no error, >0 if has error);
     * If buf is NULL, return ret (0 if no error, error code if has error) */
    return (buf != NULL) ? qbuf_cnt : ret;
}

int umq_ub_fill_fc_rx_buf(ub_queue_t *queue, uint64_t user_ctx)
{
    urma_sge_t fc_sge = {.addr = user_ctx, .len = sizeof(umq_ub_fc_sge_data_t)};
    umq_buf_t *qbuf = umq_qbuf_data_to_head((void *)(uintptr_t)user_ctx);
    if (qbuf == NULL || qbuf->mempool_id >= QBUF_POOL_MEMPOOL_ID_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, fc rx buf mempool invalid\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
        return -UMQ_ERR_EFAULT;
    }

    fc_sge.tseg = queue->dev_ctx->tseg_list[qbuf->mempool_id];
    if (fc_sge.tseg == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, qbuf->mempool_id);
        return -UMQ_ERR_EFAULT;
    }
    urma_jfr_wr_t recv_wr = {
        .src = {.sge = &fc_sge, .num_sge = 1},
        .user_ctx = user_ctx
    };
    urma_jfr_wr_t *bad_wr = NULL;
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    urma_status_t status;
    if (is_umq_ub_main_queue(queue->create_flag)) {
        status =
            umq_symbol_urma()->urma_post_jfr_wr(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr, &recv_wr, &bad_wr);
    } else {
        status =
            umq_symbol_urma()->urma_post_jetty_recv_wr(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL], &recv_wr, &bad_wr);
    }
    if (status != URMA_SUCCESS) {
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_POST_RECV, start_timestamp);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_recv_wr failed, "
            "status: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, (int)status);
        return umq_status_convert(status);
    }
    return UMQ_SUCCESS;
}

static int umq_ub_post_fc_recv_wrs(ub_queue_t *queue, urma_jfr_wr_t *recv_wr)
{
    urma_jfr_wr_t *bad_wr = NULL;
    urma_status_t status;
    bool post_jfr = is_umq_ub_main_queue(queue->create_flag);
    if (post_jfr) {
        status =
            umq_symbol_urma()->urma_post_jfr_wr(queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->jfr, recv_wr, &bad_wr);
    } else {
        status =
            umq_symbol_urma()->urma_post_jetty_recv_wr(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL], recv_wr, &bad_wr);
    }
    if (status != URMA_SUCCESS) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_post_jetty_recv_wr failed, "
            "status: %d\n", EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, (int)status);
        /* rollback SGE resources allocated above */
        if (post_jfr) {
            umq_ub_flow_control_share_rq_sge_uninit(&queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL]->share_rq_sge);
        } else {
            umq_ub_flow_control_sge_free(&queue->dev_ctx->fc_sge_mgr, &queue->flow_control.recv_sge);
        }
        return umq_status_convert(status);
    }
    return UMQ_SUCCESS;
}

static int umq_ub_fill_fc_rx_post_jfr(ub_queue_t *queue, uint32_t batch,
    urma_jfr_wr_t *recv_wr, urma_sge_t *fc_sges)
{
    jfr_ctx_t *jfr_ctx = queue->jfr_ctx[UB_QUEUE_JETTY_FLOW_CONTROL];
    if (jfr_ctx->share_rq_sge.qbuf_cnt == 0) {
        uint32_t qbuf_cnt_needed =
            (batch * sizeof(umq_ub_fc_sge_data_t) + umq_buf_size_small() - 1) / umq_buf_size_small();
        if (qbuf_cnt_needed > UMQ_UB_FLOW_CONTROL_SGE_SHARED_RECV_QBUF_MAX) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, "
                "number of requested recv wr exceeds the upper limit %u\n",
                EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
                queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, UMQ_UB_FLOW_CONTROL_SGE_SHARED_RECV_QBUF_MAX);
            return -UMQ_ERR_EINVAL;
        }
        int ret = umq_ub_flow_control_share_rq_sge_init(&jfr_ctx->share_rq_sge, qbuf_cnt_needed);
        if (ret != UMQ_SUCCESS) {
            return ret;
        }
    }
    uint16_t mempool_id = jfr_ctx->share_rq_sge.qbuf_array[0]->mempool_id;
    if (mempool_id >= QBUF_POOL_MEMPOOL_ID_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, fc rx buf mempool invalid\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
        return -UMQ_ERR_EFAULT;
    }
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];
    if (tseg == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, mempool_id);
        return -UMQ_ERR_EFAULT;
    }
    for (uint32_t i = 0; i < batch; i++) {
        uint32_t byte_offset = i * sizeof(umq_ub_fc_sge_data_t);
        uint32_t qbuf_idx = byte_offset / umq_buf_size_small();
        uint32_t qbuf_offset = byte_offset % umq_buf_size_small();
        uint64_t addr = (uint64_t)(uintptr_t)((char *)jfr_ctx->share_rq_sge.qbuf_array[qbuf_idx]->buf_data +
                                               qbuf_offset);
        fc_sges[i].addr = addr;
        fc_sges[i].len = sizeof(umq_ub_fc_sge_data_t);
        fc_sges[i].tseg = tseg;
        recv_wr[i].src.sge = &fc_sges[i];
        recv_wr[i].src.num_sge = 1;
        recv_wr[i].user_ctx = addr;
        recv_wr[i].next = (i == batch - 1) ? NULL : &recv_wr[i + 1];
    }
    return UMQ_SUCCESS;
}

static int umq_ub_fill_fc_rx_post_jetty(ub_queue_t *queue, uint32_t batch,
    urma_jfr_wr_t *recv_wr, urma_sge_t *fc_sges)
{
    uint32_t max_entries_per_slot = UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT / sizeof(umq_ub_fc_sge_data_t);
    if (batch > max_entries_per_slot) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API,
            "eid: " EID_FMT ", jetty_id: %u, batch %u exceeds max entries per slot %u\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, batch, max_entries_per_slot);
        return -UMQ_ERR_EINVAL;
    }
    int ret = umq_ub_flow_control_sge_alloc(&queue->dev_ctx->fc_sge_mgr, &queue->flow_control.recv_sge);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }
    uint32_t qbuf_idx = queue->flow_control.recv_sge.bitmap_idx /
                        (umq_buf_size_small() / UMQ_UB_FLOW_CONTROL_SGE_BYTES_PER_SLOT);
    uint16_t mempool_id = queue->dev_ctx->fc_sge_mgr.qbuf_array[qbuf_idx]->mempool_id;
    if (mempool_id >= QBUF_POOL_MEMPOOL_ID_MAX) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, fc rx buf mempool invalid\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
        return -UMQ_ERR_EFAULT;
    }
    urma_target_seg_t *tseg = queue->dev_ctx->tseg_list[mempool_id];
    if (tseg == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,
            "eid: " EID_FMT ", jetty_id: %u, mempool %u tseg not exist\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, mempool_id);
        return -UMQ_ERR_EFAULT;
    }
    for (uint32_t i = 0; i < batch; i++) {
        uint64_t addr = (uint64_t)(uintptr_t)((char *)queue->flow_control.recv_sge.addr +
                                               (i % max_entries_per_slot) * sizeof(umq_ub_fc_sge_data_t));
        fc_sges[i].addr = addr;
        fc_sges[i].len = sizeof(umq_ub_fc_sge_data_t);
        fc_sges[i].tseg = tseg;
        recv_wr[i].src.sge = &fc_sges[i];
        recv_wr[i].src.num_sge = 1;
        recv_wr[i].user_ctx = addr;
        recv_wr[i].next = (i == batch - 1) ? NULL : &recv_wr[i + 1];
    }
    return UMQ_SUCCESS;
}

int umq_ub_fill_fc_rx_buf_batch(ub_queue_t *queue, uint8_t rqe_post_factor)
{
    int ret;
    uint32_t batch = queue->fc_rx_depth * rqe_post_factor;
    if (batch == 0) {
        return UMQ_SUCCESS;
    }

    if (rqe_post_factor > URMA_UBAGG_DEV_MAX_NUM) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, "
            "rqe_post_factor %d of requested recv wr exceeds the upper limit %u\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id, rqe_post_factor, URMA_UBAGG_DEV_MAX_NUM);
        return -UMQ_ERR_EINVAL;
    }

    urma_jfr_wr_t *recv_wr = (urma_jfr_wr_t *)(uintptr_t)calloc(batch, sizeof(urma_jfr_wr_t) + sizeof(urma_sge_t));
    if (recv_wr == NULL) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, calloc recv wr failed\n",
            EID_ARGS(queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid),
            queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id);
        return -UMQ_ERR_ENOMEM;
    }

    if (is_umq_ub_main_queue(queue->create_flag)) {
        ret = umq_ub_fill_fc_rx_post_jfr(queue, batch, recv_wr, (urma_sge_t *)(recv_wr + batch));
    } else {
        ret = umq_ub_fill_fc_rx_post_jetty(queue, batch, recv_wr, (urma_sge_t *)(recv_wr + batch));
    }
    if (ret != UMQ_SUCCESS) {
        goto FREE_RECV_WR;
    }

    uint32_t post_left_num = queue->fc_rx_depth;
    uint32_t post_round = (queue->fc_rx_depth + UMQ_BATCH_SIZE - 1)/ UMQ_BATCH_SIZE;
    for (uint32_t i = 0; i < post_round; i++) {
        uint32_t post_num = post_left_num > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : post_left_num;
        post_left_num -= post_num;

        for (uint8_t j = 0; j < rqe_post_factor; j++) {
            uint32_t offset = i * rqe_post_factor * UMQ_BATCH_SIZE + j * post_num;
            recv_wr[offset + post_num - 1].next = NULL;
            ret = umq_ub_post_fc_recv_wrs(queue, &recv_wr[offset]);
            if (ret != UMQ_SUCCESS) {
                goto FREE_RECV_WR;
            }
        }
    }

FREE_RECV_WR:
    free(recv_wr);
    return ret;
}

int umq_ub_poll_rx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count)
{
    if (buf_count == 0) {
        return 0;
    }
    int ret;
    uint32_t qbuf_cnt = 0;
    uint32_t max_batch = buf_count > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;
    if (queue->flow_control.enabled) {
        int fc_qbuf_cnt = 0;
        if (!UMQ_UB_ENABLE_SHARE_FC_JFR) {
            /* buf is not NULL here, so umq_ub_poll_fc_rx returns qbuf_cnt >= 0 */
            fc_qbuf_cnt += umq_ub_poll_fc_rx(queue, buf, max_batch);
        } else if ((queue->create_flag & UMQ_CREATE_FLAG_MAIN_UMQ) != 0) {
            fc_qbuf_cnt += main_umq_ub_poll_fc_rx(queue, buf, max_batch);
        } else if (is_umq_ub_share_rq(queue->create_flag)) {
            fc_qbuf_cnt += sub_umq_ub_poll_fc_rx(queue, buf, max_batch);
        } else {
            fc_qbuf_cnt += umq_ub_poll_fc_rx(queue, buf, max_batch);
        }

        if (fc_qbuf_cnt < 0) {
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ,  "UMQ(ID:%u), poll flow control failed, ret %d\n", queue->umq_id, fc_qbuf_cnt);
            return fc_qbuf_cnt;
        }
        qbuf_cnt += (uint32_t)fc_qbuf_cnt;
    }

    if (queue->wait_ack_import.wait_ack_idx > 0) {
        umq_ub_ack_import_tseg(queue);
    }

    max_batch -= qbuf_cnt;
    urma_cr_t cr[max_batch];
    if (max_batch == 0 || is_umq_ub_share_rq(queue->create_flag)) {
        goto OUT;
    }

    if (queue->state == QUEUE_STATE_ERR) {
        // only main queue in error state can report incomplete rx
        if (!(queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ)) {
            qbuf_cnt += umq_report_incomplete_rx(queue, max_batch, &buf[qbuf_cnt]);
        }
        goto OUT;
    }

    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;
    uint64_t start_timestmap = umq_perf_get_start_timestamp();
    int rx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(queue->jfr_ctx[UB_QUEUE_JETTY_IO]->jfr_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_RX, start_timestmap, rx_cr_cnt);
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

    uint32_t success_cnt = 0;
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
            umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_RECV_ERROR, 1, queue->dev_ctx->io_lock_free);
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
            success_cnt++;
        }
        ++qbuf_cnt;
    }

    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_RECV, success_cnt, queue->dev_ctx->io_lock_free);
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
    if (imm.bs_ext.type != IMM_TYPE_CONTROL_MSG) {
        return UMQ_SUCCESS;
    }

    switch (buf_pro->opcode) {
        case UMQ_OPC_SEND_IMM:
            if (imm.bs_ext.extend_type == IMM_TYPE_EXTEND_MEM_IMPORT) {
                umq_buf_free(buf);
                return UMQ_CONTINUE_FLAG;
            } else if (imm.bs_ext.extend_type == IMM_TYPE_EXTEND_MEM_IMPORT_DONE) {
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
    uint32_t max_batach = buf_count > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : buf_count;
    urma_cr_t cr[max_batach];
    int cnt = 0;
    int cr_cnt = umq_symbol_urma()->urma_flush_jetty(queue->jetty[UB_QUEUE_JETTY_IO], max_batach, cr);
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
        case IMM_TYPE_FC_CREDIT_RETURN_REQ:
            notify = obj->bs.notify;
            fc->ops.remote_rx_window_inc(fc, notify, true);
            umq_ub_permission_release(fc);
            break;
        default:
            break;
    }
}

static ALWAYS_INLINE bool umq_ub_poll_get_jetty_node(ub_queue_t *queue)
{
    if (!is_umq_ub_logic_queue(queue->create_flag)) {
        return true;
    }

    jetty_pool_node_t *node = queue->jetty_node;
    if (node == NULL) {
        return false;
    }

    uint64_t expected = (uint64_t)(uintptr_t)queue;
    if (!__atomic_compare_exchange_n(&node->umq_ref, &expected, 0, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        queue->jetty_node = NULL;
        return false;
    }
    return true;
}

static ALWAYS_INLINE void umq_ub_poll_release_jetty_node(ub_queue_t *queue, uint32_t cnt, uint32_t tp_handle_idx)
{
    if (is_umq_ub_logic_queue(queue->create_flag) && queue->jetty_node != NULL) {
        jetty_pool_node_t *node = queue->jetty_node;
        if (__atomic_sub_fetch(&node->tx_outstanding, cnt, __ATOMIC_ACQ_REL) == 0) {
            queue->jetty_node = NULL;
            umq_ub_jetty_node_free(node);
            return;
        }
        __atomic_store_n(&node->umq_ref, (uint64_t)(uintptr_t)queue, __ATOMIC_RELEASE);
    } else if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag) &&
        cnt > 0) {
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        jetty_pool_node_t *node = jetty_node_list->node_list[tp_handle_idx];
        if (__atomic_sub_fetch(&node->tx_outstanding, cnt, __ATOMIC_ACQ_REL) == 0 &&
            __atomic_exchange_n(&node->umq_ref, 0, __ATOMIC_RELAXED) != 0) {
            queue->jetty_node = NULL;
            umq_ub_jetty_node_free(node);
            return;
        }
    }
}

// IO borrow: ensure a jetty node is borrowed for Logic UMQ IO send path.
int umq_ub_get_jetty_node(ub_queue_t *queue, uint32_t wr_cnt)
{
    if (!is_umq_ub_logic_queue(queue->create_flag)) {
        return UMQ_SUCCESS;
    }

    jetty_pool_node_t *node = queue->jetty_node;
    bool need_alloc = true;
    if (node != NULL) {
        uint64_t expected = (uint64_t)(uintptr_t)queue;
        if (__atomic_compare_exchange_n(&node->umq_ref, &expected, 0, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            need_alloc = false;
        } else {
            queue->jetty_node = NULL;
        }
    }

    if (need_alloc) {
        node = umq_ub_jetty_node_alloc();
        if (node == NULL) {
            return -errno;
        }
        queue->jetty[UB_QUEUE_JETTY_IO] = node->jetty[UB_QUEUE_JETTY_IO];
        queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL] = node->jetty[UB_QUEUE_JETTY_FLOW_CONTROL];
        queue->jfs_jfc[UB_QUEUE_JETTY_IO] = node->jfs_jfc[UB_QUEUE_JETTY_IO];
        queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL] = node->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL];
        queue->jetty_node = node;
        __atomic_store_n(&node->umq_ref, 0, __ATOMIC_RELEASE);
    }
    if (wr_cnt > 0) {
        (void)__atomic_add_fetch(&node->tx_outstanding, wr_cnt, __ATOMIC_ACQ_REL);
    }
    return UMQ_SUCCESS;
}

// FC release: restore umq_ref on success, or rollback on failure.
void umq_ub_post_release_jetty_node(ub_queue_t *queue, uint32_t failed_cnt)
{
    if (!is_umq_ub_logic_queue(queue->create_flag) || queue->jetty_node == NULL) {
        return;
    }

    jetty_pool_node_t *node = queue->jetty_node;
    if (failed_cnt == 0) {
        __atomic_store_n(&node->umq_ref, (uint64_t)(uintptr_t)queue, __ATOMIC_RELEASE);
    } else {
        if (__atomic_sub_fetch(&node->tx_outstanding, failed_cnt, __ATOMIC_ACQ_REL) == 0) {
            queue->jetty_node = NULL;
            umq_ub_jetty_node_free(node);
            return;
        }
        __atomic_store_n(&node->umq_ref, (uint64_t)(uintptr_t)queue, __ATOMIC_RELEASE);
    }
}

int umq_ub_poll_fc_tx(ub_queue_t *queue, umq_buf_t **buf, uint32_t buf_count, uint32_t tp_handle_idx)
{
    urma_cr_t cr[UMQ_UB_FLOW_CONTORL_JETTY_DEPTH];

    if (!umq_ub_poll_get_jetty_node(queue)) {
        return 0;
    }

    uint64_t start_timestmap = umq_perf_get_start_timestamp();
    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_FLOW_CONTROL]->jetty_id.id;
    /* If buf is NULL, poll max depth; otherwise poll min(buf_count, max_depth) */
    uint32_t poll_count = (buf == NULL || buf_count >= UMQ_UB_FLOW_CONTORL_JETTY_DEPTH) ?
        UMQ_UB_FLOW_CONTORL_JETTY_DEPTH : buf_count;

    urma_jfc_t *jfs_jfc = queue->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL];
    if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (jetty_node_list->bitmap != NULL && tp_handle_idx < jetty_node_list->list_len &&
            urpc_bitmap_is_set(jetty_node_list->bitmap, tp_handle_idx)) {
            jfs_jfc = jetty_node_list->node_list[tp_handle_idx]->jfs_jfc[UB_QUEUE_JETTY_FLOW_CONTROL];
        }
    }

    int tx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(jfs_jfc, poll_count, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        umq_ub_poll_release_jetty_node(queue, 0, tp_handle_idx);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return UMQ_FAIL;
    }

    if (tx_cr_cnt > 0) {
        queue->interrupt_ctx.tx_fc_interrupt = false;
    }

    int ret = UMQ_SUCCESS;
    uint32_t success_cnt = 0;
    int32_t qbuf_cnt = 0;
    uint32_t failed_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        umq_ub_fc_user_ctx_t obj = {.value = cr[i].user_ctx};
        if (cr[i].status != URMA_CR_SUCCESS) {
            if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
                umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
                umq_ub_jetty_node_mark_err(jetty_node_list->node_list[tp_handle_idx]);
            } else if (is_umq_ub_logic_queue(queue->create_flag)) {
                umq_ub_jetty_node_mark_err(queue->jetty_node);
            }
            umq_ub_fc_packet_stats(&queue->flow_control, 1, UB_PACKET_STATS_TYPE_SEND_ERROR);
            if (cr[i].status == URMA_CR_WR_FLUSH_ERR_DONE || cr[i].status == URMA_CR_WR_SUSPEND_DONE) {
                UMQ_LIMIT_VLOG_INFO(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx "
                    "cr[%d] status[%d] local_id[%u]\n", EID_ARGS(*eid), id, i, (int)cr[i].status, cr[i].local_id);
                continue;
            }
            UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_CQE, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx cr[%d] "
                "status[%d] local_id[%u]\n", EID_ARGS(*eid), id, i, (int)cr[i].status, cr[i].local_id);
            ret = -UMQ_ERR_EFLOWCTL;
            umq_ub_fc_process_tx_error(queue, &obj);
            if (buf != NULL) {
                qbuf_cnt += (int32_t)umq_ub_fill_fc_buf(queue, &buf[qbuf_cnt], UMQ_FAKE_BUF_FC_ERR);
            }
            failed_cnt++;
            continue;
        }

        success_cnt++;
    }

    if (success_cnt > 0) {
        umq_ub_fc_packet_stats(&queue->flow_control, success_cnt, UB_PACKET_STATS_TYPE_SEND_SUCCESS);
    }

    umq_ub_poll_release_jetty_node(queue, failed_cnt + success_cnt, tp_handle_idx);

    /* If buf is not NULL, return qbuf_cnt (0 if no error, >0 if has error);
     * If buf is NULL, return ret (0 if no error, error code if has error) */
    return (buf != NULL) ? qbuf_cnt : ret;
}

int umq_ub_poll_tx(uint64_t umqh, umq_buf_t **buf, uint32_t buf_count, uint32_t tp_handle_idx)
{
    (void)tp_handle_idx;
    if (buf_count == 0) {
        return 0;
    }
    int32_t qbuf_cnt = 0;
    uint32_t max_batch = buf_count > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : buf_count;
    ub_queue_t *queue = (ub_queue_t *)(uintptr_t)umqh;

    if (queue->flow_control.enabled) {
        if ((queue->create_flag & UMQ_CREATE_FLAG_SUB_UMQ) != 0) {
            uint64_t count;
            ub_queue_idle_check_t *checker = queue->checker;
            if (__atomic_load_n(&checker->need_return_credit, __ATOMIC_RELAXED)) {
                int ret = umq_ub_shared_credit_return_req_send(queue);
                if (ret != UMQ_SUCCESS) {
                    return ret;
                }
                __atomic_store_n(&checker->need_return_credit, false, __ATOMIC_RELAXED);
                (void)eventfd_read(checker->event_fd, &count);
            }
        }
        if ((queue->mode == UMQ_MODE_POLLING || queue->interrupt_ctx.tx_fc_interrupt)) {
            /* buf is not NULL here, so umq_ub_poll_fc_tx returns qbuf_cnt >= 0 */
            int ret = umq_ub_poll_fc_tx(queue, buf, buf_count, tp_handle_idx);
            if (ret < 0) {
                return ret;
            }
            qbuf_cnt += ret;
        }
    }

    if (!umq_ub_poll_get_jetty_node(queue)) {
        return 0;
    }

    urma_cr_t cr[max_batch];
    urma_jfc_t *jfs_jfc = queue->jfs_jfc[UB_QUEUE_JETTY_IO];
    if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
        umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
        if (jetty_node_list->bitmap != NULL && tp_handle_idx < jetty_node_list->list_len &&
            urpc_bitmap_is_set(jetty_node_list->bitmap, tp_handle_idx)) {
            jfs_jfc = jetty_node_list->node_list[tp_handle_idx]->jfs_jfc[UB_QUEUE_JETTY_IO];
        }
    }

    urma_eid_t *eid = &queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.eid;
    uint32_t id = queue->jetty[UB_QUEUE_JETTY_IO]->jetty_id.id;

    uint64_t start_timestmap = umq_perf_get_start_timestamp();
    int tx_cr_cnt = umq_symbol_urma()->urma_poll_jfc(jfs_jfc, max_batch, cr);
    umq_perf_record_write_poll(UMQ_PERF_RECORD_TRANSPORT_POLL_TX, start_timestmap, tx_cr_cnt);
    if (tx_cr_cnt < 0) {
        umq_ub_poll_release_jetty_node(queue, 0, tp_handle_idx);
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ_URMA_API, "eid: " EID_FMT ", jetty_id: %u, urma_poll_jfc reports tx_cr_cnt[%d]\n",
            EID_ARGS(*eid), id, tx_cr_cnt);
        return tx_cr_cnt;
    }

    uint32_t success_cnt = 0;
    uint32_t failed_cnt = 0;
    for (int i = 0; i < tx_cr_cnt; i++) {
        if (cr[i].status != URMA_CR_SUCCESS) {
            if (is_umq_ub_main_queue(queue->create_flag) && is_umq_ub_share_transport(queue->create_flag)) {
                umq_ub_jetty_node_list_t *jetty_node_list = queue->jetty_node_list;
                umq_ub_jetty_node_mark_err(jetty_node_list->node_list[tp_handle_idx]);
            } else if (is_umq_ub_logic_queue(queue->create_flag)) {
                umq_ub_jetty_node_mark_err(queue->jetty_node);
            }
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
            failed_cnt++;
        } else {
            success_cnt++;
        }

        /* After the read operation is complete, send_imm request with user_ctx equal to 0 will be sent.
         * This tx_cqe request does't need to be reported. */
        if (cr[i].user_ctx == 0) {
            umq_dec_ref(queue->dev_ctx->io_lock_free, &queue->tx_outstanding, 1);
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

    if (success_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_SUCCESS, success_cnt, queue->dev_ctx->io_lock_free);
    }

    if (queue->state == QUEUE_STATE_ERR && queue->tx_flush_done && (int)buf_count > qbuf_cnt) {
        tx_cr_cnt = umq_ub_flush_sqe(queue, &buf[qbuf_cnt], buf_count - qbuf_cnt);
        if (tx_cr_cnt > 0) {
            qbuf_cnt += tx_cr_cnt;
            failed_cnt += (uint32_t)tx_cr_cnt;
        }
    }
    if (failed_cnt > 0) {
        umq_ub_io_packet_stats(queue, UB_PACKET_STATS_TYPE_SEND_ERROR, failed_cnt, queue->dev_ctx->io_lock_free);
    }

    // Logic UMQ: release completed WRs back to pool
    umq_ub_poll_release_jetty_node(queue, success_cnt + failed_cnt, tp_handle_idx);

    return qbuf_cnt;
}