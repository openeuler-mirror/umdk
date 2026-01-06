/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: server example
 */

#include <unistd.h>
#include "urpc_framework_common.h"
#include "urpc_framework_errno.h"
#include "urpc_framework_server.h"

typedef enum client_case_type {
    CLIENT_NORAML_REQ,
    CLIENT_SET_QUEUE_REQ,
    CLIENT_TEST_CASE_NUM
} client_case_type_t;

typedef struct ref_read_idx {
    uint32_t dma_cnt;
    uint32_t dma_idx;
    uint64_t func_id;
    void *req_ctx;
    urpc_sge_t *req_sges[0];
} ref_read_idx_t;

#define TEST_REQ_TYPE_SEND 123
#define SERVER_USE_SGE_SIZE 256

static const urpc_allocator_t *g_allocator;

static int urpc_call_ref_read(urpc_poll_msg_t *msgs, uint64_t qh, custom_head_t *custom_head)
{
    urpc_ref_option_t option = {
        .option_flag = FUNC_REF_FLAG_USER_CTX,
    };

    ref_read_idx_t *read_idx =
        (ref_read_idx_t *)malloc(sizeof(ref_read_idx_t) + custom_head->dma_num * sizeof(uint64_t));
    if (read_idx == NULL) {
        return URPC_FAIL;
    }
    option.user_ctx = read_idx;
    read_idx->dma_cnt = 0;
    read_idx->dma_idx = 0;
    read_idx->req_ctx = msgs->req_recved.req_ctx;
    read_idx->func_id = msgs->req_recved.func_id;

    urpc_ref_sge_t r_ref_sge;
    urpc_ref_wr_t ref_wr = {
        .l_sges_num = 1,
        .r_ref_sges = &r_ref_sge,
        .r_ref_sges_num = 1,
    };

    urpc_example_dma_t *dma = (urpc_example_dma_t *)(custom_head + 1);
    for (uint32_t j = 0; j < custom_head->dma_num; j++) {
        r_ref_sge.addr = dma->address;
        r_ref_sge.length = dma->size;
        r_ref_sge.token_id = dma->token_id;
        r_ref_sge.token_value = dma->token_value;
        g_allocator->get_sges(&ref_wr.l_sges, 1, NULL);
        g_allocator->get_raw_buf(ref_wr.l_sges, dma->size, NULL);
        if (urpc_ref_read(qh, msgs->req_recved.req_ctx, &ref_wr, &option) != URPC_SUCCESS) {
            g_allocator->put_raw_buf(ref_wr.l_sges, NULL);
            g_allocator->put_sges(ref_wr.l_sges, NULL);
            if (read_idx->dma_cnt == read_idx->dma_idx) {
                free(read_idx);
            }
            LOG_PRINT("ref read failed\n");
            return URPC_FAIL;
        }
        read_idx->dma_cnt++;
        read_idx->req_sges[j] = ref_wr.l_sges;
        dma = (dma + 1);
    }
    LOG_PRINT("ref read success\n");
    return URPC_SUCCESS;
}

static void urpc_print_ref_msg(urpc_poll_msg_t *msg, uint64_t qh)
{
    ref_read_idx_t *read_idx = (ref_read_idx_t *)msg->ref_read_result.user_ctx;
    read_idx->dma_idx++;
    LOG_PRINT("(read client data) %s ret %u, dma_cnt %u , idx %u\n",
        (char *)(uintptr_t)msg->ref_read_result.l_sges[0].addr,
        msg->ref_read_result.ret_code, read_idx->dma_cnt, read_idx->dma_idx);

    if (read_idx->dma_cnt != read_idx->dma_idx) {
        return;
    }
    urpc_return_wr_t wr;
    urpc_return_option_t option = {0};
    int ret = urpc_func_exec(read_idx->func_id, read_idx->req_sges[0], 1, &wr.rsps, &wr.rsps_sge_num);
    if (ret == URPC_SUCCESS) {
        urpc_func_return(qh, read_idx->req_ctx, &wr, &option);
    }

    for (uint32_t i = 0; i < read_idx->dma_idx; i++) {
        g_allocator->put_raw_buf(read_idx->req_sges[i], NULL);
        free(read_idx->req_sges[i]);
    }
    free(read_idx);
}

static void server_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint64_t qh)
{
    if (msgs == NULL || poll_num > (int)CLIENT_TEST_CASE_NUM || qh == URPC_INVALID_HANDLE) {
        return;
    }

    int ret;
    for (int i = 0; i < poll_num; i++) {
        if (msgs[i].event == POLL_EVENT_READ_RET) {
            urpc_print_ref_msg(msgs + i, qh);
        } else if (msgs[i].event == POLL_EVENT_REQ_RECVED) {
            LOG_PRINT("------------------------------------------------\n");

            urpc_sge_t *sge = msgs[i].req_recved.args;
            custom_head_t *custom_head =
                (custom_head_t *)(uintptr_t)(sge->addr + urpc_hdr_size_get(URPC_REQ, 0));
            if (custom_head->msg_type == WITH_DMA) {
                (void)urpc_call_ref_read(&msgs[i], qh, custom_head);
                continue;
            }

            urpc_return_wr_t wr = {0};
            urpc_return_option_t option = {0};
            /*
             * user can directorly process msgs[i].req_recved.args/msgs[i].req_recved.args_sge_num
             * instead of calling
             */
            ret = urpc_func_exec(msgs[i].req_recved.func_id, msgs[i].req_recved.args,
                msgs[i].req_recved.args_sge_num, &wr.rsps, &wr.rsps_sge_num);
            if (ret != URPC_SUCCESS) {
                LOG_PRINT("urpc_func_exec failed %d\n", ret);
                g_allocator->put(msgs[i].req_recved.args, msgs[i].req_recved.args_sge_num, NULL);

                return;
            }
            (void)urpc_func_return(qh, msgs[i].req_recved.req_ctx, &wr, &option);

            g_allocator->put(msgs[i].req_recved.args, msgs[i].req_recved.args_sge_num, NULL);
        } else if (msgs[i].event == POLL_EVENT_RSP_SENDED) {
            g_allocator->put(msgs[i].rsp_sended.rsps, msgs[i].rsp_sended.rsps_sge_num, NULL);
        } else {
            LOG_PRINT("server_handle_poll_event %d\n", msgs[i].event);
        }
    }
}

int server_run_early_response(uint64_t qh, uint64_t qh1, const urpc_allocator_t *allocator)
{
    g_allocator = allocator;

    urpc_poll_msg_t msg = {0};
    struct urpc_poll_option poll_opt = {0};

    int poll_num;
    while (g_poll_exit == 0) {
        poll_opt.urpc_qh = qh;
        poll_num = urpc_func_poll(URPC_U32_FAIL, &poll_opt, &msg, 1);
        if (poll_num < 0) {
            LOG_PRINT("poll error, error: %d\n", poll_num);
            return URPC_FAIL;
        }
        server_handle_poll_event(&msg, poll_num, qh);

        if (qh1 != URPC_INVALID_HANDLE) {
            poll_opt.urpc_qh = qh1;
            poll_num = urpc_func_poll(URPC_U32_FAIL, &poll_opt, &msg, 1);
            if (poll_num < 0) {
                LOG_PRINT("poll error, error: %d\n", poll_num);
                return URPC_FAIL;
            }
            server_handle_poll_event(&msg, poll_num, qh1);
        }
    }

    return URPC_SUCCESS;
}
