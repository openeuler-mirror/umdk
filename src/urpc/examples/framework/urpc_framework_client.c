/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: client example
 */
 
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "urpc_framework_common.h"
#include "urpc_framework_errno.h"
#include "urpc_framework_client.h"

#define CLIENT_SGE_SIZE          4096
#define CLIENT_USE_SGE_SIZE      256
#define DEFAULT_TIMEOUT          1000
#define CLIENT_SLEEP_TIME        (1000 * 1000)

typedef enum client_case_type {
    CLIENT_NORAML_REQ,
    CLIENT_SET_QUEUE_REQ,
    CLIENT_TEST_CASE_NUM
} client_case_type_t;

static void set_early_rsp_mode(uint64_t qh __attribute__((unused)),
    urpc_channel_qinfos_t *qinfos __attribute__((unused)), urpc_call_option_t *option)
{
    option->option_flag |= FUNC_CALL_FLAG_CALL_MODE;
    option->call_mode |= FUNC_CALL_MODE_EARLY_RSP;
}

static void set_queue(uint64_t qh, urpc_channel_qinfos_t *qinfos, urpc_call_option_t *option)
{
    option->option_flag = FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH;
    option->l_qh = qh;
    option->r_qh = qinfos->r_qinfo[0].urpc_qh;
}

static void set_read(uint64_t qh __attribute__((unused)),
    urpc_channel_qinfos_t *qinfos __attribute__((unused)), urpc_call_option_t *option)
{
    option->option_flag |= FUNC_CALL_FLAG_CALL_MODE;
    option->call_mode = 0;
}

static client_test_case_t g_test_cases[] = {
    {
        .name = "early req without ack", .hit_event_num = 1,
        .hit_events = (1 << POLL_EVENT_REQ_RSPED), .func = set_early_rsp_mode
    }, {
        .name = "normal req without ack", .hit_event_num = 1,
        .hit_events = (1 << POLL_EVENT_REQ_RSPED), .func = NULL
    }, {
        .name = "normal set queue", .hit_event_num = 1,
        .hit_events = (1 << POLL_EVENT_REQ_RSPED), .func = set_queue
    }, {
        .name = "read", .hit_event_num = 1,
        .hit_events = (1 << POLL_EVENT_REQ_RSPED), .func = set_read
    }
};

static const urpc_allocator_t *g_allocator;

static void client_handle_req_sended(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if (msg->req_sended.args == NULL) {
        LOG_PRINT_ERR("(POLL_EVENT_REQ_SENDED)\n");
        return;
    }
    char *req = (char *)(uintptr_t)msg->req_sended.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
    LOG_PRINT("(POLL_EVENT_REQ_SENDED) req: %s\n", req);
    g_allocator->put(msg->req_sended.args, msg->req_sended.args_sge_num, NULL);

    *hit_events -= (1 << POLL_EVENT_REQ_SENDED);
}

static void client_handle_req_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if ((char *)(uintptr_t)msg->req_rsped.args == NULL &&
        (char *)(uintptr_t)msg->req_rsped.rsps == NULL) {
        LOG_PRINT_ERR("(POLL_EVENT_REQ_RSPED)\n");
        return;
    }

    if ((char *)(uintptr_t)msg->req_rsped.args != NULL) {
        custom_head_t *custom_header =
            (custom_head_t *)(uintptr_t)(msg->req_rsped.args->addr + urpc_hdr_size_get(URPC_REQ, 0));
        char *req_msg = (char *)(uintptr_t)msg->req_rsped.args->addr +
            urpc_hdr_size_get(URPC_REQ, 0) + sizeof(custom_head_t);
        if (custom_header->msg_type == WITH_DMA) {
            for (uint32_t i = 0; i < custom_header->dma_num; i++) {
                urpc_example_dma_t *dma = (urpc_example_dma_t *)(uintptr_t)req_msg + i;
                char *dma_buf = (char *)(uintptr_t)dma->address;
                LOG_PRINT("(POLL_EVENT_REQ_RSPED) req: %s\n", dma_buf);
                urpc_sge_t sge_one = {
                    .addr = dma->address,
                    .length = dma->size,
                };
                g_allocator->put_raw_buf(&sge_one, NULL);
            }
        } else {
            LOG_PRINT("(POLL_EVENT_REQ_RSPED) req: %s\n", req_msg);
        }
        g_allocator->put(msg->req_rsped.args, msg->req_rsped.args_sge_num, NULL);
    }

    if ((char *)(uintptr_t)msg->req_rsped.rsps != NULL) {
        char *rsp = (char *)(uintptr_t)msg->req_rsped.rsps->addr + urpc_hdr_size_get(URPC_RSP, 0);
        LOG_PRINT("(POLL_EVENT_REQ_RSPED) rsp: %s\n", rsp);
        g_allocator->put(msg->req_rsped.rsps, msg->req_rsped.rsps_sge_num, NULL);
    }

    *hit_events -= (1 << POLL_EVENT_REQ_RSPED);
}

static void client_handle_req_acked_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if ((char *)(uintptr_t)msg->req_acked_rsped.args == NULL &&
        (char *)(uintptr_t)msg->req_acked_rsped.rsps == NULL) {
        LOG_PRINT_ERR("(POLL_EVENT_REQ_ACKED_RSPED)\n");
        return;
    }

    if ((char *)(uintptr_t)msg->req_acked_rsped.args != NULL) {
        char *req = (char *)(uintptr_t)msg->req_acked_rsped.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
        LOG_PRINT("(POLL_EVENT_REQ_ACKED_RSPED) req: %s\n", req);
        g_allocator->put(msg->req_acked_rsped.args, msg->req_acked_rsped.args_sge_num, NULL);
    }

    if ((char *)(uintptr_t)msg->req_acked_rsped.rsps != NULL) {
        char *rsp = (char *)(uintptr_t)msg->req_acked_rsped.rsps->addr + urpc_hdr_size_get(URPC_RSP, 0);
        LOG_PRINT("(POLL_EVENT_REQ_ACKED_RSPED) rsp: %s\n", rsp);
        g_allocator->put(msg->req_acked_rsped.rsps, msg->req_acked_rsped.rsps_sge_num, NULL);
    }

    *hit_events -= (1 << POLL_EVENT_REQ_ACKED_RSPED);
}

static uint32_t client_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint32_t *hit_events)
{
    uint32_t event_num = 0;
    for (int i = 0; i < poll_num; i++) {
        if (msgs[i].event == POLL_EVENT_REQ_ACKED) {
            if ((char *)(uintptr_t)msgs[i].req_acked.args == NULL) {
                LOG_PRINT_ERR("(POLL_EVENT_REQ_ACKED)\n");
                continue;
            }

            char *req = (char *)(uintptr_t)msgs[i].req_acked.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
            LOG_PRINT("(POLL_EVENT_REQ_ACKED) req: %s\n", req);
            g_allocator->put(msgs[i].req_acked.args, msgs[i].req_acked.args_sge_num, NULL);
            *hit_events -= (1 << POLL_EVENT_REQ_ACKED);
            event_num++;
        } else if (msgs[i].event == POLL_EVENT_REQ_RSPED) {
            client_handle_req_rsped(msgs + i, hit_events);
            event_num++;
        } else if (msgs[i].event == POLL_EVENT_REQ_SENDED) {
            client_handle_req_sended(msgs + i, hit_events);
            event_num++;
        } else if (msgs[i].event == POLL_EVENT_REQ_ACKED_RSPED) {
            client_handle_req_acked_rsped(msgs + i, hit_events);
            event_num++;
        } else {
            LOG_PRINT_ERR("(other event:%u) \n", (uint32_t)msgs[i].event);
            if (msgs[i].event == POLL_EVENT_REQ_ERR) {
                LOG_PRINT_ERR("msg err_code is %u\n", msgs[i].req_err.err_code);
                g_allocator->put(msgs[i].req_err.args, msgs[i].req_err.args_sge_num, NULL);
                /* we need test abort */
                if (*hit_events == (1 << POLL_EVENT_REQ_ERR)) {
                    *hit_events -= (1 << POLL_EVENT_REQ_ERR);
                }
                event_num++;
            }
        }
    }

    return event_num;
}

static int client_process_req(uint32_t chid, uint64_t qh, char *name, uint32_t event_num, uint32_t events)
{
    uint32_t hit_event_num = event_num;
    uint32_t hit_events = events;
    struct urpc_poll_msg *msgs = calloc((int)hit_event_num, sizeof(struct urpc_poll_msg));
    if (msgs == NULL) {
        LOG_PRINT_ERR("msgs calloc failed\n");
        return URPC_FAIL;
    }

    struct urpc_poll_option poll_opt = {0};
    poll_opt.urpc_qh = qh;

    while (hit_event_num != 0) {
        if (strcmp(name, "send and read only ack and set timeout client sleep") == 0) {
            usleep(CLIENT_SLEEP_TIME);
            LOG_PRINT_ERR("client sleep 800ms finish\n");
        }

        int poll_num = urpc_func_poll(chid, &poll_opt, msgs, hit_event_num);
        if (poll_num < 0) {
            LOG_PRINT_ERR("poll error, error: %d\n", poll_num);
            free(msgs);
            return URPC_FAIL;
        }

        hit_event_num -= client_handle_poll_event(msgs, poll_num, &hit_events);
    }
    free(msgs);
    if (hit_events != 0) {
        LOG_PRINT_ERR("client_process_req err event:%u\n", hit_events);
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static int client_run_test_case(uint32_t chid, uint64_t qh,
    urpc_channel_qinfos_t *qinfos, uint64_t func_id, client_test_case_t *test_case)
{
    urpc_call_wr_t wr = {.func_id = func_id};
    urpc_sge_t sge_one = { 0 };
    int ret;

    urpc_call_option_t option = { .option_flag = FUNC_CALL_FLAG_L_QH, .l_qh = qh };
    if (test_case->func != NULL) {
        test_case->func(qh, qinfos, &option);
    }

    // only support FUNC_DEF_NULL
    if (option.func_defined != FUNC_DEF_NULL) {
        return URPC_SUCCESS;
    }

    uint32_t urpc_hdr_size = urpc_hdr_size_get(URPC_REQ, 0);
    uint32_t custom_head_size = sizeof(custom_head_t);
    uint32_t hdr_size = urpc_hdr_size + custom_head_size;
    
    ret = g_allocator->get(&wr.args, &wr.args_num, DEFAULT_MSG_SIZE, NULL);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT_ERR("g_allocator->get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        return ret;
    }

    if (strcmp(test_case->name, "read") == 0) {
        custom_head_t ecustom_head = {
            .dma_num = 1,
            .msg_type = WITH_DMA,
        };
        memcpy((char *)(uintptr_t)wr.args->addr + urpc_hdr_size, &ecustom_head, sizeof(ecustom_head));

        ret = g_allocator->get_raw_buf(&sge_one, DEFAULT_MSG_SIZE, NULL);
        if (ret != URPC_SUCCESS) {
            LOG_PRINT_ERR("g_allocator->get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
            goto FREE_WR_ARGS;
        }
        mem_seg_token_t token;
        ret = urpc_mem_seg_token_get(sge_one.mem_h, &token);
        if (ret != URPC_SUCCESS) {
            LOG_PRINT_ERR("urpc_mem_seg_token_get failed\n");
            goto FREE_SGE_ONE;
        }
        urpc_example_dma_t dma = {
            .address = sge_one.addr,
            .size = sge_one.length,
            .token_id = token.token_id,
            .token_value = token.token_value
        };
        
        memcpy((char *)(uintptr_t)wr.args->addr + hdr_size, &dma, sizeof(urpc_example_dma_t));
        (void)snprintf((char *)(uintptr_t)sge_one.addr, DEFAULT_MSG_SIZE, "hello server I'm %s!", test_case->name);
    } else {
        custom_head_t custom_head = {
            .dma_num = 0,
            .msg_type = WITHOUT_DMA,
        };
        memcpy((char *)(uintptr_t)wr.args->addr + urpc_hdr_size, &custom_head, sizeof(custom_head_t));

        (void)snprintf((char *)(uintptr_t)wr.args->addr + hdr_size, DEFAULT_MSG_SIZE - hdr_size,
            "hello server I'm %s!", test_case->name);
    }

    if (urpc_func_call(chid, &wr, &option) == URPC_U64_FAIL) {
        LOG_PRINT_ERR("urpc_func_call failed, errno:%d, message: %s.\n", errno, strerror(errno));
        goto FREE_SGE_ONE;
    }

    ret = client_process_req(chid, qh, test_case->name, test_case->hit_event_num, test_case->hit_events);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT_ERR("client_process_req failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        goto FREE_SGE_ONE;
    }

    return URPC_SUCCESS;

FREE_SGE_ONE:
    if (sge_one.addr != 0) {
        g_allocator->put_raw_buf(&sge_one, NULL);
    }
FREE_WR_ARGS:
    g_allocator->put(wr.args, wr.args_num, NULL);
    return ret;
}

int client_run(uint32_t chid, uint64_t qh, urpc_channel_qinfos_t *qinfos,
               uint64_t func_id, const urpc_allocator_t *allocator)
{
    g_allocator = allocator;
    for (uint32_t i = 0; i < (uint32_t)sizeof(g_test_cases) / sizeof(client_test_case_t); i++) {
        LOG_PRINT("------- client start test case: [%u] %s -------\n", i, g_test_cases[i].name);
        if (client_run_test_case(chid, qh, qinfos, func_id, &g_test_cases[i]) != URPC_SUCCESS) {
            LOG_PRINT_ERR("------- client run test case[%u] %s failed -------\n", i, g_test_cases[i].name);
            return URPC_FAIL;
        }
        LOG_PRINT("------- client finish test case: [%u] %s -------\n", i, g_test_cases[i].name);
    }
    return URPC_SUCCESS;
}
