/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define keepalive probe management
 * Create: 2024-11-20
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "allocator.h"
#include "cp.h"
#include "dp.h"
#include "urpc_framework_api.h"
#include "urpc_lib_log.h"
#include "urpc_manage.h"
#include "func.h"

#include "keepalive.h"

#define URPC_KEEPALIVE_POLL_NUM 32
#define URPC_KEEPALIVE_SEND_RETRY_MAX 3
#define DEFAULT_POST_NUM 1
#define KEEPALIVE_CHECK_TIME_DEFAULT 18 // s
#define KEEPALIVE_CYCLE_TIME_DEFAULT 3 // s
#define DELAYED_RELEASE_RESOURCE_TIME 9 // s

static struct {
    uint64_t qh;
    urpc_keepalive_config_t cfg;
    urpc_epoll_event_t event;
} g_keepalive_probe_ctx;

static void keepalive_probe_poll_msg(void *args)
{
    int poll_num;
    struct urpc_poll_msg msgs[URPC_KEEPALIVE_POLL_NUM];
    struct urpc_poll_option poll_opt = {.urpc_qh = g_keepalive_probe_ctx.qh};

    bool call_wait = args == NULL ? false : *((bool *)args);
    queue_t *queue = (queue_t *)(uintptr_t)g_keepalive_probe_ctx.qh;
    if (URPC_UNLIKELY(call_wait && queue->ops->wait(queue, 1) < 0)) {
        return;
    }

    poll_num = urpc_func_poll(URPC_U32_FAIL, &poll_opt, msgs, URPC_KEEPALIVE_POLL_NUM);
    if (URPC_UNLIKELY(poll_num < 0)) {
        URPC_LIB_LIMIT_LOG_ERR("poll error, error: %d\n", poll_num);
        return;
    }

    if (URPC_UNLIKELY(poll_num == 0)) {
        return;
    }

    urpc_keepalive_process_msg(msgs, poll_num, &poll_opt);
}

static inline void keepalive_epoll_event_process(uint32_t events, struct urpc_epoll_event *e)
{
    bool call_wait = true;
    keepalive_probe_poll_msg((void *)&call_wait);
}

int urpc_keepalive_probe_init(urpc_keepalive_config_t *cfg)
{
    g_keepalive_probe_ctx.cfg = *cfg;

    urpc_qcfg_create_t queue_cfg = {
        .create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_MODE |
                       QCREATE_FLAG_CUSTOM_FLAG,
        .rx_buf_size = URPC_KEEPALIVE_MSG_SIZE,
        .rx_depth = cfg->q_depth,
        .tx_depth = cfg->q_depth,
        .mode = QUEUE_MODE_INTERRUPT,
        .custom_flag = QALLOCA_LARGE_SIZE_FLAG,
    };

    urpc_queue_trans_mode_t q_trans_mode = urpc_queue_default_trans_mode_get();
    uint16_t q_flag = URPC_QUEUE_FLAG_KEEPALIVE;
    g_keepalive_probe_ctx.qh = queue_create(q_trans_mode, &queue_cfg, q_flag);
    if (g_keepalive_probe_ctx.qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("urpc keepalive queue create failed\n");
        return URPC_FAIL;
    }
    if (post_rx_buf(g_keepalive_probe_ctx.qh, cfg->q_depth, URPC_KEEPALIVE_MSG_SIZE) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("keepalive post rx buffer failed\n");
    }

    int qfd = urpc_queue_interrupt_fd_get(g_keepalive_probe_ctx.qh);
    if (qfd < 0) {
        URPC_LIB_LOG_ERR("get keepalive qfd failed\n");
        goto DESTROY_QH;
    }

    int flags = fcntl(qfd, F_GETFL);
    if (flags < 0) {
        URPC_LIB_LOG_ERR("get keepalive qfd flag failed\n");
        goto DESTROY_QH;
    }
    int ret = fcntl(qfd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0) {
        URPC_LIB_LOG_ERR("set keepalive qfd nonblock failed, errno: %s\n", strerror(errno));
        goto DESTROY_QH;
    }

    g_keepalive_probe_ctx.event.fd = qfd;
    g_keepalive_probe_ctx.event.args = NULL;
    g_keepalive_probe_ctx.event.func = keepalive_epoll_event_process;
    g_keepalive_probe_ctx.event.events = EPOLLIN;
    if (urpc_mange_event_register(URPC_MANAGE_JOB_TYPE_LISTEN, &g_keepalive_probe_ctx.event) != URPC_SUCCESS) {
        goto DESTROY_QH;
    }

    urpc_manage_job_register(URPC_MANAGE_JOB_TYPE_LISTEN, keepalive_probe_poll_msg, NULL, 0);

    return URPC_SUCCESS;

DESTROY_QH:
    (void)urpc_queue_destroy(g_keepalive_probe_ctx.qh);

    return URPC_FAIL;
}

void urpc_keepalive_probe_uninit(void)
{
    (void)urpc_queue_destroy(g_keepalive_probe_ctx.qh);
    memset(&g_keepalive_probe_ctx, 0, sizeof(g_keepalive_probe_ctx));
}

uint64_t urpc_keepalive_queue_handle_get(void)
{
    return g_keepalive_probe_ctx.qh;
}

uint32_t urpc_keepalive_cycle_time_get(void)
{
    if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        return g_keepalive_probe_ctx.cfg.keepalive_cycle_time;
    }
    return KEEPALIVE_CYCLE_TIME_DEFAULT;
}

uint32_t urpc_keepalive_check_time_get(void)
{
    if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        return g_keepalive_probe_ctx.cfg.keepalive_check_time;
    }
    return KEEPALIVE_CHECK_TIME_DEFAULT;
}

uint32_t urpc_keepalive_release_time_get(void)
{
    if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        return g_keepalive_probe_ctx.cfg.delay_release_time;
    }
    return DELAYED_RELEASE_RESOURCE_TIME;
}

keepalive_callback_t urpc_keepalive_callback_get(void)
{
    return g_keepalive_probe_ctx.cfg.keepalive_callback;
}

static int urpc_keepalive_req_func_id_get(urpc_sge_t *args, uint32_t args_sge_num, uint64_t *func_id, bool is_tx)
{
    if (args == NULL || args_sge_num == 0) {
        URPC_LIB_LIMIT_LOG_ERR(
            "keepalive poll %s cqe args invalid, sge num %u\n", is_tx ? "send" : "recv", args_sge_num);
        return URPC_FAIL;
    }

    if (args[0].length < sizeof(urpc_req_head_t)) {
        URPC_LIB_LIMIT_LOG_ERR("keepalive poll %s cqe args invalid, sge num %u, msg length %u\n",
            is_tx ? "send" : "recv", args_sge_num, args[0].length);
        return URPC_FAIL;
    }

    uint64_t function = urpc_req_parse_function((urpc_req_head_t *)((uintptr_t)(args[0].addr)));
    if (args[0].length < URPC_KEEPALIVE_HDR_SIZE) {
        URPC_LIB_LIMIT_LOG_ERR("keepalive poll %s cqe args invalid, sge num %u, msg length %u\n",
            is_tx ? "send" : "recv", args_sge_num, args[0].length);
        return URPC_FAIL;
    }

    *func_id = function;

    return URPC_SUCCESS;
}

static void urpc_keepalive_process_send(struct urpc_poll_msg *msg)
{
    if (URPC_UNLIKELY(msg->req_rsped.args[0].length < URPC_KEEPALIVE_HDR_SIZE)) {
        return;
    }

    urpc_keepalive_id_t id = {.id = (uint64_t)(uintptr_t)msg->req_rsped.user_ctx};
    urpc_keepalive_head_t *header =
        (urpc_keepalive_head_t *)((uintptr_t)(msg->req_rsped.args[0].addr + sizeof(urpc_req_head_t)));
    if (urpc_keepalive_parse_rsp(header)) {
        // when logic server recv rsp ta_ack
        urpc_keepalive_task_timestamp_update(&id, true);
    }
}

static void urpc_keepalive_process_send_msg(
    urpc_allocator_t *allocator, urpc_allocator_option_t *option, struct urpc_poll_msg *msg)
{
    int ret;
    uint64_t function;
    ret = urpc_keepalive_req_func_id_get(msg->req_rsped.args, msg->req_rsped.args_sge_num, &function, true);
    if (ret != URPC_SUCCESS) {
        goto EXIT;
    }

    urpc_keepalive_process_send(msg);

EXIT:
    (void)allocator->put(msg->req_rsped.args, msg->req_rsped.args_sge_num, option);
}

static void urpc_keepalive_server_reply(urpc_allocator_t *allocator, urpc_allocator_option_t *option,
    uint32_t client_chid, uint32_t mapped_server_chid, struct urpc_poll_msg *msg)
{
    uint32_t server_chid = server_channel_id_map_lookup(mapped_server_chid);
    // get remote keepalive queue
    urpc_queue_flag_t flag = {.is_remote = URPC_TRUE, .is_keepalive = URPC_TRUE};
    queue_t *remote_q = server_channel_search_remote_queue_by_flag(server_chid, flag);
    if (remote_q == NULL) {
        (void)allocator->put(msg->req_recved.args, msg->req_recved.args_sge_num, option);
        URPC_LIB_LIMIT_LOG_ERR("server channel[%u] keepalive send reply get remote queue failed\n", server_chid);
        return;
    }

    urpc_keepalive_id_t id = {.client_chid = client_chid, .server_chid = server_chid};
    uint64_t func_id = urpc_req_parse_function((urpc_req_head_t *)(uintptr_t)msg->req_rsped.args[0].addr);
    urpc_call_wr_t wr = {.func_id = func_id, .args = msg->req_recved.args, .args_num = msg->req_recved.args_sge_num};
    urpc_call_option_t call_option = {
        .option_flag = FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH | FUNC_CALL_FLAG_CALL_MODE | FUNC_CALL_FLAG_USER_CTX,
        .l_qh = urpc_keepalive_queue_handle_get(),
        .r_qh = (uint64_t)(uintptr_t)remote_q,
        .call_mode = FUNC_CALL_MODE_EARLY_RSP,
        .user_ctx = (void *)(uintptr_t)id.id};

    int ret;
    for (int i = 0; i < URPC_KEEPALIVE_SEND_RETRY_MAX; i++) {
        ret = urpc_func_call_early_rsp(mapped_server_chid, &wr, &call_option);
        if (ret != URPC_FAIL || (errno != URPC_ERR_EAGAIN && errno != EAGAIN)) {
            break;
        }
    }
    server_channel_unlock(server_chid);

    if (ret == URPC_FAIL) {
        // if send failed, rx buffer freed here, else rx buffer will be freed in tx cqe
        (void)allocator->put(msg->req_recved.args, msg->req_recved.args_sge_num, option);
    } else {
        URPC_LIB_LIMIT_LOG_DEBUG(
            "server channel[%u] process keepalive reply %u bytes\n", server_chid, msg->req_recved.args[0].length);
    }
}

static void urpc_keepalive_recv_input_msg(
    urpc_keepalive_id_t *id, struct urpc_poll_msg *msg, uint32_t fixed_size, bool is_server)
{
    if (msg->req_recved.args[0].length <= fixed_size) {
        // if no input msg
        return;
    }

    urpc_keepalive_event_info_t info = {
        .user_msg = {
            .addr = (uintptr_t)(msg->req_recved.args[0].addr + fixed_size),
            .length = (msg->req_recved.args[0].length - fixed_size),
        }
    };
    if (urpc_keepalive_task_entry_info_get(id, is_server, &info) != URPC_SUCCESS) {
        URPC_LIB_LIMIT_LOG_ERR(
            "find user ctx in server channel[%u] failed, client channel[%u] input msg length %u\n", id->server_chid,
            id->client_chid, msg->req_recved.args[0].length - fixed_size);
        return;
    }

    g_keepalive_probe_ctx.cfg.keepalive_callback(URPC_KEEPALIVE_MSG_RECEIVED, info);
    URPC_LIB_LOG_INFO("recv keepalive input msg %u bytes from client channel[%u] to server channel[%u]\n",
        info.user_msg.length, id->client_chid, id->server_chid);
}

static void urpc_keepalive_process_recv(urpc_allocator_t *allocator, urpc_allocator_option_t *option,
    urpc_poll_option_t *poll_opt, struct urpc_poll_msg *msg)
{
    urpc_req_head_t *req_head = (urpc_req_head_t *)(uintptr_t)msg->req_rsped.args[0].addr;
    urpc_keepalive_head_t *header =
        (urpc_keepalive_head_t *)((uintptr_t)(msg->req_rsped.args[0].addr + sizeof(urpc_req_head_t)));
    uint32_t server_chid = urpc_keepalive_parse_server_channel(header);
    urpc_keepalive_id_t id = {.client_chid = urpc_req_parse_client_channel(req_head), .server_chid = server_chid};

    if (urpc_keepalive_parse_rsp(header) == URPC_FALSE) {
        id.server_chid = server_channel_id_map_lookup(server_chid);
        urpc_keepalive_recv_input_msg(&id, msg, URPC_KEEPALIVE_HDR_SIZE, true);

        (void)urpc_func_return(poll_opt->urpc_qh, msg->req_recved.req_ctx, NULL, NULL);
        URPC_LIB_LIMIT_LOG_DEBUG(
            "server process keepalive req %u bytes from client channel[%u] to server channel[%u]\n",
            msg->req_recved.args[0].length, id.client_chid, id.server_chid);

        urpc_keepalive_fill_rsp(header, URPC_TRUE);
        msg->req_recved.args[0].length = (uint32_t)(URPC_KEEPALIVE_HDR_SIZE);
        urpc_keepalive_server_reply(allocator, option, id.client_chid, server_chid, msg);
        return;
    }

    URPC_LIB_LIMIT_LOG_DEBUG("client process keepalive rsp %u bytes from server channel[%u] to client channel[%u]\n",
        msg->req_recved.args[0].length, id.server_chid, id.client_chid);

    // when logic client recv rsp
    urpc_keepalive_task_timestamp_update(&id, false);
    urpc_keepalive_recv_input_msg(&id, msg, URPC_KEEPALIVE_HDR_SIZE, false);

    // client process rsp, put rx buffer
    (void)urpc_func_return(poll_opt->urpc_qh, msg->req_recved.req_ctx, NULL, NULL);
    (void)allocator->put(msg->req_recved.args, msg->req_recved.args_sge_num, option);
}

// server recv keepalive req, need to send rsp(early-rsp req)
static void urpc_keepalive_process_recv_msg(urpc_allocator_t *allocator, urpc_allocator_option_t *option,
    urpc_poll_option_t *poll_opt, struct urpc_poll_msg *msg)
{
    int ret;
    uint64_t function;

    ret = urpc_keepalive_req_func_id_get(msg->req_recved.args, msg->req_recved.args_sge_num, &function, false);
    if (ret != URPC_SUCCESS) {
        (void)allocator->put(msg->req_recved.args, msg->req_recved.args_sge_num, option);
        return;
    }

    urpc_keepalive_process_recv(allocator, option, poll_opt, msg);
}

static void urpc_keepalive_process_default_msg(
    urpc_allocator_t *allocator, urpc_allocator_option_t *option, struct urpc_poll_msg *msg)
{
    if (msg->event == POLL_EVENT_REQ_ERR) {
        (void)process_cr_err(g_keepalive_probe_ctx.qh, msg->req_err.err_code);
        if (msg->req_err.args == NULL || msg->req_err.args_sge_num == 0 ||
            msg->req_err.args[0].length < sizeof(urpc_req_head_t)) {
            URPC_LIB_LIMIT_LOG_ERR("keepalive msg send failed, sge num %u, UDMA(UB)/URMA TX reports err_code: %u\n",
                msg->req_err.args_sge_num, msg->req_err.err_code);
            (void)allocator->put(msg->req_err.args, msg->req_err.args_sge_num, option);
            return;
        }

        URPC_LIB_LIMIT_LOG_ERR(
            "keepalive msg send failed, sge num %u, length %u, UDMA(UB)/URMA TX reports err_code: %u\n",
            msg->req_err.args_sge_num, msg->req_err.args[0].length, msg->req_err.err_code);
        // keepalive req/rsp send error, release rx buffer
        (void)allocator->put(msg->req_err.args, msg->req_err.args_sge_num, option);

        return;
    }

    if (msg->event == POLL_EVENT_ERR) {
        (void)urpc_queue_modify(g_keepalive_probe_ctx.qh, QUEUE_STATUS_FAULT);
        URPC_LIB_LIMIT_LOG_ERR("keepalive get error event (%d)\n", (int)msg->event_err.err_event);
        return;
    }

    // keepalive will never get these events
    URPC_LIB_LIMIT_LOG_ERR("keepalive get unexpected event (%d)\n", msg->event);
}

void urpc_keepalive_process_msg(struct urpc_poll_msg *msgs, int poll_num, urpc_poll_option_t *poll_opt)
{
    urpc_allocator_option_t option = {.qcustom_flag = QALLOCA_LARGE_SIZE_FLAG};
    urpc_allocator_t *allocator = default_allocator_get();
    if (allocator == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get allocator failed\n");
        return;
    }

    for (int i = 0; i < poll_num; i++) {
        if (msgs[i].event == POLL_EVENT_REQ_RSPED) {
            urpc_keepalive_process_send_msg(allocator, &option, &msgs[i]);
        } else if (msgs[i].event == POLL_EVENT_REQ_RECVED) {
            urpc_keepalive_process_recv_msg(allocator, &option, poll_opt, &msgs[i]);
        } else {
            urpc_keepalive_process_default_msg(allocator, &option, &msgs[i]);
        }
    }
}

static int urpc_keepalive_sge_get(urpc_call_wr_t *wr)
{
    urpc_allocator_t *allocator = default_allocator_get();
    if (allocator == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get allocator failed\n");
        return URPC_FAIL;
    }

    urpc_allocator_option_t opt = {.qcustom_flag = QALLOCA_LARGE_SIZE_FLAG};
    if (allocator->get(&wr->args, &wr->args_num, URPC_KEEPALIVE_MSG_SIZE, &opt)) {
        URPC_LIB_LIMIT_LOG_ERR("allocator->get failed, errno:%d\n", errno);
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static void urpc_keepalive_sge_put(urpc_call_wr_t *wr)
{
    urpc_allocator_t *allocator = default_allocator_get();
    if (allocator == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get allocator failed\n");
        return;
    }

    urpc_allocator_option_t opt = {.qcustom_flag = QALLOCA_LARGE_SIZE_FLAG};
    (void)allocator->put(wr->args, wr->args_num, &opt);
}

static int urpc_keepalive_sge_construct(urpc_keepalive_task_entry_t *entry, urpc_call_wr_t *wr)
{
    if (urpc_keepalive_sge_get(wr) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    wr->args[0].length = (uint32_t)URPC_KEEPALIVE_HDR_SIZE;
    wr->func_id = URPC_KEEPALIVE_FUNCTION_ID;

    queue_local_t *local_q = (queue_local_t *)(uintptr_t)urpc_keepalive_queue_handle_get();
    // urpc_req_head_t will be filled in urpc_func_call
    urpc_keepalive_head_t *hdr = (urpc_keepalive_head_t *)((uintptr_t)(wr->args[0].addr + sizeof(urpc_req_head_t)));
    urpc_keepalive_fill_head(hdr, URPC_KEEPALIVE_VERSION, URPC_FALSE, local_q->qid, entry->client_task_id.server_chid);

    return URPC_SUCCESS;
}

int urpc_keepalive_request_send(urpc_keepalive_task_entry_t *entry)
{
    urpc_channel_info_t *channel = channel_get(entry->client_task_id.client_chid);
    if (channel == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get manage channel[%u] failed\n", entry->client_task_id.client_chid);
        return URPC_FAIL;
    }

    // get remote keepalive queue
    urpc_queue_flag_t flag = {.is_remote = URPC_TRUE, .is_keepalive = URPC_TRUE};
    queue_t *r_q = channel_get_remote_queue_by_flag(channel, flag);
    if (r_q == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("get manage channel[%u] remote queue failed\n", entry->client_task_id.client_chid);
        return URPC_FAIL;
    }

    urpc_call_option_t option = {
        .option_flag = FUNC_CALL_FLAG_CALL_MODE | FUNC_CALL_FLAG_L_QH | FUNC_CALL_FLAG_R_QH | FUNC_CALL_FLAG_USER_CTX,
        .call_mode = FUNC_CALL_MODE_EARLY_RSP,
        .l_qh = urpc_keepalive_queue_handle_get(),
        .r_qh = (uint64_t)(uintptr_t)r_q,
        .user_ctx = (void *)(uintptr_t)entry->client_task_id.id};

    urpc_call_wr_t wr = {0};
    if (urpc_keepalive_sge_construct(entry, &wr) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    uint64_t ret;
    uint32_t msg_size = wr.args[0].length;
    for (int i = 0; i < URPC_KEEPALIVE_SEND_RETRY_MAX; i++) {
        ret = urpc_func_call(entry->client_task_id.client_chid, &wr, &option);
        if (ret != URPC_U64_FAIL || (errno != URPC_ERR_EAGAIN && errno != EAGAIN)) {
            break;
        }
    }

    if (ret == URPC_U64_FAIL) {
        urpc_keepalive_sge_put(&wr);
        URPC_LIB_LIMIT_LOG_ERR("manage channel[%u] urpc_func_call to remote[%u] failed, errno:%d\n",
            entry->client_task_id.client_chid, entry->client_task_id.server_chid, errno);
        return URPC_FAIL;
    }

    URPC_LIB_LIMIT_LOG_DEBUG("keepalive send req %u bytes, local_chid[%u], remote_chid[%u]\n", msg_size,
        entry->client_task_id.client_chid, entry->client_task_id.server_chid);

    return URPC_SUCCESS;
}
