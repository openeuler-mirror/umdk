/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs alarm implementation file
 * Author: Wuyuyan
 * Create: 2024-05-06
 * Note:
 * History:
 */
#include "uvs_types.h"
#include "tpsa_log.h"
#include "ub_hash.h"
#include "uvs_private_api.h"
#include "tpsa_worker.h"
#include "uvs_alarm.h"

int uvs_handle_nl_create_vtp_task_retry(tpsa_worker_t *worker, uint8_t retry_num_left, void *arg)
{
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .genl_ctx = &worker->genl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
        .fd = -1
    };

    uvs_nl_create_vtp_alarm_arg_t *nl_arg = (uvs_nl_create_vtp_alarm_arg_t *)arg;
    if (nl_arg->nl_msg.msg_type != TPSA_NL_FE2TPF_REQ) {
        TPSA_LOG_ERR("Invalid msg_type: %d.\n", nl_arg->nl_msg.msg_type);
        return -1;
    }
    tpsa_nl_req_host_t *tmsg = (tpsa_nl_req_host_t *)nl_arg->nl_msg.payload;
    if (tmsg->req.opcode != TPSA_MSG_CREATE_VTP) {
        TPSA_LOG_ERR("Invalid req opcode: %d.\n", tmsg->req.opcode);
        return -1;
    }
    return uvs_create_vtp(&ctx, &nl_arg->nl_msg, retry_num_left);
}

int uvs_handle_sock_create_vtp_req_task_retry(tpsa_worker_t *worker, uint8_t retry_num_left, void *arg)
{
    uvs_sock_create_vtp_req_alarm_arg_t *sock_arg = (uvs_sock_create_vtp_req_alarm_arg_t *)arg;
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .genl_ctx = &worker->genl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
        .fd = sock_arg->fd
    };

    if (sock_arg->sock_msg.msg_type != TPSA_CREATE_REQ) {
        TPSA_LOG_ERR("Invalid msg_type: %d.\n", sock_arg->sock_msg.msg_type);
        return -1;
    }
    /* msg is freed when removing task */
    return uvs_handle_create_vtp_req(&ctx, &sock_arg->sock_msg, retry_num_left);
}

static uvs_alarm_t g_uvs_alarm[] = {
    {UVS_NL_CREATE_VTP_ALARM, UVS_EXPIRATION_TIME_DUR, UVS_ALARM_MAX_RETRY_TIME,
        uvs_handle_nl_create_vtp_task_retry},
    {UVS_SOCK_CREATE_VTP_REQ_ALARM, UVS_EXPIRATION_TIME_DUR, UVS_ALARM_MAX_RETRY_TIME,
        uvs_handle_sock_create_vtp_req_task_retry}
};

/* add a new alarm into the list */
int uvs_set_alarm(tpsa_worker_t *worker, uvs_alarm_type_t type, void *arg)
{
    uvs_alarm_node_t *new_alarm = (uvs_alarm_node_t *)calloc(1, (sizeof(uvs_alarm_node_t)));
    if (new_alarm == NULL) {
        TPSA_LOG_ERR("Fail to malloc new alarm.\n");
        return -1;
    }
    new_alarm->type = type;
    new_alarm->arg = arg;
    new_alarm->cb = g_uvs_alarm[type].cb;
    struct timespec cur_time;
    (void)clock_gettime(CLOCK_MONOTONIC, &cur_time);
    new_alarm->set_ts = cur_time.tv_sec * MS_PER_SEC + cur_time.tv_nsec / NS_PER_MS;
    new_alarm->exp_ts = g_uvs_alarm[type].exp_time_dur + new_alarm->set_ts;
    new_alarm->retry_num_left = g_uvs_alarm[type].max_retry_num;
    ub_list_push_back(&worker->table_ctx.alarm_list, &new_alarm->node);
    return 0;
}

int uvs_set_nl_create_vtp_alarm(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    /* free when removing task */
    uvs_nl_create_vtp_alarm_arg_t *arg =
        (uvs_nl_create_vtp_alarm_arg_t *)calloc(1, (sizeof(uvs_nl_create_vtp_alarm_arg_t)));
    if (arg == NULL) {
        TPSA_LOG_ERR("Failed to alloc arg for create_vtp task.\n");
        return -1;
    }
    (void)memcpy(&arg->nl_msg, msg, sizeof(tpsa_nl_msg_t));
    if (uvs_set_alarm(worker, UVS_NL_CREATE_VTP_ALARM, (void *)arg) != 0) {
        free(arg);
        TPSA_LOG_ERR("failed to set alarm for create_vtp task, abandon create_vtp message.\n");
        return -1;
    }
    return 0;
}

void uvs_set_sock_create_vtp_req_alarm(tpsa_worker_t *worker, tpsa_sock_msg_t *msg, int fd)
{
    /* free when removing task */
    uvs_sock_create_vtp_req_alarm_arg_t *arg =
        (uvs_sock_create_vtp_req_alarm_arg_t *)calloc(1, (sizeof(uvs_sock_create_vtp_req_alarm_arg_t)));
    if (arg == NULL) {
        TPSA_LOG_ERR("Failed to alloc arg for create_vtp_req task.\n");
        return;
    }
    (void)memcpy(&arg->sock_msg, msg, sizeof(tpsa_sock_msg_t));
    arg->fd = fd;
    if (uvs_set_alarm(worker, UVS_SOCK_CREATE_VTP_REQ_ALARM, (void *)arg) != 0) {
        free(arg);
        TPSA_LOG_ERR("failed to set alarm for create vtp req task, abandon create vtp message.\n");
    }
    return;
}

static bool is_uvs_timer_expired(uvs_alarm_node_t *cur_alarm)
{
    struct timespec cur_ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &cur_ts);
    uint64_t cur_ts_ms = cur_ts.tv_sec * MS_PER_SEC + cur_ts.tv_nsec / NS_PER_MS;
    return (cur_alarm->exp_ts <= cur_ts_ms);
}

void uvs_process_expired_timer(tpsa_worker_t *worker)
{
    uvs_alarm_node_t *cur_alarm = NULL;
    int cnt = 0;
    int ret = 0;
    UB_LIST_FIRST_NODE(cur_alarm, node, &worker->table_ctx.alarm_list);
    while (cnt < UVS_MAX_ALARM_EXEC_CNT && cur_alarm != NULL && is_uvs_timer_expired(cur_alarm)) {
        --cur_alarm->retry_num_left;
        ret = cur_alarm->cb(worker, cur_alarm->retry_num_left, cur_alarm->arg);
        /* Failure: failed due to other reason or return -EAGAIN at the last retry */
        if ((ret < 0 && ret != -EAGAIN) || (cur_alarm->retry_num_left == 0 && ret == -EAGAIN)) {
            TPSA_LOG_ERR("Failed to process expired timer, retry_num_left: %hu, ret: %d.\n",
                cur_alarm->retry_num_left, ret);
        }
        /* Remove alarm */
        ub_list_remove(&cur_alarm->node);
        /* Update alarm: max_retry_num is not exceeded and return -EAGAIN for current retry */
        if (cur_alarm->retry_num_left != 0 && ret == -EAGAIN) {
            struct timespec cur_time;
            (void)clock_gettime(CLOCK_MONOTONIC, &cur_time);
            cur_alarm->set_ts = cur_time.tv_sec * MS_PER_SEC + cur_time.tv_nsec / NS_PER_MS;
            cur_alarm->exp_ts = g_uvs_alarm[cur_alarm->type].exp_time_dur + cur_alarm->set_ts;
            ub_list_push_back(&worker->table_ctx.alarm_list, &cur_alarm->node);
        } else {
            /* task is assumed as failed or successful */
            free(cur_alarm->arg);
            cur_alarm->arg = NULL;
            free(cur_alarm);
        }
        UB_LIST_FIRST_NODE(cur_alarm, node, &worker->table_ctx.alarm_list);
        ++cnt;
    }
}
