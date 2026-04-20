/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq example of base feature functions
 */

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "umq_example_common.h"
#include "umq_example_base.h"

static const char *EXAMPLE_CLIENT_ENQUEUE_DATA = "hello, this is umq client";
static const char *EXAMPLE_SERVER_ENQUEUE_DATA = "hello, this is umq server";
static const char *g_log_level_to_str[UMQ_LOG_LEVEL_MAX] = {"EMERG", "ALERT", "CRIT", "ERROR", "WARNING",
                                                            "NOTICE", "INFO", "DEBUG"};

static void default_output(int level, char *log_msg)
{
    struct timeval tval;
    struct tm time;
    (void)gettimeofday(&tval, NULL);
    (void)localtime_r(&tval.tv_sec, &time);
    (void)fprintf(stdout, "%02d%02d %02d:%02d:%02d.%06ld|%s|%s", time.tm_mon + 1, time.tm_mday, time.tm_hour,
                  time.tm_min, time.tm_sec, (long)tval.tv_usec, g_log_level_to_str[level], log_msg);
}

int run_umq_example_server(struct urpc_example_config *cfg)
{
    uint32_t recv_size;
    int ret = example_init_umq(cfg);
    if (ret != 0) {
        LOG_PRINT_ERR("init umq failed\n");
        return -1;
    }

    if (server_accept(cfg->server_ip, cfg->tcp_port) != 0) {
        goto UNINIT;
    }

    ret = dev_eid_query(cfg, &cfg->src_eid);
    if (ret != 0) {
        goto DISCONNECT;
    }

    ret = server_exchange_data((uint8_t *)&cfg->src_eid, sizeof(umq_eid_t), (uint8_t *)&cfg->dst_eid, &recv_size);
    if (ret != 0 || recv_size != sizeof(umq_eid_t)) {
        LOG_PRINT_ERR("server exchange eid failed\n");
        goto DISCONNECT;
    }

    ret = server_exchange_data((uint8_t *)&cfg->src_port_id, sizeof(umq_port_id_t), (uint8_t *)&cfg->src_port_id,
                               &recv_size);
    if (ret != 0 || recv_size != sizeof(umq_port_id_t)) {
        LOG_PRINT_ERR("server exchange port_id failed\n");
        goto DISCONNECT;
    }

    uint32_t local_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t local_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    uint64_t umqh = example_create_umq(cfg, local_bind_info, &local_bind_info_size);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("create umq failed\n");
        goto UNINIT;
    }

    uint32_t remote_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t remote_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    ret = server_exchange_data(local_bind_info, local_bind_info_size, remote_bind_info, &remote_bind_info_size);
    if (ret < 0 || remote_bind_info_size > UMQ_MAX_BIND_INFO_SIZE) {
        LOG_PRINT_ERR("server exchange bind info failed\n");
        goto DESTROY;
    }

    ret = umq_bind(umqh, remote_bind_info, remote_bind_info_size);
    if (ret != UMQ_SUCCESS) {
        LOG_PRINT_ERR("server bind failed\n");
        goto DESTROY;
    }
    LOG_PRINT("server bind success\n");

    umq_log_config_t log_cfg = {
        .log_flag = UMQ_LOG_FLAG_FUNC | UMQ_LOG_FLAG_LEVEL,
        .func = default_output,
        .level = UMQ_LOG_LEVEL_DEBUG
    };

    if (umq_log_config_set(&log_cfg) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_log_config_set failed\n");
        goto UNBIND;
    }

    if (umq_log_config_get(&log_cfg) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_log_config_get failed\n");
        goto UNBIND;
    }
    LOG_PRINT("log level is %s\n", g_log_level_to_str[log_cfg.level]);

    if (example_dequeue_data(umqh, EXAMPLE_CLIENT_ENQUEUE_DATA, strlen(EXAMPLE_CLIENT_ENQUEUE_DATA)) != 0) {
        goto UNBIND;
    }

    if (example_enqueue_data(umqh, EXAMPLE_SERVER_ENQUEUE_DATA, strlen(EXAMPLE_SERVER_ENQUEUE_DATA))) {
        goto UNBIND;
    }

    usleep(EXAMPLE_SLEEP_TIME_US);
    ret = 0;

UNBIND:
    umq_unbind(umqh);
DESTROY:
    umq_destroy(umqh);
DISCONNECT:
    server_dsiconnect();
UNINIT:
    umq_uninit();
    return ret;
}

int run_umq_example_client(struct urpc_example_config *cfg)
{
    uint32_t recv_size;
    uint32_t local_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t local_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    int ret = example_init_umq(cfg);
    if (ret != 0) {
        LOG_PRINT_ERR("init umq failed\n");
        return -1;
    }

    ret = client_connect(cfg->server_ip, cfg->tcp_port);
    if (ret != 0) {
        goto UNINIT;
    }

    ret = dev_eid_query(cfg, &cfg->src_eid);
    if (ret != 0) {
        goto DISCONNECT;
    }

    ret = client_exchange_data((uint8_t *)&cfg->src_eid, sizeof(umq_eid_t), (uint8_t *)&cfg->dst_eid, &recv_size);
    if (ret != 0 || recv_size != sizeof(umq_eid_t)) {
        LOG_PRINT_ERR("client exchange eid failed\n");
        goto DISCONNECT;
    }

    ret = used_port_query(cfg);
    if (ret != 0) {
        goto DISCONNECT;
    }

    ret = client_exchange_data((uint8_t *)&cfg->dst_port_id, sizeof(umq_port_id_t), (uint8_t *)&cfg->dst_port_id,
                               &recv_size);
    if (ret != 0 || recv_size != sizeof(umq_port_id_t)) {
        LOG_PRINT_ERR("client exchange port_id failed\n");
        goto DISCONNECT;
    }

    uint64_t umqh = example_create_umq(cfg, local_bind_info, &local_bind_info_size);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("create umq failed\n");
        goto UNINIT;
    }

    uint32_t remote_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t remote_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    ret = client_exchange_data(local_bind_info, local_bind_info_size, remote_bind_info, &remote_bind_info_size);
    if (ret < 0 || remote_bind_info_size > UMQ_MAX_BIND_INFO_SIZE) {
        LOG_PRINT_ERR("client exchange bind info failed\n");
        goto DESTROY;
    }

    ret = umq_bind(umqh, remote_bind_info, remote_bind_info_size);
    if (ret != UMQ_SUCCESS) {
        LOG_PRINT_ERR("client bind failed\n");
        goto DESTROY;
    }
    LOG_PRINT("client bind success\n");
    sleep(1); // sleep 1s to wait for server ready

    if (example_enqueue_data(umqh, EXAMPLE_CLIENT_ENQUEUE_DATA, strlen(EXAMPLE_CLIENT_ENQUEUE_DATA))) {
        goto UNBIND;
    }

    if (example_dequeue_data(umqh, EXAMPLE_SERVER_ENQUEUE_DATA, strlen(EXAMPLE_CLIENT_ENQUEUE_DATA)) != 0) {
        goto UNBIND;
    }
    ret = 0;

UNBIND:
    umq_unbind(umqh);
DESTROY:
    umq_destroy(umqh);
DISCONNECT:
    client_dsiconnect();
UNINIT:
    umq_uninit();
    return ret;
}

int run_umq_example(struct urpc_example_config *cfg)
{
    if (cfg->instance_mode == CLIENT) {
        return run_umq_example_client(cfg);
    } else if (cfg->instance_mode == SERVER) {
        return run_umq_example_server(cfg);
    }

    return -1;
}
