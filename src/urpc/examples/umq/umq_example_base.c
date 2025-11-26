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
    int ret = -1;

    uint32_t local_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t local_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    uint64_t umqh = init_and_create_umq(cfg, local_bind_info, &local_bind_info_size);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("init and create umq failed\n");
        return -1;
    }

    uint32_t remote_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t remote_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    ret = server_exchange_bind_info(cfg->server_ip, cfg->tcp_port, local_bind_info,
        local_bind_info_size, remote_bind_info, &remote_bind_info_size);
    if (ret < 0 || remote_bind_info_size > UMQ_MAX_BIND_INFO_SIZE) {
        LOG_PRINT_ERR("server_exchange_bind_info failed\n");
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
    umq_uninit();
    return ret;
}

int run_umq_example_client(struct urpc_example_config *cfg)
{
    int ret = -1;
    uint32_t local_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t local_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    uint64_t umqh = init_and_create_umq(cfg, local_bind_info, &local_bind_info_size);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("init and create umq failed\n");
        return -1;
    }

    uint32_t remote_bind_info_size = UMQ_MAX_BIND_INFO_SIZE;
    uint8_t remote_bind_info[UMQ_MAX_BIND_INFO_SIZE] = {0};
    ret = client_exchange_bind_info(cfg->server_ip, cfg->tcp_port, local_bind_info,
        local_bind_info_size, remote_bind_info, &remote_bind_info_size);
    if (ret < 0 || remote_bind_info_size > UMQ_MAX_BIND_INFO_SIZE) {
        LOG_PRINT_ERR("client_exchange_bind_info failed\n");
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
