/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: perftest for umq
 * Create: 2025-8-27
 */

#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>

#include "umq_api.h"
#include "umq_pro_api.h"
#include "umq_perftest_param.h"
#include "perftest_util.h"
#include "perftest_thread.h"
#include "perftest_latency.h"
#include "perftest_qps.h"
#include "umq_perftest_qps.h"
#include "umq_perftest_latency.h"

#define PERFTEST_STR_SIZE 1024

typedef struct umq_perftest_worker_arg {
    perftest_thread_arg_t thd_arg;
    umq_perftest_config_t *cfg;
    uint64_t umqh;
    union {
        umq_perftest_latency_arg_t lat_arg;
        umq_perftest_qps_arg_t qps_arg;
    };
} umq_perftest_worker_arg_t;

// perftest resources
static struct umq_perftest_ctx {
    umq_perftest_worker_arg_t *args;
    umq_perftest_config_t cfg;

    uint64_t umqh;
    int fd;
    int accept_fd;
    volatile bool force_quit;
} g_umq_perftest_ctx = {0};

void perftest_force_quit(void)
{
    g_umq_perftest_ctx.force_quit = true;
}

bool is_perftest_force_quit(void)
{
    return g_umq_perftest_ctx.force_quit;
}

//-------------------------------------------client&server functions--------------------------------------------------
static int fill_dev_info(umq_dev_assign_t *dev_info, umq_perftest_config_t *cfg)
{
    uint32_t addr;
    if (strlen(cfg->config.dev_name) != 0) {
        LOG_PRINT("umq perftest init with dev: %s\n", cfg->config.dev_name);
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
        memcpy(dev_info->dev.dev_name, cfg->config.dev_name, strlen(cfg->config.dev_name));
    } else if (inet_pton(AF_INET, cfg->config.local_ip, &addr) == 1) {
        LOG_PRINT("umq perftest init with ipv4: %s\n", cfg->config.local_ip);
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_IPV4;
        memcpy(dev_info->ipv4.ip_addr, cfg->config.local_ip, strlen(cfg->config.local_ip));
    } else {
        LOG_PRINT("umq perftest init with ipv6: %s\n", cfg->config.local_ip);
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_IPV6;
        memcpy(dev_info->ipv6.ip_addr, cfg->config.local_ip, strlen(cfg->config.local_ip));
    }

    return 0;
}

typedef struct feature_and_string {
    uint32_t feature;
    const char *str;
} feature_and_string_t;

static void umq_perftest_show_feature(uint32_t feature)
{
    feature_and_string_t array[] = {
        // UMQ_FEATURE_API_BASE need special handling
        {.feature = UMQ_FEATURE_API_PRO, .str = "UMQ_FEATURE_API_PRO"},
        {.feature = UMQ_FEATURE_ENABLE_TOKEN_POLICY, .str = "UMQ_FEATURE_ENABLE_TOKEN_POLICY"},
        {.feature = UMQ_FEATURE_ENABLE_STATS, .str = "UMQ_FEATURE_ENABLE_STATS"},
        {.feature = UMQ_FEATURE_ENABLE_PERF, .str = "UMQ_FEATURE_ENABLE_PERF"},
        {.feature = UMQ_FEATURE_ENABLE_FLOW_CONTROL, .str = "UMQ_FEATURE_ENABLE_FLOW_CONTROL"},
    };

    char feature_str[PERFTEST_STR_SIZE] = {0};
    int str_len = 0;
    int ret = 0;

    if ((feature & UMQ_FEATURE_API_PRO) == 0) {
        ret = snprintf(feature_str, PERFTEST_STR_SIZE, "%s", "UMQ_FEATURE_API_BASE");
        if (ret < 0) {
            LOG_PRINT("set feature string: UMQ_FEATURE_API_BASE failed\n");
            return;
        }
    }

    str_len += ret;
    for (uint32_t i = 0; i < sizeof(array) / sizeof(feature_and_string_t); i++) {
        if ((feature & array[i].feature) == 0) {
            continue;
        }

        if (str_len > 0) {
            ret = snprintf(feature_str + str_len, PERFTEST_STR_SIZE - str_len, " | %s", array[i].str);
        } else {
            ret = snprintf(feature_str + str_len, PERFTEST_STR_SIZE - str_len, " %s", array[i].str);
        }
        if (ret < 0) {
            LOG_PRINT("set feature string: %s failed\n", array[i].str);
            return;
        }
        str_len += ret;
    }
    LOG_PRINT("umq init with feature: %s\n", feature_str);
}

static int umq_perftest_init_umq(umq_perftest_config_t *cfg)
{
    umq_init_cfg_t *umq_config = (umq_init_cfg_t *)calloc(1, sizeof(*umq_config));
    if (umq_config == NULL) {
        LOG_PRINT("calloc umq_config failed\n");
        return -1;
    }
    umq_config->buf_mode = cfg->buf_mode;
    umq_config->feature = cfg->feature;
    umq_config->flow_control.use_atomic_window = cfg->use_atomic_window;
    umq_config->flow_control.notify_interval =
        cfg->config.case_type == PERFTEST_CASE_LAT ? (cfg->config.rx_depth >> 1) : 0;
    umq_config->headroom_size = 0;
    umq_config->io_lock_free = true;
    umq_config->trans_info_num = 1;
    umq_config->trans_info[0].trans_mode = (umq_trans_mode_t)cfg->trans_mode;
    umq_config->cna = cfg->cna;
    umq_config->ubmm_eid = cfg->deid;
    umq_config->eid_idx = cfg->eid_idx;
    if (fill_dev_info(&umq_config->trans_info[0].dev_info, cfg) != 0) {
        free(umq_config);
        return -1;
    }

    if (umq_init(umq_config) != UMQ_SUCCESS) {
        LOG_PRINT("umq_init failed\n");
        free(umq_config);
        return -1;
    }

    umq_perftest_show_feature(umq_config->feature);

    free(umq_config);
    return 0;
}

static int umq_perftest_create_umqh(umq_perftest_config_t *cfg)
{
    umq_create_option_t option = {
        .trans_mode = (umq_trans_mode_t)cfg->trans_mode,
        .create_flag = UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_TX_BUF_SIZE |
            UMQ_CREATE_FLAG_RX_DEPTH | UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_QUEUE_MODE,
        .rx_buf_size = cfg->config.size,
        .tx_buf_size = cfg->config.size,
        .rx_depth = cfg->config.rx_depth,
        .tx_depth = cfg->config.tx_depth,
        .mode = cfg->config.interrupt ? UMQ_MODE_INTERRUPT : UMQ_MODE_POLLING,
    };
    char *name = cfg->config.instance_mode == PERF_INSTANCE_SERVER ? "umq_perftest_server" : "umq_perftest_client";
    (void)sprintf(option.name, "%s", name);
    if (fill_dev_info(&option.dev_info, cfg) != 0) {
        LOG_PRINT("dev info copy failed\n");
        return -1;
    }

    uint64_t umqh = umq_create(&option);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT("umq_create failed\n");
        return -1;
    }
    g_umq_perftest_ctx.umqh = umqh;

    return 0;
}

static int umq_perftest_post_rx(umq_perftest_config_t *cfg)
{
    if ((cfg->feature & UMQ_FEATURE_API_PRO) == 0) {
        return 0;
    }

    // pro mode，need alloc rx buf
    uint32_t require_rx_count = cfg->config.rx_depth;
    uint32_t cur_batch_count = 0;
    umq_buf_t *bad_buf = NULL;
    do {
        cur_batch_count = require_rx_count > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : require_rx_count;

        umq_buf_t *buf = umq_buf_alloc(cfg->config.size, cur_batch_count, UMQ_INVALID_HANDLE, NULL);
        if (buf == NULL) {
            LOG_PRINT("alloc buf failed\n");
            return -1;
        }

        if (umq_post(g_umq_perftest_ctx.umqh, buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
            LOG_PRINT("post rx failed\n");
            umq_buf_free(bad_buf);
            return -1;
        }

        require_rx_count -= cur_batch_count;
    } while (require_rx_count > 0);
    return 0;
}

static inline void umq_perftest_server_qps_work_load(perftest_thread_arg_t *args)
{
    umq_perftest_worker_arg_t *arg = (umq_perftest_worker_arg_t *)args;
    arg->qps_arg.cfg = arg->cfg;
    umq_perftest_run_qps(arg->umqh, &arg->qps_arg);
}

static inline void umq_perftest_latency_work_load(perftest_thread_arg_t *args)
{
    umq_perftest_worker_arg_t *arg = (umq_perftest_worker_arg_t *)args;
    arg->lat_arg.cfg = arg->cfg;
    umq_perftest_run_latency(arg->umqh, &arg->lat_arg);
}

static int umq_perftest_start_test_threads(umq_perftest_config_t *cfg)
{
    g_umq_perftest_ctx.args = (umq_perftest_worker_arg_t *)calloc(1, sizeof(umq_perftest_worker_arg_t));
    if (g_umq_perftest_ctx.args == NULL) {
        LOG_PRINT("malloc perftest ctx args failed\n");
        return -1;
    }

    if (cfg->config.case_type == PERFTEST_CASE_LAT) {
        g_umq_perftest_ctx.args->thd_arg.func = umq_perftest_latency_work_load;
    } else {
        g_umq_perftest_ctx.args->thd_arg.func = umq_perftest_server_qps_work_load;
    }

    g_umq_perftest_ctx.args->thd_arg.state = PERFTEST_THREAD_INIT;
    g_umq_perftest_ctx.args->thd_arg.cpu_affinity = cfg->config.cpu_affinity;
    g_umq_perftest_ctx.args->cfg = cfg;
    g_umq_perftest_ctx.args->umqh = g_umq_perftest_ctx.umqh;
    if (perftest_worker_thread_create(&g_umq_perftest_ctx.args->thd_arg) != 0) {
        LOG_PRINT("create worker thread failed\n");
        free(g_umq_perftest_ctx.args);
        g_umq_perftest_ctx.args = NULL;
        return -1;
    }

    return 0;
}

static void umq_perftest_wait(perftest_config_t *cfg)
{
    if (cfg->case_type == PERFTEST_CASE_LAT) {
        perftest_print_latency(get_perftest_latency_ctx());
    } else {
        perftest_qps_ctx_t *ctx = get_perftest_qps_ctx();
        ctx->show_thread = false;
        ctx->size_total = cfg->size;
        ctx->thread_num = 1;
        perftest_print_qps(ctx);
    }
}

static void umq_perftest_stop_test_threads(perftest_config_t *cfg)
{
    if (g_umq_perftest_ctx.args == NULL) {
        return;
    }

    perftest_worker_thread_destroy(&g_umq_perftest_ctx.args->thd_arg);
    free(g_umq_perftest_ctx.args);
    g_umq_perftest_ctx.args = NULL;
}

static int umq_perftest_client_exchange_data(void)
{
    // 客户端先发送本端bind信息，然后接收server端的bind信息，然后进行绑定
    exchange_info_t local_info = {0};
    local_info.msg_len = umq_bind_info_get(g_umq_perftest_ctx.umqh, local_info.data, MAX_INFO_SIZE);
    if (local_info.msg_len == 0) {
        LOG_PRINT("umq_bind_info_get failed\n");
        return -1;
    }

    if (send_exchange_data(g_umq_perftest_ctx.fd, &local_info) < 0) {
        return -1;
    }
    LOG_PRINT("client send bind info succeed, local bind info size: %u\n", local_info.msg_len);

    exchange_info_t remote_info = {0};
    if (recv_exchange_data(g_umq_perftest_ctx.fd, &remote_info) != 0) {
        return -1;
    }

    if (umq_bind(g_umq_perftest_ctx.umqh, remote_info.data, remote_info.msg_len) != 0) {
        LOG_PRINT("client bind failed, remote bind info size: %u\n", remote_info.msg_len);
        return -1;
    }

    LOG_PRINT("client bind succeed\n");
    return 0;
}

static int umq_perftest_run_client(umq_perftest_config_t *cfg)
{
    int ret = -1;

    // init
    if (umq_perftest_init_umq(cfg) != 0) {
        return -1;
    }

    // create umqh
    if (umq_perftest_create_umqh(cfg) != 0) {
        goto UNINIT;
    }

    // create socket for exchange info and sync，and attach server
    g_umq_perftest_ctx.fd = perftest_create_client_socket(&cfg->config);
    if (g_umq_perftest_ctx.fd < 0) {
        goto DESTROY;
    }

    // exchange bind info and bind
    ret = umq_perftest_client_exchange_data();
    if (ret != 0) {
        goto CLOSE_SOC;
    }

    // post rx
    ret = umq_perftest_post_rx(cfg);
    if (ret != 0) {
        goto UNBIND;
    }

    // sync
    ret = perftest_client_sync(g_umq_perftest_ctx.fd);
    if (ret != 0) {
        goto UNBIND;
    }

    // run test
    ret = umq_perftest_start_test_threads(cfg);
    if (ret != 0) {
        goto UNBIND;
    }

    // wait test complete
    umq_perftest_wait(&cfg->config);

    // stop test threads
    umq_perftest_stop_test_threads(&cfg->config);

UNBIND:
    // unbind and flush tx and rx
    (void)umq_unbind(g_umq_perftest_ctx.umqh);

CLOSE_SOC:
    // destroy socket
    (void)close(g_umq_perftest_ctx.fd);

DESTROY:
    // destroy umqh
    (void)umq_destroy(g_umq_perftest_ctx.umqh);

UNINIT:
    // uninit
    umq_uninit();

    return ret;
}

static int umq_perftest_server_exchange_and_bind(umq_perftest_config_t *cfg)
{
    /* 1. serevr recv client bind info
     * 2. bind client
     * 3. send bind info to client */
    exchange_info_t remote_info = {0};
    if (recv_exchange_data(g_umq_perftest_ctx.accept_fd, &remote_info) != 0) {
        return -1;
    }
    LOG_PRINT("server recv bind info succeed, bind info size: %u\n", remote_info.msg_len);

    if (umq_bind(g_umq_perftest_ctx.umqh, remote_info.data, remote_info.msg_len) != 0) {
        LOG_PRINT("server bind failed\n");
        return -1;
    }

    exchange_info_t local_info = {0};
    local_info.msg_len = umq_bind_info_get(g_umq_perftest_ctx.umqh, local_info.data, MAX_INFO_SIZE);
    if (local_info.msg_len == 0) {
        LOG_PRINT("umq_bind_info_get failed\n");
        return -1;
    }
    if (send_exchange_data(g_umq_perftest_ctx.accept_fd, &local_info) != 0) {
        LOG_PRINT("server send bind info failed\n");
        return -1;
    }

    LOG_PRINT("server send bind info succeed, bind info size: %u\n", local_info.msg_len);
    return 0;
}

static int umq_perftest_run_server(umq_perftest_config_t *cfg)
{
    int ret = -1;
    // init
    if (umq_perftest_init_umq(cfg) != 0) {
        return ret;
    }

    // create umqh
    if (umq_perftest_create_umqh(cfg) != 0) {
        goto UNINIT;
    }

    // create socket for exchange attach info and sync
    g_umq_perftest_ctx.fd = perftest_create_server_socket(&cfg->config);
    if (g_umq_perftest_ctx.fd < 0) {
        goto DESTROY;
    }

    g_umq_perftest_ctx.accept_fd =
        perftest_server_do_accept(&cfg->config, g_umq_perftest_ctx.fd, &g_umq_perftest_ctx.force_quit);
    if (g_umq_perftest_ctx.accept_fd < 0) {
        goto CLOSE_FD;
    }

    // exchange bind info and bind
    ret = umq_perftest_server_exchange_and_bind(cfg);
    if (ret != 0) {
        goto CLOSE_ACCEPT_FD;
    }

    // fill rx
    ret = umq_perftest_post_rx(cfg);
    if (ret != 0) {
        goto UNBIND;
    }

    // sync between client and server after fill rx
    ret = perftest_server_sync(g_umq_perftest_ctx.accept_fd);
    if (ret != 0) {
        goto UNBIND;
    }

    // run test
    ret = umq_perftest_start_test_threads(cfg);
    if (ret != 0) {
        goto UNBIND;
    }

    // wait test complete
    umq_perftest_wait(&cfg->config);

    // stop test threads
    umq_perftest_stop_test_threads(&cfg->config);

UNBIND:
    // unbind and flush rx and tx
    (void)umq_unbind(g_umq_perftest_ctx.umqh);

CLOSE_ACCEPT_FD:
    // destroy socket
    (void)close(g_umq_perftest_ctx.accept_fd);
CLOSE_FD:
    (void)close(g_umq_perftest_ctx.fd);

DESTROY:
    // destroy umqh
    (void)umq_destroy(g_umq_perftest_ctx.umqh);

UNINIT:
    // uninit
    umq_uninit();

    return ret;
}

int main(int argc, char *argv[])
{
    init_signal_handler();

    if (umq_perftest_parse_arguments(argc, argv, &g_umq_perftest_ctx.cfg) != 0) {
        return -1;
    }

    // only UB/UB_PLUS/IB/IB_PLUS support pro feature
    uint32_t trans_mode = g_umq_perftest_ctx.cfg.trans_mode;
    if ((g_umq_perftest_ctx.cfg.feature & UMQ_FEATURE_API_PRO) &&
        trans_mode != UMQ_TRANS_MODE_UB && trans_mode != UMQ_TRANS_MODE_IB &&
        trans_mode != UMQ_TRANS_MODE_UB_PLUS && trans_mode != UMQ_TRANS_MODE_IB_PLUS) {
        LOG_PRINT("trans_mode: %u doesn't support pro feature\n", trans_mode);
        return -1;
    }

    int ret;
    if (g_umq_perftest_ctx.cfg.config.instance_mode == PERF_INSTANCE_SERVER) {
        ret = umq_perftest_run_server(&g_umq_perftest_ctx.cfg);
    } else {
        ret = umq_perftest_run_client(&g_umq_perftest_ctx.cfg);
    }

    LOG_PRINT("umq perftest finished\n");
    return ret;
}
