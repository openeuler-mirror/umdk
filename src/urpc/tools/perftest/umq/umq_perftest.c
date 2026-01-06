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
#include <stdarg.h>

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
#define PERFTEST_WAIT_TIMEOUT_US 100
#define PERFTEST_WAIT_UMQ_READY_ROUND 10000

#define UMQ_PERFTEST_EQUALS "=========================================================================================\
================================================================================"
#define UMQ_PERFTEST_UNDERLINE "--------------------------------------------------------------------------------------\
-----------------------------------------------------------------------------------"
#define UMQ_PERFTEST_ERTF_INFO_STR_SIZE (1024 + 1024 * 5 * 2) // head size: 1024, thread size: 1024 * 5, thread num: 2
#define UMQ_PERFTEST_PERF_REC_NAME_MAX_LEN 20 // stay synchronized with the output format
static char g_perf_record_type_name[UMQ_PERF_RECORD_TYPE_MAX][UMQ_PERFTEST_PERF_REC_NAME_MAX_LEN] = {
    "umq_enqueue",
    "umq_dequeue",
    "umq_dequeue_empty",
    "umq_post_all",
    "umq_post_tx",
    "umq_post_rx",
    "umq_poll_all",
    "umq_poll_tx",
    "umq_poll_rx",
    "umq_poll_all_empty",
    "umq_poll_tx_empty",
    "umq_poll_rx_empty",
    "umq_notify",
    "tp_post_send",
    "tp_post_recv",
    "tp_poll_tx",
    "tp_poll_rx",
    "tp_poll_tx_empty",
    "tp_poll_rx_empty",
    "tp_read",
    "tp_send_imm",
    "tp_write_imm",
};

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
        dev_info->dev.eid_idx = cfg->eid_idx;
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

static inline int umq_perftest_write_perf_recode_msg(char *str_buf, int all_str_len, const char *format, ...)
{
    if (all_str_len <= 0) {
        return 0;
    }

    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str_buf, all_str_len, format, args);
    va_end(args);
    return ret;
}

static uint64_t umq_perftest_perf_cal_quantile(
    umq_perf_record_t *record, umq_perf_record_type_t type, uint64_t count, uint64_t *thresh, uint32_t thresh_num)
{
    if (thresh_num == 0) {
        return 0;
    }

    uint32_t idx;
    uint64_t quantile_cnt = count;
    for (idx = 0; idx < thresh_num; ++idx) {
        if (record->type_record[type].bucket[idx] >= quantile_cnt) {
            break;
        }
        quantile_cnt -= record->type_record[type].bucket[idx];
    }

    // the queried quantile cnt exceeds the maximum thresh records, return the max thresh
    if (idx >= thresh_num) {
        return thresh[thresh_num - 1];
    }

    if (record->type_record[type].bucket[idx] == 0) {
        return 0;
    }

    uint64_t base = (idx == 0) ? 0 : thresh[idx - 1];
    return ((double)quantile_cnt / record->type_record[type].bucket[idx]) * (thresh[idx] - base) + base;
}

static int umq_perftest_perf_analyse_and_output(
    char *perf_info_str, int perf_info_size, umq_perf_record_t *perf_rec, uint64_t *thresh, uint32_t thresh_num)
{
    int ret = 0;
    for (int type = 0; type < UMQ_PERF_RECORD_TYPE_MAX; ++type) {
        uint64_t ave_cost = perf_rec->type_record[type].cnt != 0 ?
                            (perf_rec->type_record[type].accumulation / perf_rec->type_record[type].cnt) : 0;
        uint64_t median = umq_perftest_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.5 * perf_rec->type_record[type].cnt), thresh, thresh_num);
        uint64_t p90 = umq_perftest_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.9 * perf_rec->type_record[type].cnt), thresh, thresh_num);
        uint64_t p99 = umq_perftest_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.99 * perf_rec->type_record[type].cnt), thresh, thresh_num);
        ret += umq_perftest_write_perf_recode_msg(perf_info_str + ret, perf_info_size - ret,
            "%-20s %-20lu %-20lu %-20lu %-20lu %-20lu %-20lu %-20lu\n",
            g_perf_record_type_name[type], perf_rec->type_record[type].cnt, ave_cost,
            perf_rec->type_record[type].min, perf_rec->type_record[type].max, median, p90, p99);
    }
    return ret;
}

static int umq_perftest_perf_info_string_get(char *perf_info, int perf_info_size,
    umq_perf_record_t **perf_record_table, uint32_t table_num, uint64_t *thresh, uint32_t thresh_num)
{
    if (perf_info == NULL || perf_record_table == NULL) {
        return UMQ_FAIL;
    }

    int str_size = 0;
    char *ret_str = perf_info;
    (void)memset(perf_info, 0, perf_info_size);

    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "%s\n", UMQ_PERFTEST_EQUALS);
    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "                                                                    Analyse IO performance records\n");
    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "%s\n", UMQ_PERFTEST_EQUALS);
    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "%-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n",
        "Type", "Sample Num", "Average (ns)", "Minimum (ns)", "Maxinum (ns)", "Median (ns)", "P90 (ns)", "P99 (ns)");
    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "%s\n", UMQ_PERFTEST_UNDERLINE);
    umq_perf_record_t **recv_perf = perf_record_table;

    // Ananlyse the recved perf data
    for (uint32_t i = 0; i < table_num; ++i) {
        if (!recv_perf[i]->is_used) {
            continue;
        }
        str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
            "                                                                           Data Thread %u\n", i);
        str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
            "%s\n", UMQ_PERFTEST_UNDERLINE);
        str_size += umq_perftest_perf_analyse_and_output(ret_str + str_size, perf_info_size - str_size,
            recv_perf[i], thresh, thresh_num);
        str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
            "%s\n", UMQ_PERFTEST_UNDERLINE);
    }
    str_size += umq_perftest_write_perf_recode_msg(ret_str + str_size, perf_info_size - str_size,
        "%s\n", UMQ_PERFTEST_EQUALS);
    return str_size;
}

static int umq_perftest_start_perf(umq_perftest_config_t *cfg)
{
    if ((cfg->feature & UMQ_FEATURE_ENABLE_PERF) != 0) {
        umq_dfx_cmd_t dfx_cmd = {
            .module_id = UMQ_DFX_MODULE_PERF,
            .perf_cmd_id = UMQ_PERF_CMD_START,
            .perf_in_param = {
                .thresh_num = cfg->thresh_num,
            },
        };
        (void)memcpy(dfx_cmd.perf_in_param.thresh_array, cfg->thresh_array, sizeof(uint64_t) * cfg->thresh_num);
        umq_dfx_result_t result_ctl = {0};
        umq_dfx_cmd_process(&dfx_cmd, &result_ctl);
        if (result_ctl.err_code != 0) {
            LOG_PRINT("start dfx perf failed\n");
            return -1;
        }
    }
    return 0;
}

static void umq_perftest_finish_perf(umq_perftest_config_t *cfg)
{
    umq_dfx_cmd_t dfx_cmd;
    umq_dfx_result_t result_ctl = {0};

    if ((cfg->feature & UMQ_FEATURE_ENABLE_PERF) != 0) {
        // stop perf
        dfx_cmd.module_id = UMQ_DFX_MODULE_PERF;
        dfx_cmd.perf_cmd_id = UMQ_PERF_CMD_STOP;
        umq_dfx_cmd_process(&dfx_cmd, &result_ctl);
        if (result_ctl.err_code != 0) {
            LOG_PRINT("stop perf failed\n");
            return;
        }

        // get perf record
        dfx_cmd.module_id = UMQ_DFX_MODULE_PERF;
        dfx_cmd.perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;
        umq_dfx_cmd_process(&dfx_cmd, &result_ctl);
        if (result_ctl.err_code != 0) {
            LOG_PRINT("get perf result failed\n");
            return;
        }

        // procrss raw data and output
        char *perf_info_str_buf = (char *)malloc(UMQ_PERFTEST_ERTF_INFO_STR_SIZE);
        if (perf_info_str_buf == NULL) {
            LOG_PRINT("malloc perf info str failed\n");
            return;
        }
        umq_perf_infos_t *perf_record = (umq_perf_infos_t *)result_ctl.perf_out_param;
        uint64_t *thresh_array = cfg->thresh_array;
        uint32_t thresh_num = cfg->thresh_num;
        int str_size = umq_perftest_perf_info_string_get(perf_info_str_buf, UMQ_PERFTEST_ERTF_INFO_STR_SIZE,
            perf_record->perf_record, perf_record->perf_record_num, thresh_array, thresh_num);
        if (str_size >= UMQ_PERFTEST_ERTF_INFO_STR_SIZE) {
            perf_info_str_buf[UMQ_PERFTEST_ERTF_INFO_STR_SIZE - 1] = '\0';
            LOG_PRINT("perf info str buf too small\n");
        }
        printf("%s\n", perf_info_str_buf);
        free(perf_info_str_buf);
    }
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
    umq_buf_t *buf = NULL;
    umq_state_t umq_state = QUEUE_STATE_MAX;
    int poll_cnt = 0;
    if ((cfg->feature & UMQ_FEATURE_API_PRO) == 0) {
        goto WAIT_UMQ_READY;
    }

    // pro mode，need alloc rx buf
    uint32_t require_rx_count = cfg->config.rx_depth;
    uint32_t cur_batch_count = 0;
    umq_buf_t *bad_buf = NULL;
    do {
        cur_batch_count = require_rx_count > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : require_rx_count;

        buf = umq_buf_alloc(cfg->config.size, cur_batch_count, UMQ_INVALID_HANDLE, NULL);
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

WAIT_UMQ_READY:
    do {
        int ret = umq_poll(g_umq_perftest_ctx.umqh, UMQ_IO_TX, &buf, 1);
        if (ret != 0) {
            LOG_PRINT("poll tx get unexpected result %d\n", ret);
            break;
        }

        umq_state = umq_state_get(g_umq_perftest_ctx.umqh);
        if (umq_state != QUEUE_STATE_IDLE) {
            break;
        }
        usleep(PERFTEST_WAIT_TIMEOUT_US);
    } while (poll_cnt++ < PERFTEST_WAIT_UMQ_READY_ROUND);

    if (umq_state != QUEUE_STATE_READY) {
        LOG_PRINT("wait umq to be ready failed, umq state %d\n", umq_state);
        return -1;
    }

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
    umq_perftest_worker_arg_t *arg = (umq_perftest_worker_arg_t *)(uintptr_t)args;
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

    // start perf
    if (umq_perftest_start_perf(cfg) != 0) {
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

    // finish ferf and out reslut
    umq_perftest_finish_perf(cfg);

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

    if (umq_bind(g_umq_perftest_ctx.umqh, remote_info.data, remote_info.msg_len) != 0) {
        LOG_PRINT("server bind failed\n");
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

    // start perf
    if (umq_perftest_start_perf(cfg) != 0) {
        return -1;
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

    // finish ferf and out reslut
    umq_perftest_finish_perf(cfg);

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
    if (((g_umq_perftest_ctx.cfg.feature & UMQ_FEATURE_API_PRO) != 0) &&
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
