/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc sge cmd
 * Create: 2024-11-21
 */
#include <math.h>

#include "perf.h"
#include "urpc_framework_errno.h"
#include "urpc_util.h"
#include "urpc_admin_cmd.h"
#include "urpc_admin_log.h"
#include "urpc_admin_param.h"

#define URPC_ADMIN_PERF_CMD_NUM         (sizeof(g_perf_cmd) / sizeof(urpc_admin_cmd_t))
#define URPC_PERF_REC_NAME_MAX_LEN      (128u)

static char g_urpc_perf_record_type_name[PERF_RECORD_POINT_MAX][URPC_PERF_REC_NAME_MAX_LEN] = {
    "urpc_func_call",
    "urpc_func_poll",
    "urpc_func_return",
    "urpc_ref_read",
    "urpc_queue_rx_post",
    "urpc_ext_func_call",
    "urpc_ext_func_return",
    "transport_send",
    "transport_poll",
    "transport_read",
    "transport_post",
};

_Static_assert((sizeof(g_urpc_perf_record_type_name) / sizeof(g_urpc_perf_record_type_name[0])) ==
    PERF_RECORD_POINT_MAX,
    "g_urpc_perf_record_type_name size is inconsistent with PERF_RECORD_POINT_MAX");

static int compare(const void *a, const void *b)
{
    return (*(uint64_t *)a > *(uint64_t *)b) - (*(uint64_t *)a < *(uint64_t *)b);
}

static inline uint64_t ns_to_cpu_cycles(uint64_t time_ns)
{
    // The CPU frequency is around X GHz, so dividing by NS_PER_SEC=1e9 will solve the overflow issue.
    if (time_ns != 0 && UINT64_MAX / time_ns <= urpc_get_cpu_hz()) {
        return time_ns / NS_PER_SEC * urpc_get_cpu_hz();
    } else {
        return time_ns * urpc_get_cpu_hz() / NS_PER_SEC;
    }
}

static inline uint64_t cpu_cycles_to_ns(uint64_t cycles)
{
    // The CPU frequency is around X GHz, so dividing by CPU hz will solve the overflow issue.
    if (cycles != 0 && UINT64_MAX / cycles <= NS_PER_SEC) {
        return cycles / urpc_get_cpu_hz() * NS_PER_SEC;
    } else {
        return cycles * NS_PER_SEC / urpc_get_cpu_hz();
    }
}

static char *perf_start_request_gen(uint64_t count_thresh[], uint8_t count_thresh_num, uint32_t *data_size)
{
    // Sort the input thresh
    qsort(count_thresh, count_thresh_num, sizeof(uint64_t), compare);

    uint32_t result_size =  count_thresh_num * sizeof(uint64_t);
    uint64_t *result = (uint64_t *)calloc(1, result_size);
    if (result == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < count_thresh_num; ++i) {
        // user input thresh in nanosecond, we convert it to cpu cycles
        result[i] = ns_to_cpu_cycles(count_thresh[i]);
    }

    *data_size = result_size;
    return (char *)result;
}

static int perf_start_request_create(urpc_ipc_ctl_head_t *req_ctl,
    char **request, urpc_admin_config_t *cfg __attribute__((unused)))
{
    req_ctl->module_id = (uint16_t)URPC_IPC_MODULE_PERF;
    req_ctl->cmd_id = (uint16_t)URPC_PERF_CMD_ID_START;
    req_ctl->error_code = 0;

    uint32_t request_size = 0;
    *request = perf_start_request_gen(cfg->perf.count_thresh, cfg->perf.count_thresh_num, &request_size);
    req_ctl->data_size = request_size;

    (void)printf("Name     : perf request\n");
    (void)printf("Command  : IO perf record start\n");

    return 0;
}

static int perf_start_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != URPC_SUCCESS) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        switch (rsp_ctl->error_code) {
            case URPC_FAIL:
                LOG_PRINT("IO perf record has been started, please stop it first before restart.\n");
                return -1;
            case URPC_PARTIAL_SUCCESS:
                LOG_PRINT("IO perf record started without quantile\n");
                break;
            default:
                break;
        }
    }

    if (rsp_ctl->data_size == 0) {
        LOG_PRINT("recv empty response\n");
    } else {
        (void)printf("%s", reply);
    }

    return 0;
}

static int perf_stop_request_create(urpc_ipc_ctl_head_t *req_ctl,
    char **request __attribute__((unused)), urpc_admin_config_t *cfg __attribute__((unused)))
{
    req_ctl->module_id = (uint16_t)URPC_IPC_MODULE_PERF;
    req_ctl->cmd_id = (uint16_t)URPC_PERF_CMD_ID_STOP;
    req_ctl->error_code = 0;
    req_ctl->data_size = 0;

    (void)printf("Name     : perf request\n");
    (void)printf("Command  : IO perf record stop\n\n");

    return 0;
}

static void urpc_admin_perf_convert_cycles_to_ns(urpc_perf_record_t *perf_rec)
{
    for (int type = 0; type < PERF_RECORD_POINT_MAX; ++type) {
        // min default value is inited as UINT64_MAX, we output it as 0 for readability
        perf_rec->type_record[type].min =
            perf_rec->type_record[type].min == UINT64_MAX ? 0 : cpu_cycles_to_ns(perf_rec->type_record[type].min);
        perf_rec->type_record[type].max = cpu_cycles_to_ns(perf_rec->type_record[type].max);
        perf_rec->type_record[type].mean = cpu_cycles_to_ns(perf_rec->type_record[type].mean);
        perf_rec->type_record[type].std_m2 = cpu_cycles_to_ns(perf_rec->type_record[type].std_m2);
    }
}

static uint64_t urpc_admin_perf_cal_quantile(
    urpc_perf_record_t *record, urpc_perf_record_type_t type, uint64_t count, urpc_admin_config_t *cfg)
{
    uint32_t idx;
    uint64_t quantile_cnt = count;

    if (cfg == NULL || cfg->perf.count_thresh_num == 0 || count == 0) {
        return 0;
    }

    for (idx = 0; idx < URPC_PERF_QUANTILE_MAX_NUM + 1; ++idx) {
        if (record->type_record[type].bucket[idx] >= quantile_cnt) {
            break;
        }
        quantile_cnt -= record->type_record[type].bucket[idx];
    }

    // the queried quantile cnt exceeds the maximum thresh records, return the max thresh
    if (idx >= URPC_PERF_QUANTILE_MAX_NUM) {
        return cfg->perf.count_thresh[cfg->perf.count_thresh_num - 1];
    }

    if (record->type_record[type].bucket[idx] == 0) {
        return 0;
    }

    uint64_t base = (idx == 0) ? 0 : cfg->perf.count_thresh[idx - 1];
    return ((double)quantile_cnt / record->type_record[type].bucket[idx]) * (cfg->perf.count_thresh[idx] - base) + base;
}

static void urpc_admin_perf_analyse_and_output(urpc_perf_record_t *perf_rec, urpc_admin_config_t *cfg)
{
    // convert the record from cpu cycles to ns
    urpc_admin_perf_convert_cycles_to_ns(perf_rec);

    for (int type = 0; type < PERF_RECORD_POINT_MAX; ++type) {
        double ave_cost = perf_rec->type_record[type].mean;
        double std = sqrt(perf_rec->type_record[type].std_m2 / (perf_rec->type_record[type].cnt - 1));
        uint64_t median = urpc_admin_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.5 * perf_rec->type_record[type].cnt), cfg);
        uint64_t p90 = urpc_admin_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.9 * perf_rec->type_record[type].cnt), cfg);
        uint64_t p99 = urpc_admin_perf_cal_quantile(perf_rec, type,
            (uint64_t)(0.99 * perf_rec->type_record[type].cnt), cfg);
        printf("%-20s %-20lu %-20.2lf %-20.2lf %-20lu %-20lu %-20lu %-20lu %-20lu\n",
               g_urpc_perf_record_type_name[type], perf_rec->type_record[type].cnt, ave_cost, std,
               perf_rec->type_record[type].min, perf_rec->type_record[type].max, median, p90, p99);
    }
}

static inline void print_equals(void)
{
    printf("====================================================================================================="
           "============================================================================\n");
}

static inline void print_underline(void)
{
    printf("-----------------------------------------------------------------------------------------------------"
           "----------------------------------------------------------------------------\n");
}

static int perf_stop_response_process(urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg)
{
    if (rsp_ctl->error_code != 0) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        return -1;
    }

    if (reply == NULL || rsp_ctl->data_size == 0) {
        LOG_PRINT("perf record stop with no data\n");
        return -1;
    }

    // Sort the input thresh
    qsort(cfg->perf.count_thresh, cfg->perf.count_thresh_num, sizeof(uint64_t), compare);

    print_equals();
    printf("                                                                    Analyse IO performance records\n");
    print_equals();
    printf("%-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n", "type", "sample num",
        "average (ns)", "stdev", "minimum (ns)", "maximum (ns)", "median (ns)", "p90 (ns)", "p99 (ns)");
    print_underline();

    urpc_perf_record_t *recv_perf = (urpc_perf_record_t *)reply;
    uint32_t perf_rec_num = (uint32_t)(rsp_ctl->data_size / sizeof(urpc_perf_record_t));
    // Ananlyse the recved perf data
    for (uint32_t i = 0; i < perf_rec_num; ++i) {
        if (!recv_perf[i].is_used) {
            continue;
        }
        printf("                                                                           Data Thread %u\n", i);
        print_underline();
        urpc_admin_perf_analyse_and_output(&recv_perf[i], cfg);
        print_underline();
    }
    print_equals();
    (void)LOG_PRINT("Perf record stopped.\n");

    return 0;
}

static int perf_clear_request_create(urpc_ipc_ctl_head_t *req_ctl,
    char **request __attribute__((unused)), urpc_admin_config_t *cfg __attribute__((unused)))
{
    req_ctl->module_id = (uint16_t)URPC_IPC_MODULE_PERF;
    req_ctl->cmd_id = (uint16_t)URPC_PERF_CMD_ID_CLEAR;
    req_ctl->error_code = 0;
    req_ctl->data_size = 0;

    (void)printf("Name     : perf request\n");
    (void)printf("Command  : IO perf record clear\n\n");

    return 0;
}

static int perf_clear_response_process(
    urpc_ipc_ctl_head_t *rsp_ctl, char *reply, urpc_admin_config_t *cfg __attribute__((unused)))
{
    if (rsp_ctl->error_code != URPC_SUCCESS) {
        LOG_PRINT("recv error code %d\n", rsp_ctl->error_code);
        switch (rsp_ctl->error_code) {
            case URPC_FAIL:
                LOG_PRINT("IO perf is still running, clear it after stop.\n");
                return -1;
            default:
                break;
        }
    }
    LOG_PRINT("IO perf is cleared successfully.\n");

    return 0;
}

static urpc_admin_cmd_t g_perf_cmd[] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_START,
        .create_request = perf_start_request_create,
        .process_response = perf_start_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_STOP,
        .create_request = perf_stop_request_create,
        .process_response = perf_stop_response_process,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_CLEAR,
        .create_request = perf_clear_request_create,
        .process_response = perf_clear_response_process,
    }
};

static void __attribute__((constructor)) urpc_admin_perf_cmd_init(void)
{
    urpc_admin_cmds_register(g_perf_cmd, URPC_ADMIN_PERF_CMD_NUM);
}