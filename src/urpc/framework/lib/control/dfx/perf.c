/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc sge cmd
 * Create: 2024-11-21
 */

#include <pthread.h>
#include <string.h>

#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_util.h"
#include "unix_server.h"
#include "urpc_thread_closure.h"
#include "urpc_dbuf_stat.h"
#include "perf.h"

#define URPC_PERF_CMD_NUM               (sizeof(g_urpc_perf_cmd) / sizeof(urpc_ipc_cmd_t))
#define URPC_PERF_MAX_THRESH_NS         (100000u)
#define URPC_PERF_REC_MAX_NUM           (256u)

static __thread uint32_t g_perf_record_index = -1;
static urpc_perf_recorder_t g_urpc_perf_recorder = NULL;
static __thread pthread_once_t g_dp_thread_run_once = PTHREAD_ONCE_INIT;

// collect the functions run once per data plane thread
void urpc_dp_thread_run_once(void)
{
    pthread_once(&g_dp_thread_run_once, urpc_perf_record_alloc);
}

struct urpc_perf_record_ctx {
    urpc_perf_record_t perf_record_table[URPC_PERF_REC_MAX_NUM];
    uint64_t perf_quantile_thresh[URPC_PERF_QUANTILE_MAX_NUM];
    pthread_mutex_t lock;
    bool io_record_started;
} g_urpc_perf_record_ctx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .io_record_started = 0,
};

static void urpc_clear_perf_record_item(uint32_t record_idx)
{
    urpc_perf_record_t *cur_record = &g_urpc_perf_record_ctx.perf_record_table[record_idx];
    for (int type = 0; type < PERF_RECORD_POINT_MAX; ++type) {
        cur_record->type_record[type].mean = 0;
        cur_record->type_record[type].std_m2 = 0;
        cur_record->type_record[type].min = UINT64_MAX;
        cur_record->type_record[type].max = 0;
        cur_record->type_record[type].cnt = 0;
        memset(cur_record->type_record[type].bucket, 0, sizeof(cur_record->type_record[type].bucket));
    }
}

static inline void urpc_perf_record_closure(uint64_t idx)
{
    (void)pthread_mutex_lock(&g_urpc_perf_record_ctx.lock);
    urpc_clear_perf_record_item(idx);
    g_urpc_perf_record_ctx.perf_record_table[idx].is_used = false;
    (void)pthread_mutex_unlock(&g_urpc_perf_record_ctx.lock);
}

void urpc_perf_record_alloc(void)
{
    uint32_t idx;

    (void)pthread_mutex_lock(&g_urpc_perf_record_ctx.lock);
    for (idx = 0; idx < URPC_PERF_REC_MAX_NUM; ++idx) {
        if (!g_urpc_perf_record_ctx.perf_record_table[idx].is_used) {
            break;
        }
    }
    if (idx == URPC_PERF_REC_MAX_NUM) {
        (void)pthread_mutex_unlock(&g_urpc_perf_record_ctx.lock);
        URPC_LIB_LOG_WARN("perf_rec table capacity %u were exhausted, alloc perf_rec failed\n", URPC_PERF_REC_MAX_NUM);
        return;
    }

    urpc_clear_perf_record_item(idx);
    g_urpc_perf_record_ctx.perf_record_table[idx].is_used = true;
    (void)pthread_mutex_unlock(&g_urpc_perf_record_ctx.lock);

    g_perf_record_index = idx;
    urpc_thread_closure_register(THREAD_CLOSURE_PERF, idx, urpc_perf_record_closure);
}

static inline uint32_t find_perf_record_bucket(uint64_t delta)
{
    if (g_urpc_perf_record_ctx.perf_quantile_thresh[0] == 0) {
        // quantile thresh is not set, don't fill the bucket
        return URPC_INVALID_ID_U32;
    }
    uint32_t idx;
    for (idx = 0; idx < URPC_PERF_QUANTILE_MAX_NUM; ++idx) {
        if (delta <= g_urpc_perf_record_ctx.perf_quantile_thresh[idx]) {
            break;
        }
    }

    // return URPC_PERF_QUANTILE_MAX_NUM for samples whose time cost > maximum quantile_thresh,
    // since bucket[URPC_PERF_QUANTILE_MAX_NUM] stores the number of samples that exceed the max quantile_thresh
    return idx;
}

static uint64_t urpc_perf_get_start_timestamp(void)
{
    if (URPC_LIKELY(!(g_urpc_perf_record_ctx.io_record_started && g_perf_record_index < URPC_PERF_REC_MAX_NUM))) {
        return 0;
    }
    return urpc_get_cpu_cycles();
}

// use welford algorithm to calculate standard deviation
static void calculate_welford_m2(uint64_t new_cost, double *mean, double *m2, uint64_t iter)
{
    if (URPC_UNLIKELY(iter == UINT64_MAX)) {
        return;
    }
    double delta = new_cost - *mean;
    *mean += delta / (iter + 1);
    double delta2 = new_cost - *mean;
    *m2 += delta * delta2;
}

void urpc_perf_record_write(urpc_perf_record_point_t point, uint64_t start)
{
    if (URPC_LIKELY(!(
        g_urpc_perf_record_ctx.io_record_started && g_perf_record_index < URPC_PERF_REC_MAX_NUM && start != 0))) {
        return;
    }
    uint64_t delta = urpc_get_cpu_cycles() - start;
    urpc_perf_record_t *cur_rec = &g_urpc_perf_record_ctx.perf_record_table[g_perf_record_index];
    calculate_welford_m2(
        delta, &cur_rec->type_record[point].mean, &cur_rec->type_record[point].std_m2, cur_rec->type_record[point].cnt);
    (delta < cur_rec->type_record[point].min) ? cur_rec->type_record[point].min = delta : 0;
    (delta > cur_rec->type_record[point].max) ? cur_rec->type_record[point].max = delta : 0;
    uint32_t bucket_idx = find_perf_record_bucket(delta);
    if (bucket_idx != URPC_INVALID_ID_U32) {
        ++cur_rec->type_record[point].bucket[bucket_idx];
    }
    ++cur_rec->type_record[point].cnt;
}

static void perf_start_cmd_process(
    urpc_ipc_ctl_head_t *req_ctl, char *request, urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    // IO perf record has been started, user must stop it first before restart
    if (g_urpc_perf_record_ctx.io_record_started) {
        URPC_LIB_LOG_INFO("IO perf record has been started, please stop it first before restart\n");
        rsp_ctl->error_code = URPC_FAIL;
        return;
    }

    uint32_t thresh_num = req_ctl->data_size / sizeof(uint64_t);
    if (request == NULL || thresh_num == 0) {
        URPC_LIB_LOG_INFO("IO perf record started without quantile\n");
        goto START_WITHOUT_QUANTILE;
    }
    if (thresh_num > URPC_PERF_QUANTILE_MAX_NUM) {
        URPC_LIB_LOG_WARN(
            "configured thresh num %u exceeds the max thresh_num %u, only the minimum %d of them are used\n",
            thresh_num, URPC_PERF_QUANTILE_MAX_NUM, URPC_PERF_QUANTILE_MAX_NUM);
        thresh_num = URPC_PERF_QUANTILE_MAX_NUM;
    }

    // set quantile bucket
    uint32_t idx = 0;
    uint64_t *thresh_array = (uint64_t *)request;
    for (uint32_t i = 0; i < thresh_num; ++i) {
        if (thresh_array[i] > (URPC_PERF_MAX_THRESH_NS * urpc_get_cpu_hz() / NS_PER_SEC)) {
            continue;
        }
        if (idx == 0 || thresh_array[i] > g_urpc_perf_record_ctx.perf_quantile_thresh[idx - 1]) {
            g_urpc_perf_record_ctx.perf_quantile_thresh[idx++] = thresh_array[i];
        }
    }

    g_urpc_perf_record_ctx.io_record_started = true;
    rsp_ctl->error_code = URPC_SUCCESS;
    URPC_LIB_LOG_INFO("IO perf record started successfully, set %u thresh\n", idx);

    return;

START_WITHOUT_QUANTILE:
    g_urpc_perf_record_ctx.io_record_started = true;
    rsp_ctl->error_code = URPC_PARTIAL_SUCCESS;
}

static void perf_stop_cmd_process(urpc_ipc_ctl_head_t *req_ctl __attribute__((unused)),
    char *request __attribute__((unused)), urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (!g_urpc_perf_record_ctx.io_record_started) {
        URPC_LIB_LOG_INFO("IO perf has not been started.\n");
        return;
    }
    g_urpc_perf_record_ctx.io_record_started = false;
    URPC_LIB_LOG_INFO("IO perf record stopped.\n");
    *reply = (char *)g_urpc_perf_record_ctx.perf_record_table;
    rsp_ctl->data_size = (uint32_t)(sizeof(g_urpc_perf_record_ctx.perf_record_table));
    memset(g_urpc_perf_record_ctx.perf_quantile_thresh, 0, URPC_PERF_QUANTILE_MAX_NUM * sizeof(uint64_t));
}

static void perf_clear_cmd_process(urpc_ipc_ctl_head_t *req_ctl __attribute__((unused)),
    char *request __attribute__((unused)), urpc_ipc_ctl_head_t *rsp_ctl, char **reply)
{
    if (g_urpc_perf_record_ctx.io_record_started) {
        rsp_ctl->error_code = URPC_FAIL;
        URPC_LIB_LOG_INFO("IO perf is still running, clear it after stop\n");
        return;
    }
    for (uint32_t i = 0; i < URPC_PERF_REC_MAX_NUM; ++i) {
        urpc_clear_perf_record_item(i);
    }
    memset(g_urpc_perf_record_ctx.perf_quantile_thresh, 0, URPC_PERF_QUANTILE_MAX_NUM * sizeof(uint64_t));
    rsp_ctl->error_code = URPC_SUCCESS;
    URPC_LIB_LOG_INFO("IO perf records were cleared\n");
}

static urpc_ipc_cmd_t g_urpc_perf_cmd[] = {
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_START,
        .func = perf_start_cmd_process,
        .reply_malloced = false,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_STOP,
        .func = perf_stop_cmd_process,
        .reply_malloced = false,
    },
    {
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = (uint16_t)URPC_PERF_CMD_ID_CLEAR,
        .func = perf_clear_cmd_process,
        .reply_malloced = false,
    }
};

int urpc_perf_cmd_init(void)
{
    for (uint32_t i = 0; i < URPC_PERF_REC_MAX_NUM; ++i) {
        urpc_clear_perf_record_item(i);
    }
    return unix_server_cmds_register(g_urpc_perf_cmd, URPC_PERF_CMD_NUM);
}

void urpc_perf_cmd_uninit(void)
{
    unix_server_cmds_unregister(g_urpc_perf_cmd, URPC_PERF_CMD_NUM);
}

/*
urpc inner performance statistic will exclude the time spent on user callbacks, it will start after user callback
invokes.
*/
uint64_t urpc_perf_record_begin(urpc_perf_record_point_t point)
{
    if (g_urpc_perf_recorder != NULL) {
        g_urpc_perf_recorder(PERF_RECORD_TYPE_BEGIN, point);
    }

    urpc_dp_thread_run_once();
    return urpc_perf_get_start_timestamp();
}

/*
urpc inner performance statistic will exclude the time spent on user callbacks, it will end before user callback
invokes.
*/
void urpc_perf_record_end(urpc_perf_record_point_t point, uint64_t start)
{
    urpc_perf_record_write(point, start);

    if (g_urpc_perf_recorder != NULL) {
        g_urpc_perf_recorder(PERF_RECORD_TYPE_END, point);
    }
}

int urpc_perf_recorder_register(urpc_perf_recorder_t perf_recorder)
{
    if (g_urpc_perf_recorder != NULL) {
        URPC_LIB_LOG_ERR("perf recorder has been register, unregister it first\n");
        return -URPC_ERR_EINVAL;
    }
    g_urpc_perf_recorder = perf_recorder;
    URPC_LIB_LOG_INFO("perf recorder register successful\n");
    return URPC_SUCCESS;
}

int urpc_perf_recorder_unregister(void)
{
    if (g_urpc_perf_recorder == NULL) {
        return URPC_SUCCESS;
    }
    g_urpc_perf_recorder = NULL;
    URPC_LIB_LOG_INFO("perf recorder unregister successful\n");
    return URPC_SUCCESS;
}