/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: parse parameters header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_PARAMETERS_H
#define PERFTEST_PARAMETERS_H

#include <stdint.h>
#include <stdbool.h>

#include "urma_types.h"
#include "urma_ex_api.h"

#include "perftest_communication.h"

/* Default Values of perftest parameters */
#define PERFTEST_DEF_JFC_DEPTH_LAT (1)
#define PERFTEST_DEF_PORT (21115)
#define PERFTEST_DEF_SIZE_LAT (2)
#define PERFTEST_DEF_SIZE_BW (65536)
#define PERFTEST_DEF_MAX_SIZE (8388608)
#define PERFTEST_DEF_ITERS_LAT (10000)
#define PERFTEST_DEF_ITERS_BW (50000)
#define PERFTEST_DEF_JFS_DEPTH_LAT (1)
#define PERFTEST_DEF_JFS_DEPTH_BW (128)
#define PERFTEST_DEF_JFR_DEPTH_OTHER   (1)
#define PERFTEST_DEF_JFR_DEPTH_SEND   (512)
/* Too small jfc depth will lead to ibv poll error: transport retry counter exceeded */
#define PERFTEST_DEF_JFC_DEPTH_BW (8 * PERFTEST_DEF_JFR_DEPTH_SEND)
#define PERFTEST_DEF_JFC_DEPTH_BW_IP (2 * PERFTEST_DEF_JFR_DEPTH_SEND)
#define PERFTEST_DEF_CQ_NUM   (100)
#define PERFTEST_DEF_NUM_JETTYS   (1)
#define PERFTEST_DEF_IBP_ATOMIC_SIZE   (8)
#define PERFTEST_SIZE_CQ_MOD_LIMIT (8192)
#define PERFTEST_BW_NO_PEAK_INTERS (20000)

#define PERFTEST_INLINE_LAT_RC (220)
#define PERFTEST_INLINE_LAT_RM (236)
#define PERFTEST_INLINE_LAT_UM (188)
#define PERFTEST_DEF_INLINE_LAT PERFTEST_INLINE_LAT_RC
#define PERFTEST_DEF_INLINE_BW (0)

#define PERFTEST_DEF_CACHE_LINE_SIZE (64)
#define PERFTEST_PAGE_SIZE (4096)

#define PERFTEST_MIN_ORDER  (1)
#define PERFTEST_SIZE_ORDER  (16)    // 2^16
#define PERFTEST_MAX_ORDER  (23)

// value range of perftest iterations
#define PERFTEST_ITERS_MIN  (5)
#define PERFTEST_ITERS_MAX  (100000000)

// value range of perftest jfs_depth
#define PERFTEST_JFS_DEPTH_MIN  (1)
#define PERFTEST_JFS_DEPTH_MAX  (15000)

// value range of perftest jettys
#define PERFTEST_JETTYS_MIN  (1)
#define PERFTEST_JETTYS_MAX  (0x4000)

// value range of perftest inline size
#define PERFTEST_INLINE_MIN  (0)
#define PERFTEST_INLINE_MAX  (912)

// value range of perftest jfr_depth
#define PERFTEST_JFR_DEPTH_MIN  (1)
#define PERFTEST_JFR_DEPTH_MAX  (0x4000)

// value range of perftest cq_mod
#define PERFTEST_CQ_MOD_MIN  (1)
#define PERFTEST_CQ_MOD_MAX  (0x400)

// value range of perftest err_timeout
#define PERFTEST_ERR_TIMEOUT_MIN  (0)
#define PERFTEST_ERR_TIMEOUT_MAX  (31)

// value range of perftest priority
#define PERFTEST_PRIORITY_MIN  (0)
#define PERFTEST_PRIORITY_MAX  (15)

#define PERFTEST_DEF_TEST_TIME (2)    // 1/2 of duration for test
#define PERFTEST_DEF_WARMUP_TIME (4)  // 1/4 of duration for warmup
#define PERFTEST_DEF_INF_PERIOD (2)

#define PERFTEST_RESULT_LINE "---------------------------------------------------------------------------------------\n"


typedef enum perftest_api_type {
    PERFTEST_READ,
    PERFTEST_WRITE,
    PERFTEST_SEND,
    PERFTEST_ATOMIC
} perftest_api_type_t;

typedef enum perftest_type {
    PERFTEST_LAT,
    PERFTEST_BW
} perftest_type_t;

typedef enum perftest_atomic_type {
    PERFTEST_CAS,
    PERFTEST_FAA
} perftest_atomic_type_t;

typedef union perftest_time_type {
    struct {
        uint32_t iterations        :   1;
        uint32_t duration          :   1;
        uint32_t infinite          :   1;
        uint32_t reserved          :   29;
    } bs;
    uint32_t value;
} perftest_time_type_t;

typedef enum perftest_cmd_type {
    PERFTEST_READ_LAT,
    PERFTEST_WRITE_LAT,
    PERFTEST_SEND_LAT,
    PERFTEST_ATOMIC_LAT,
    PERFTEST_READ_BW,
    PERFTEST_WRITE_BW,
    PERFTEST_SEND_BW,
    PERFTEST_ATOMIC_BW,
    PERFTEST_CMD_NUM
} perftest_cmd_type_t;

typedef enum perftest_jetty_mode {
    PERFTEST_JETTY_SIMPLEX,                  /* simplex mode for jfs/jfr */
    PERFTEST_JETTY_DUPLEX                    /* duplex mode only for jetty */
} perftest_jetty_mode_t;

typedef struct perftest_config {
    perftest_cmd_type_t cmd;
    perftest_type_t type;
    perftest_api_type_t api_type;
    bool all;                          /* Run sizes from 2 till 2^16. */
    perftest_atomic_type_t atomic_type;
    uint32_t jfc_depth;
    char dev_name[URMA_MAX_NAME];      /* The name of ubep device. */
    uint32_t duration;                 /* Run test for a customized period of second. */
    bool use_jfce;
    perftest_time_type_t time_type;
    uint32_t inline_size;              /* Max size of message to be sent in inline. */
    uint32_t jettys;                   /* Num of jetty's(default 1). */
    uint32_t token_policy;
    uint32_t mtu;
    urma_transport_type_t tp_type;
    uint64_t iters;                    /* Number of exchanges (at least 5, default 1000). */
    uint64_t last_iters;               /* [private] only used for infinite. */
    bool no_peak;
    uint32_t jfs_post_list;            /* Post list of send WQEs of <list size> size. */
    perftest_jetty_mode_t jetty_mode;
    uint32_t cq_mod;                   /* Generate Cqe only after <--cq-mod> completion. */
    uint32_t jfr_post_list;            /* Post list of receive WQEs of <list size> size. */
    uint32_t jfr_depth;
    uint32_t size;
    uint32_t jfs_depth;
    urma_transport_mode_t trans_mode;

    uint32_t cache_line_size;
    uint64_t page_size;
    bool use_flat_api;                  /* Choose to use flat API, only works in PERFTEST_JETTY_SIMPLEX mode. */
    bool cpu_freq_f;                    /* To report warnings when CPU frequency drifts. */
    bool ignore_jetty_in_cr;            /* NOT to fill jetty_id in parse cr. */
    bool warm_up;                       /* Warm_up is only available for read/write/atomic bw test. */
    bool bidirection;                   /* Bidirectional only supports BW test. */
    bool jfc_inline;
    uint32_t inf_period;                /* Print period for infinite mode, default 2 seconds. */
    uint32_t order;                     /* Set max order of 2, only used for ALL. */
    uint8_t err_timeout;
    bool lock_free;
    uint8_t priority;
    bool share_jfr;
    uint32_t io_thread_num;
    perftest_comm_t comm;
} perftest_config_t;

typedef struct perftest_value_range {
    uint64_t value;
    uint32_t min;
    uint32_t max;
    char *name;
} perftest_value_range_t;

typedef struct bw_report_data {
    uint32_t size;
    uint64_t iters;
    double bw_peak;
    double bw_avg;
    double msg_rate_avg;
} bw_report_data_t;

void print_cfg(const perftest_config_t *cfg);
int perftest_parse_args(int argc, char *argv[], perftest_config_t *cfg);
void destroy_cfg(perftest_config_t *cfg);
int check_local_cfg(perftest_config_t *cfg);
int check_remote_cfg(perftest_config_t *cfg);
#endif