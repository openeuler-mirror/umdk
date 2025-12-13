/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
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

#include "ub_util.h"
#include "urma_types.h"

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
#define PERFTEST_DEF_ATOMIC_SIZE   (8)
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
#define PERFTEST_JETTYS_MAX  (0xFFFF)

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
#define PERFTEST_DEF_CREDIT_RATE   (4)
#define PERFTEST_DEF_INF_PERIOD_MS  (50)
#define PERFTEST_SEC_TO_MS    (1000)
#define PERFTEST_MSEC_TO_USEC    (1000)

#define PERFTEST_DEF_RETRY_NUM 7
#define PERFTEST_DEF_RETRY_FACTOR 7
#define PERFTEST_DEF_ACK_TIMEOUT 15
#define PERFTEST_DEF_DSCP 63
#define PERFTEST_DEF_PSN 0x59
#define PERFTEST_DEF_HOP_LIMIT 255
#define PERFTEST_DEF_WAIT_JFC_TIME  (1000)  // 1s

#define PERFTEST_M (1000000)
#define PERFTEST_G (1000000000)
#define PERFTEST_MBS (0x100000)
#define PERFTEST_KPPS (1000)
#define PERFTEST_BW_MB 0x100000 // 2^20
#define PERFTEST_BYTE_SIZE 8

#define PERFTEST_WRITE_DIRTY_PERIOD (50)
#define PERFTEST_CHAR_MAX_VALUE (256)

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

enum perftest_opts {
    PERFTEST_OPT_EID_IDX = 1,
    PERFTEST_OPT_RATE_LIMIT,
    PERFTEST_OPT_BURST_SIZE,
    PERFTEST_OPT_RATE_UNITS,
    PERFTEST_OPT_ORDER_TYPE,
    PERFTEST_OPT_ENABLE_IPV6,
    PERFTEST_OPT_ENABLE_CREDIT,
    PERFTEST_OPT_CREDIT_THRESHOLD,
    PERFTEST_OPT_CREDIT_NOTIFY_CNT,
    PERFTEST_OPT_JETTYS_PRE_JFR,
    PERFTEST_OPT_SEG_PRE_JETTY,
    PERFTEST_OPT_ENABLE_IMM,
    PERFTEST_OPT_INF_PERIOD_MS,
    PERFTEST_OPT_ENABLE_ERR_CONTINUE,
    PERFTEST_OPT_NOTIFY_DATA,
    PERFTEST_OPT_ENABLE_USER_TP,
    PERFTEST_OPT_OOR_EN,
    PERFTEST_OPT_SPRAY_EN,
    PERFTEST_OPT_CC_EN,
    PERFTEST_OPT_CC_ALG,
    PERFTEST_OPT_RETRY_NUM,
    PERFTEST_OPT_ACK_TIMEOUT,
    PERFTEST_OPT_SGE_NUM,
    PERFTEST_OPT_WRITE_DIRTY,
    PERFTEST_OPT_PAIR_NUM,
    PERFTEST_OPT_ASYNC_CONNECT,
    PERFTEST_OPT_TP_AWARE,
    PERFTEST_OPT_TP_REUSE,
    PERFTEST_OPT_CTP,
    PERFTEST_OPT_SINGLE_PATH,
    PERFTEST_OPT_JETTY_ID,
    PERFTEST_OPT_WAIT_JFC_TIMEOUT,
    PERFTEST_OPT_PAGE_SIZE,
    PERFTEST_OPT_AGGR_MODE,
};

typedef enum perftest_rate_limiter_units {
    PERFTEST_RATE_LIMIT_MEGA_BYTE,
    PERFTEST_RATE_LIMIT_GIGA_BIT,
    PERFTEST_RATE_LIMIT_PS
} perftest_rate_limiter_units_t;

typedef struct perftest_config {
    perftest_cmd_type_t cmd;
    perftest_type_t type;
    uint32_t eid_idx;
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
    uint32_t order_type;

    uint32_t cache_line_size;
    uint64_t page_size;
    bool use_flat_api;                  /* Choose to use flat API, only works in PERFTEST_JETTY_SIMPLEX mode. */
    bool cpu_freq_f;                    /* To report warnings when CPU frequency drifts. */
    bool warm_up;                       /* Warm_up is only available for read/write/atomic bw test. */
    bool bidirection;                   /* Bidirectional only supports BW test. */
    bool jfc_inline;
    uint32_t inf_period;                /* Print period for infinite mode, default 2 seconds. */
    uint32_t inf_period_ms;                    /* ms-level print for infinite mode, default 2 seconds. */
    uint32_t order;                     /* Set max order of 2, only used for ALL. */
    uint8_t err_timeout;
    bool lock_free;
    uint8_t priority;
    bool share_jfr;
    uint32_t jettys_pre_jfr;           /* How many jettys share a jfr. */
    perftest_comm_t comm;

    /* Rate Limiter */
    bool is_rate_limit;
    double rate_limit;
    uint32_t burst_size;
    perftest_rate_limiter_units_t rate_units;
    uint64_t gap_cycles;

    /* send credit */
    bool enable_credit;
    uint32_t credit_threshold;
    uint32_t credit_notify_cnt;

    bool seg_pre_jetty;

    bool enable_imm;
    bool enable_notify;
    uint64_t notify_data;
    bool enable_err_continue;

    /* user tp */
    bool enable_user_tp;
    bool oor_en;
    bool spray_en;
    bool cc_en;
    uint32_t cc_alg;
    uint32_t retry_num;
    uint32_t ack_timeout;

    uint32_t sge_num;

    bool enable_write_dirty;
    uint32_t write_dirty_period;
    uint32_t pair_num;
    bool pair_flag;
    uint8_t group_id;

    bool enable_async_import;
    bool use_bonding;
    bool single_path;
    bool tp_aware;
    bool tp_reuse;
    bool use_ctp;
    uint32_t jetty_id;
    int32_t wait_jfc_timeout;
    urma_huge_page_size_t huge_page;
    bool use_huge_page;
    bool enable_aggr_mode;
    uint32_t aggr_mode;
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

static inline bool perftest_check_rs_mode(const perftest_config_t *cfg)
{
    return cfg->trans_mode == URMA_TM_RC && (cfg->order_type & URMA_OT);
};

void print_cfg(const perftest_config_t *cfg);
int perftest_parse_args(int argc, char *argv[], perftest_config_t *cfg);
void destroy_cfg(perftest_config_t *cfg);
int check_local_cfg(perftest_config_t *cfg);
int check_remote_cfg(perftest_config_t *cfg);
bool is_jfr_depth_valid(perftest_config_t *cfg);
int establish_connection(perftest_config_t *cfg);
void close_connection(perftest_config_t *cfg);

#endif
