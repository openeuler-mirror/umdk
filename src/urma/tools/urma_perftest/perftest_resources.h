/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: resource operation header file for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef PERFTEST_RESOURCES_H
#define PERFTEST_RESOURCES_H

#include "urma_types.h"

#include "ub_util.h"

#include "perftest_parameters.h"
#include "ub_get_clock.h"

#define PERFTEST_BUF_NUM (2)
#define PERFTEST_MAX_BUF_LEN (1UL << PERFTEST_SIZE_ORDER)

#define PERFTEST_ALIGN_CACHELINE(size, cache_line_size) (((size) > (cache_line_size)) ? \
    ROUND_UP((size), (cache_line_size)) : (cache_line_size))

typedef enum duration_states {
    WARMUP_STATE,
    START_STATE,
    STOP_STATE,
    END_STATE
} duration_states_t;

typedef struct user_tp_ctx {
    urma_tp_cfg_t cfg;
    urma_tp_attr_t attr;
    uint32_t net_addr_cnt;
    urma_net_addr_info_t *net_addr_list;
} user_tp_ctx_t;

typedef struct run_test_ctx {
    uint32_t duration;
    volatile duration_states_t state;
    uint64_t rid;
    uint64_t *tposted;    // cycles
    uint64_t *tcompleted;  // cycles
    int rposted;
    uint64_t *scnt;
    uint64_t *ccnt;
    urma_jfs_wr_t *jfs_wr;
    urma_jfr_wr_t *jfr_wr;
    urma_sge_t *jfs_sge;
    urma_sge_t *jfr_sge;
    uint64_t *rx_buf_addr;

    urma_jfs_wr_t *credit_wr;
    urma_sge_t *credit_sge;
    urma_sge_t *remote_credit_sge;
} run_test_ctx_t;

typedef struct perftest_context {
    urma_eid_t eid;
    urma_context_t *urma_ctx;
    urma_device_attr_t dev_attr;
    urma_token_id_t **token_id;

    // jetty
    urma_jfce_t **jfce_r;
    urma_jfce_t **jfce_s;
    urma_jfc_t **jfc_r;
    urma_jfc_t **jfc_s;
    urma_jfs_t **jfs;
    urma_jfr_t **jfr;
    urma_jetty_t **jetty;
    uint32_t jetty_num;

    // buf
    uint64_t page_size;
    void **local_buf;
    uint64_t buf_size;
    uint64_t buf_len;     // buf_len = buf_size * PERFTEST_BUF_NUM
    urma_target_seg_t **local_tseg;

    // remote info
    urma_seg_t *remote_seg;
    urma_jetty_id_t *remote_jetty_id;

    // import seg
    urma_target_seg_t **import_tseg;
    // import jfr
    urma_target_jetty_t **import_tjfr;
    // import jetty
    urma_target_jetty_t **import_tjetty;

    // run test
    run_test_ctx_t run_ctx;
    bool infinite_print;

    /* send credit */
    uint64_t **ctrl_buf;
    urma_target_seg_t **credit_seg;
    urma_token_id_t **credit_token_id;
    urma_seg_t *remote_credit_seg;
    urma_target_seg_t **import_credit_seg;

    /* user tp */
    user_tp_ctx_t *user_tp;
    user_tp_ctx_t *remote_user_tp;

    /* write dirty thread */
    pthread_t write_dirty_thread_id;
} perftest_context_t;

typedef struct perftest_thread_arg {
    perftest_config_t *cfg;
    perftest_context_t *ctx;
    uint32_t id;
    pthread_t thread_id;
} perftest_thread_arg_t;

/* calculate sge addr offset and step forward. */
static inline void increase_loc_addr(urma_sge_t *sge, uint32_t size, uint64_t rcnt, uint64_t prim_addr,
    uint32_t cache_line_size, uint64_t page_size)
{
    sge->addr += PERFTEST_ALIGN_CACHELINE(size, cache_line_size);
    /* if sge addr reaches the end of cycle buffer, it returns to primary address. */
    if (((rcnt + 1) % (page_size / PERFTEST_ALIGN_CACHELINE(size, cache_line_size))) == 0) {
        sge->addr = prim_addr;
    }
}

int create_ctx(perftest_context_t *ctx, perftest_config_t *cfg);
void destroy_ctx(perftest_context_t *ctx, perftest_config_t *cfg);

/* Warm_up function is only available for READ/WRITE/ATOMIC bw test. */
int perform_warm_up(perftest_context_t *ctx, perftest_config_t *cfg);
#endif
