/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: umq test_framework
*/

#ifndef UMQ_ATOM_H
#define UMQ_ATOM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "../common/common.h"

#include "umq_api.h"
#include "umq_errno.h"
#include "umq_pro_api.h"

#define UMQ_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#define UMQ_EID_STR_MIN_LEN 3

#define CTX_FLAG_UMQ_INIT (1)
#define CTX_FLAG_UMQ_CREATE (1 << 1)
#define CTX_FLAG_UMQ_L_BINFO_GET (1 << 2)
#define CTX_FLAG_UMQ_BIND (1 << 3)

#define UMQ_DEFAULT_TX_DEPTH (128)
#define UMQ_DEFAULT_RX_DEPTH (128)
#define UMQ_DEFAULT_TX_BUF_SIZE (4096)
#define UMQ_DEFAULT_RX_BUF_SIZE (4096)
#define UMQ_QBUF_BLOCK_SIZE (8192)
#define UMQ_MAX_WR_COUNT (64)
#define TEST_UMQ_MAX_BIND_INFO_SIZE (4608)

#define DEQUEUE_SLEEP_TIME_US (100)
#define DEQUEUE_TIMEOUT_MS (30000)
#define DEFAULT_WAIT_TIME_MS (3000)
#define DEFAULT_FLUSH_TIME_MS (1000)
#define STATUS_SLEEP_TIME_US (10000)
#define TEST_MAX_POLL_BATCH (64)
#define TEST_IMM_DATA (123456)

#define CQ_EVENT_FLAG_DISABLE 0
#define CQ_EVENT_FLAG_ENABLE 1

typedef enum {
    TEST_TRANS_MODE_IP = 0,
    TEST_TRANS_MODE_UB,
    TEST_TRANS_MODE_IB,
    TEST_TRANS_MODE_IPC = 3,
    TEST_TRANS_MODE_UB_PLUS = 5,
    TEST_TRANS_MODE_UBMM_PLUS = 7,
} test_trans_mode_t;

typedef enum {
    SMALL_IO_NO_RSP = 0,
    SMALL_IO_HAS_RSP,
    BIG_IO_NO_RSP,
    BIG_IO_HAS_RSP,
} test_data_type_t;

typedef struct {
    uint32_t idx;
    uint64_t qh;
    umq_create_option_t option;
    int tx_fd;
    int rx_fd;
    int event_fd;
    uint32_t src_app_id;
    uint32_t dst_app_id;
    uint32_t r_qidx;
    uint32_t l_binfo_len;
    uint32_t r_binfo_len;
    uint8_t l_binfo[TEST_UMQ_MAX_BIND_INFO_SIZE];
    uint8_t r_binfo[TEST_UMQ_MAX_BIND_INFO_SIZE];
    umq_port_id_t used_ports[UMQ_MAX_ROUTES];
    uint8_t used_ports_num;
    bool not_check_data;
    umq_opcode_t opcode;
} umqh_ops_t;

typedef struct {
    uint32_t src_app_id;
    uint32_t dst_app_id;
    uint32_t l_qidx;
    uint32_t r_qidx;
    uint32_t bind_info_len;
    uint8_t bind_info[TEST_UMQ_MAX_BIND_INFO_SIZE];
} exchange_bind_info_t;

typedef struct {
    uint32_t src_app_id;
    uint32_t dst_app_id;
    uint32_t l_qidx;
    uint32_t r_qidx;
    uint32_t total_size;
    uint32_t data_size;
    test_data_type_t data_type;
    uint8_t digest[MD5_DIGEST_LENGTH];
    uint32_t rsvd2;
    uint64_t rsvd3;
    uint64_t rsvd4;
} test_data_header_t;

#define TEST_DATA_HEADER_SIZE sizeof(test_data_header_t)

typedef struct {
    int epoll_fd;
    int flag;
} umqh_async_ops_t;


typedef struct {
    test_context_t *ctx;
    uint32_t app_num;
    uint32_t app_id;
    uint64_t pid;
    uint16_t cna;
    uint32_t eid;
    umq_trans_mode_t trans_mode;
    umq_init_cfg_t cfg;
    uint32_t umqh_num;
    uint32_t umqh_sub_num;
    umqh_ops_t *umqh_ops;
    umqh_ops_t *umqh_sub_ops;
    umqh_async_ops_t async_ops;
    uint32_t ctx_flag;
    umq_log_config_t log_cfg;
    bool is_self_log;
    bool is_share_jfr;
    umq_tp_mode_t tp_mode;
    umq_tp_type_t tp_type;
    bool is_lock_free;
    bool is_bonding;

} test_umq_ctx_t;

typedef struct {
    test_data_type_t data_type;
    uint32_t data_size;
    char *data;
    umqh_ops_t *umqh_ops;
    bool is_not_poll;
    uint32_t *seed;
} test_data_args_t;

extern test_umq_ctx_t g_test_umq_ctx;
extern const char *ENQUEUE_DATA_DEFAUT;
extern size_t enqueue_data_len;
extern const char * POST_DATA_DEFAUT;
extern size_t post_data_len;

#define NS_PER_SEC 1000000000UL
#define MS_PER_SEC 1000
#define NS_PER_MS 1000000

#define EID_FMT          "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_RAW_ARGS(eid)                                                                                              \
    eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], eid[10], eid[11], eid[12],         \
        eid[13], eid[14], eid[15]
#define EID_ARGS(eid)             EID_RAW_ARGS((eid).raw)

static inline uint64_t get_timestamp_ns(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return (uint64_t)(tc.tv_sec * NS_PER_SEC + tc.tv_nsec);
}

static inline uint64_t get_timestamp_ms(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return (uint64_t)tc.tv_sec * MS_PER_SEC + tc.tv_nsec / NS_PER_MS;
}

static inline uint64_t get_timestamp_s(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return tc.tv_sec;
}

int test_umq_str_to_eid(const char *buf, umq_eid_t *eid);
void test_get_ubmm_cna(test_umq_ctx_t *ctx);
void test_get_ubmm_eid(test_umq_ctx_t *ctx);
test_umq_ctx_t *test_umq_ctx_init(int argc, char *argv[], int thread_num = 1);
int test_umq_ctx_uninit(test_umq_ctx_t *ctx);
int set_trans_dev_info(test_umq_ctx_t *ctx, umq_dev_assign_t *dev_info, umq_dev_assign_mode_t assign_mode);
int set_umq_init_cfg(test_umq_ctx_t *ctx, umq_dev_assign_mode_t assign_mode, umq_trans_mode_t trans_mode);
int test_umq_init(test_umq_ctx_t *ctx, bool set_default = true);
void test_umq_uninit(test_umq_ctx_t *ctx);
int set_umq_creat_option(test_umq_ctx_t *ctx, bool all_interrupt = false);
int test_umq_create(test_umq_ctx_t *ctx, bool set_default = true);
int test_umq_destroy(test_umq_ctx_t *ctx);
int test_umq_bind_info_get(test_umq_ctx_t *ctx);
void test_exchange_bind_info(test_umq_ctx_t *ctx, uint32_t src_app_id, uint32_t dst_app_id, uint32_t l_qidx, uint32_t r_qidx);
void test_umq_bind_info_exchange(test_umq_ctx_t *ctx);
int test_umq_bind_one(umqh_ops_t *umqh_ops);
int test_umq_unbind_one(umqh_ops_t *umqh_ops);
int test_umq_bind(test_umq_ctx_t *ctx);
int test_umq_unbind(test_umq_ctx_t *ctx);
int test_umq_prepare(test_umq_ctx_t *ctx);
int test_umq_undo_prepare(test_umq_ctx_t *ctx);

uint64_t get_buf_alloc_umqh(umqh_ops_t *umqh_ops, uint32_t data_size);
umq_buf_t *test_umq_buf_alloc(umqh_ops_t *umqh_ops, umq_alloc_option_t *option, const char *data, uint32_t data_size);
int test_umq_buf_fill(umqh_ops_t *umqh_ops, umq_buf_t *buf, const char *data, uint32_t data_size);
int test_umq_buf_parse(umq_buf_t *buf, const char *data, uint32_t data_size);
int test_umq_rearm_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, bool solicated = false);
int test_umq_wait_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, int timeout = DEFAULT_WAIT_TIME_MS);
int test_umq_get_cq_event(umqh_ops_t *umqh_ops, umq_io_direction_t direction, int timeout = -1);
void test_umq_ack_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, uint32_t nevents);
void test_data_args_fill(test_data_args_t *data_args);

int test_umq_post_rx_buf(umqh_ops_t *umqh_ops, uint32_t depth = 0, uint32_t size = 0, uint64_t *status = NULL);
int test_umq_post_rx(test_umq_ctx_t *ctx, uint32_t depth = 0, umqh_ops_t *umqh_ops = nullptr, uint64_t *status = NULL);
int test_umq_post_tx_buf(umqh_ops_t *umqh_ops, const char *data = POST_DATA_DEFAUT, uint32_t data_size = post_data_len, uint64_t *status = NULL);
int test_umq_poll(uint64_t umqh, umq_io_option_t *option, umq_buf_t **buf, uint32_t buf_count = TEST_MAX_POLL_BATCH, uint64_t timeout  = DEQUEUE_TIMEOUT_MS);
int test_umq_poll_tx_buf(umqh_ops_t *umqh_ops, uint64_t timeout = DEQUEUE_TIMEOUT_MS, uint64_t *status = NULL);
int test_umq_poll_rx_buf(umqh_ops_t *umqh_ops, const char *data = POST_DATA_DEFAUT, uint32_t data_size = post_data_len, uint64_t timeout = DEQUEUE_TIMEOUT_MS, uint64_t *status = NULL);
void test_umq_flush(umqh_ops_t *umqh_ops, umq_io_direction_t direction = UMQ_IO_ALL, uint64_t timeout = DEFAULT_FLUSH_TIME_MS);
int test_umq_pro_func_req(test_data_args_t *data_args);
int test_umq_pro_func_rsp(test_data_args_t *data_args);
int get_used_ports(test_umq_ctx_t *ctx, umqh_ops_t *umqh_ops);

#endif