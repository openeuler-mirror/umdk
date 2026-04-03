/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma test_framework
*/
#ifndef URMA_ATOM_H
#define URMA_ATOM_H

#include "../../../../../src/urma/lib/urma/core/include/urma_api.h"
#include "../common/common.h"
#include "stdint.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ALPHABET_TOTAL 26
#define MAX_POLL_JFC_CNT 10
#define TEST_JETTY_DEPTH 1024
#define MAX_NUM_SGE 32
#define MAX_NUM_WR 32
#define SIZE_1K 0x400
#define SIZE_4K 0x1000
#define SIZE_64K 0x10000
#define SIZE_1M 0x100000
#define SIZE_128M 0x8000000
#define SIZE_1G 0x40000000
#define SIZE_2G 0x80000000
#define URMA_TEST_SLEEP_TIME 1000
#define URMA_TEST_POLL_CNT 1000
#define MSEC_IN_SEC 1000
#define EVENT_LIST_SIZE 32

#define TEST_DEFAULT_JFCE_NUM 1
#define TEST_DEFAULT_JFC_NUM 1
#define TEST_DEFAULT_JFR_NUM 3
#define TEST_DEFAULT_JFS_NUM 3
#define TEST_DEFAULT_JETTY_NUM 3
#define TEST_DEFAULT_SEG_NUM 4

#ifndef URMA_TYPICAL_RETRY_CNT
#define URMA_TYPICAL_RETRY_CNT 7
#endif

typedef struct test_jfc_cfg {
    uint32_t depth;       /* [Required] the depth of jfc, no greater than urma_device_cap_t->jfc_depth */
    urma_jfc_flag_t flag; /* [Optional] see urma_jfc_flag_t, set flag.value to be 0 by default */
    uint32_t ceqn;        /* [Optional] event queue id, no greater than urma_device_cap_t->ceq_cnt
                              set to 0 by default */
    uint32_t jfce_id;     /* [Required] the event of jfc */
    uint64_t user_ctx;    /* [Optional] private data of jfc, set to NULL by default */
} test_jfc_cfg_t;

typedef struct test_jfs_cfg {
    uint32_t depth;           /* [Required] the depth of jfs, defaut urma_device_cap_t->jfs_depth */
    urma_jfs_flag_t flag;     /* [Optional] see urma_jfs_flag_t definition */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t priority;         /* [Optional] set the priority of JFS, ranging from [0, 15]
                                 Services with low delay need to set high priority. */
    uint8_t max_sge;          /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint8_t max_rsge;         /* [Optional] max remote sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint32_t max_inline_data; /* [Optional] the max inline data size of JFS. if the parameter is 0,
                                 the system will assign device's max inline data length. */
    uint8_t rnr_retry;        /* [Optional] number of times that jfs will resend packets before report error,
                                 when the remote side is not ready to receive (RNR), ranging from [0, 7],
                                 the value 0 means never retry and,
                                 the value 7 means retry infinite number of times for RDMA devices */
    uint8_t err_timeout;      /* [Optional] the timeout before report error, ranging from [0, 31],
                                 the actual timeout in usec is caculated by: 4.096*(2^err_timeout) */
    uint32_t jfc_id;          /* [Required] need to specify jfc */
    uint64_t user_ctx;        /* [Optional] private data of jfs */
} test_jfs_cfg_t;

typedef struct test_jfr_cfg {
    uint32_t id;           /* [Optional] specify jfr id. If the parameter is 0,
                              the system will randomly assign a non-0 value. */
    uint32_t depth;        /* [Required] total depth, include berth, defaut urma_device_cap_t->jfr_depth. */
    urma_jfr_flag_t flag;  /* [Optional] whether is in TAG_matching, whether is in DC/IDC mode. */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t max_sge;       /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfr_sge. */
    uint8_t min_rnr_timer; /* [Optional] the minimum RNR NACK timer, ranging from [0, 31], i.e.
                              the time before jfr sends NACK to the sender for the reason of "ready to receive" */
    uint32_t jfc_id;       /* [Required] need to specify jfc. */
    urma_token_t token_value;       /* [Required] specify token_value for jfr. */
    uint64_t user_ctx;     /* [Optional] private data of jfr */
} test_jfr_cfg_t;

typedef struct test_jetty_cfg {
    uint32_t id;                 /* [Optional] user specified jetty id. */
    urma_jetty_flag_t flag;      /* [Optional] Connection or connection less */

    /* send configuration */
    test_jfs_cfg_t jfs_cfg;     /* [Required] see urma_jfs_cfg_t */

    /* recv configuration */
    struct {
        uint32_t jfr_id;     /* [Optional] shared jfr to receive msg */
        uint32_t jfc_id;     /* [Optional] To replace the jfc related to the above jfr */
    } shared;                /* [Optional] */
    test_jfr_cfg_t jfr_cfg;  /* [Optional] Parma to create an new internel jfr. */

    uint64_t user_ctx;           /* [Optional] private data of jetty */
    int bind_app_id;
    int bind_jetty_id;
} test_jetty_cfg_t;

typedef struct test_seg_cfg {
    uint64_t len;                 /* specify the length of the segment to be registered */
    urma_token_id_t *token_id;
    urma_token_t token_value;        /* Security authentication for access */
    urma_reg_seg_flag_t flag;
    uint64_t user_ctx;
    uint64_t iova;                /* user iova, maybe zero-based-address */
    void *va;                     /* 测试用的va */
    void *protect_va;             /* 实际malloc的va 预留4K防止测试越界 */
} test_seg_cfg_t;

typedef struct urma_local_ctx {
    urma_eid_t eid;
    uint32_t num_jfce;
    urma_jfce_t **jfce;
    uint32_t num_jfc;
    test_jfc_cfg_t *jfc_cfg;
    urma_jfc_t **jfc;
    uint32_t num_jfs;
    test_jfs_cfg_t *jfs_cfg;
    urma_jfs_t **jfs;
    uint32_t num_jfr;
    test_jfr_cfg_t *jfr_cfg;
    urma_jfr_t **jfr;
    uint32_t num_jetty;
    test_jetty_cfg_t *jetty_cfg;
    urma_jetty_t **jetty;
    uint32_t num_tseg;
    test_seg_cfg_t *seg_cfg;
    urma_target_seg_t **tseg;
} l_ctx_t;

typedef struct urma_remote_ctx {
    urma_eid_t eid;
    uint32_t num_jfr;
    urma_jfr_id_t *jfr_id;
    urma_target_jetty_t **tjfr;
    uint32_t num_jetty;
    urma_jetty_id_t *jetty_id;
    urma_target_jetty_t **tjetty;
    uint32_t num_tseg;
    urma_seg_t *seg;
    urma_target_seg_t **tseg;
} r_ctx_t;

typedef struct async_event_info {
    urma_async_event_t event_list[EVENT_LIST_SIZE];
    int event_num;
} async_event_info_t;

typedef struct test_urma_ctx {
    test_context_t *test_ctx;
    uint32_t app_num;
    uint32_t app_id;
    uint32_t uasid;
    int io_thread_num;
    urma_device_attr_t dev_attr;
    urma_context_t *urma_ctx;
    urma_transport_type_t tp_type;
    urma_transport_mode_t tp_mode;
    uint32_t tp_kind;
    uint32_t token_id_num;
    urma_token_id_t **token_id;
    urma_token_t token_value;

    l_ctx_t l_ctx;
    r_ctx_t *r_ctx;

    // 异步事件
    pthread_t ae_thread;
    pthread_mutex_t ae_lock;
    async_event_info_t ae_info;
    bool ae_thread_stop;
} test_urma_ctx_t;

test_urma_ctx_t *test_create_ctx(test_context_t *test_ctx);
void test_set_default_ctx(test_urma_ctx_t *ctx);
void test_set_default_ctx_num(test_urma_ctx_t *ctx);
void test_set_default_ctx_cfg(test_urma_ctx_t *ctx);
void test_set_default_ctx_calloc_buf(test_urma_ctx_t *ctx);
void test_set_default_ctx_jfc(test_urma_ctx_t *ctx);
void test_set_default_ctx_jfs(test_urma_ctx_t *ctx);
void test_set_default_ctx_jfr(test_urma_ctx_t *ctx);
void test_set_default_ctx_jetty(test_urma_ctx_t *ctx);
void test_set_default_ctx_seg(test_urma_ctx_t *ctx);
void test_delete_ctx(test_urma_ctx_t *ctx);

int test_init_urma();
int test_create_urma_ctx(test_urma_ctx_t *ctx);
urma_jfce_t *test_create_jfce(test_urma_ctx_t *ctx);
urma_jfc_t *test_create_jfc(test_urma_ctx_t *ctx, test_jfc_cfg_t test_jfc_cfg);
urma_jfs_t *test_create_jfs(test_urma_ctx_t *ctx, test_jfs_cfg_t test_jfs_cfg);
urma_jfr_t *test_create_jfr(test_urma_ctx_t *ctx, test_jfr_cfg_t test_jfr_cfg);
urma_jetty_t *test_create_jetty(test_urma_ctx_t *ctx, test_jetty_cfg_t test_jetty_cfg);
urma_target_seg_t *test_create_seg(test_urma_ctx_t *ctx, test_seg_cfg_t test_seg_cfg);
void test_ctx_import_jfr(test_urma_ctx_t *ctx, int r_ctx_id, int r_jetty_id);
void test_ctx_import_jetty(test_urma_ctx_t *ctx, int r_ctx_id, int r_jetty_id);
void test_ctx_import_seg(test_urma_ctx_t *ctx, int r_ctx_id, int r_jetty_id);
int test_ctx_unimport_seg(test_urma_ctx_t *ctx, int app, int id);
int test_ctx_unimport_jetty(test_urma_ctx_t *ctx, int app, int id);
int test_ctx_unimport_jfr(test_urma_ctx_t *ctx, int app, int id);

int test_create_resource(test_urma_ctx_t *ctx);
void test_delete_resource(test_urma_ctx_t *ctx);
int test_exchange_resource(test_urma_ctx_t *ctx);
int test_import_resource(test_urma_ctx_t *ctx);
void test_unimport_resource(test_urma_ctx_t *ctx);

int test_urma_post_jetty_recv_wr(const urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
int test_urma_post_jetty_send_wr(const urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
int test_poll_jfc_wait(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr, int timeout);

test_urma_ctx_t *create_default_ctx(test_context_t *test_ctx);
void delete_default_ctx(test_urma_ctx_t *ctx);

urma_jfs_wr_flag_t get_default_wr_flag();
void test_delete_jfs_wr(urma_jfs_wr_t *wr);
urma_jfs_wr_t *test_fill_jfs_wr_send(test_urma_ctx_t *ctx, uint64_t addr, uint32_t length, urma_target_seg_t *tseg);
void test_delete_jfr_wr(urma_jfr_wr_t *wr);
urma_jfr_wr_t *test_fill_jfr_wr(test_urma_ctx_t *ctx, uint64_t addr, uint32_t length, urma_target_seg_t *tseg);
void test_get_async_event_list(test_urma_ctx_t *ctx, async_event_info_t *ae_info, int timeout);
#endif