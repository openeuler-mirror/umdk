/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urpclib test_framework
*/

#ifndef URPC_LIB_ATOM_H
#define URPC_LIB_ATOM_H

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <algorithm>
#include <limits.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include "../../../../../src/urpc/include/framework/urpc_framework_api.h"
#include "../../../../../src/urpc/include/framework/urpc_framework_errno.h"
#include "../common/common.h"

#define THREAD_NAME_MAX_LEN 16
#define URPC_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#define URPC_EID_STR_MIN_LEN 3
#define TEST_MAX_BUF_LEN (1024)

#define ALLOCATOR_SIZE (64 * 1024 * 1024)
#define ALLOCATOR_BLOCK_SIZE (4 * 1024)
#define ALLOCATOR_BLOCK_COUNT (ALLOCATOR_SIZE / ALLOCATOR_BLOCK_SIZE) 
#define ALLOCATOR_BLOCK_NUM 2 
#define MAX_ALLOC_SIZE (ALLOCATOR_BLOCK_NUM * ALLOCATOR_SIZE)

#define CLOUD_STORAGE_PRIORITY 4
#define DEFAULT_PRIORITY CLOUD_STORAGE_PRIORITY

#define DEFAULT_MSG_SIZE ALLOCATOR_BLOCK_SIZE
#define DEFAULT_RX_BUF_SIZE 4096
#define DEFAULT_RX_DEPTH 64
#define DEFAULT_TX_DEPTH 64
#define DEFAULT_SERVER_NUM 1

#define CTRL_MSG_MAX_SIZE (64 * 1024)

#define DEFAULT_CHANNEL_NUM 1
#define DEFAULT_QUEUE_NUM 1

#define DEFAULT_FUNC_NAME "DEFAULT_FUNC_NAME"
#define DEFAULT_FUNC_ID 8388612

#define DEFAULT_INPUT_MSG_SIZE 20

#define DEFAULT_SSL_PSK_ID "urpc_lib_psk_id"
#define DEFAULT_SSL_PSK_KEY "urpc_lib_psk_key"

#define SERVER_POLL_TIMEOUT 300
#define CLINET_POLL_TIMEOUT 10
#define MILLISECOND_PER_SECOND 1000

#define URPC_CHANNEL_MAX_R_QUEUE_SIZE (256)
#define URPC_CLIENT_CHANNEL_ATTACH_MAX (16)
#define URPC_KEEPALIVE_MSG_MAX_SIZE (2000)

#define CTX_FLAG_URPC_INIT (1)
#define CTX_FLAG_CHANNEL_CREATE (1 << 2)
#define CTX_FLAG_QUEUE_CREATE (1 << 4)
#define CTX_FLAG_FUNC_REGISTER (1 << 5)
#define CTX_FLAG_SERVER_START (1 << 6)
#define CTX_FLAG_CHANNEL_ADD_LOCAL_QUEUE (1 << 7)
#define CTX_FLAG_SERVER_ATTACH (1 << 8)
#define CTX_FLAG_CHANNEL_ADD_REMOTE_QUEUE (1 << 9)
#define CTX_FLAG_QUEUE_PAIR (1 << 10)
#define CTX_FLAG_MEM_SEG_ACCESS_ENABLE (1 << 11)


#define RSP_ACK_SEND_PUSH_WITHOUT_PLOG 1
#define RSP_SEND_PUSH_WITHOUT_PLOG 2
#define ACK_SEND_PUSH_WITHOUT_PLOG 3
#define NO_ACK_RSP_SEND_PUSH_WITHOUT_PLOG 4

#define MAX_RX_SGE 4
#define MAX_TX_SGE 13

#define ASYNC_FLAG_ENABLE 4
#define ASYNC_FLAG_NOT_EPOLL 5
#define ASYNC_FLAG_BLOCK 0
#define ASYNC_FLAG_NON_BLOCK 1
#define ASYNC_FLAG_NON_BLOCK_NOT_POLL 2

#define MAX_DMC_CNT 169

typedef struct ref_read_idx {
    uint32_t dma_cnt;
    uint32_t dma_idx;
    uint64_t func_id;
    void * req_ctx;
    urpc_sge_t *req_sges[0];
} ref_read_idx_t;

typedef struct {
    uint64_t total_size;
    uint32_t allocator_size;
    uint32_t allocator_num;
    uint32_t block_size;
    uint32_t block_num;
} test_allocator_config_t;

typedef struct test_allocator_buf {
    char *buf;
    uint32_t block_len;
    uint32_t total_count;
    uint32_t free_count;
    char *block_head;
    uint64_t tsge;
    struct test_allocator_buf *next;
} test_allocator_buf_t;

typedef struct test_allocator_ctx {
    struct test_allocator_buf *allocator_buf;
    uint32_t total_count;
    uint32_t free_count;
} test_allocator_ctx_t;

typedef struct  {
    bool is_epoll;
    bool *is_polling;
    int *queue_fd;
    int epoll_fd;
    int epoll_timeout;
} queue_ops_t;

typedef struct {
    int epoll_fd;
    int event_fd;
    int flag;
} async_ops_t;

typedef struct {
    uint32_t qid[URPC_CHANNEL_MAX_R_QUEUE_SIZE];
    uint32_t num;
    uint32_t app_id;
} server_queue_t;

typedef struct {
uint64_t qh;
} lqueue_ops_t;

typedef struct {
    uint32_t qid;
    uint64_t qh;
} rqueue_ops_t;

typedef struct {
    uint32_t idx;
    uint32_t id;
    server_queue_t squeue;
    urpc_host_info_t server;
    urpc_channel_connect_option_t coption;
    uint32_t lqueue_num;
    uint32_t rqueue_num;
    lqueue_ops_t *lqueue_ops;
    rqueue_ops_t * rqueue_ops;
    bool flush_lqueue;
    bool flush_rqueue;
    bool not_one_by_one;
} channel_ops_t;

typedef struct {
    test_context_t *ctx;
    enum urpc_role instance_role;
    enum urpc_trans_mode trans_mode;
    uint32_t app_num;
    uint32_t app_id;
    uint64_t pid;
    uint32_t channel_num;
    uint32_t *channel_ids;
    uint32_t queue_num;
    uint64_t * queue_handles;
    uint64_t func_id;
    uint64_t ctx_flag;
    uint32_t qgrph_num;
    uint64_t *qgrphs;
    bool cp_is_ipv6;
    bool dp_is_ipv6;
    uint32_t server_num;
    char *unix_domain_file_path;
    uint32_t req_size;
    uint32_t rsp_size;
    channel_ops_t *channel_ops;
    queue_ops_t queue_ops;
    async_ops_t async_ops;
    urpc_config_t urpc_config;
    urpc_server_info_t *server_info;
    urpc_qcfg_create_t *queue_cfg;
    urpc_control_plane_config_t *urpc_cp_config;
    urpc_host_info_t *host_info;
    test_allocator_config_t allocator_config;
    urpc_log_config_t log_cfg;
    uint64_t attach_cb_count;
    uint64_t refresh_cb_count;
    uint64_t detach_cb_count;
    urpc_ctrl_msg_t *ctrl_msg;
    urpc_ctrl_cb_t ctrl_cb;
    urpc_ssl_config_t ssl_cfg;
    bool co_thd;
    bool not_one_by_one;
} test_urpc_ctx_t;

typedef void (*test_poll_cb_t)(void);

typedef struct {
    uint32_t channel_id;
    uint64_t lqueue_handle;
    uint64_t rqueue_handle;
    uint64_t expect_poll_num;
    uint32_t expect_hit_events;
    uint64_t timeout;
    uint64_t poll_timeout;
    uint64_t func_id;
    int func_define;
    int data_type;
    int is_not_poll;
    int is_push_to_pull;
    int is_send_write;
    int is_send_write_imm;
    int call_errno;
    uint64_t poll_tx_qh;
    uint64_t poll_rx_qh;
    urpc_call_option_t call_option;
    urpc_poll_option_t poll_opt;
    test_poll_cb_t poll_cb;
} test_func_args_t;

typedef struct server_thread_arg {
    int tid;
    test_func_args_t func_args;
    pthread_barrier_t *barrier;
    int ret;
    pthread_t thread;
} server_thread_arg_t;

typedef struct {
    int tid;
    int ret;
    int polled_num;
    urpc_poll_direction_t direction;
    pthread_barrier_t *barrier;
    pthread_t thread;
    bool do_rx_post;
} poll_thread_args_t;

typedef enum test_msg_type {
    WITHOUT_DMA,
    WITH_DMA,
} test_msg_type_t;

typedef struct custom_head {
    test_msg_type_t msg_type;
    uint32_t dma_num;
} custom_head_t;

typedef struct test_custom_read_dma {
    uint64_t address;
    uint32_t size;
    uint32_t token_id;
    uint32_t token_value;
} test_custom_read_dma_t;

typedef struct {
    FILE *fd;
    char file_name[MAX_FILE_NAME_LEN];
    int inited : 1;
} log_file_info_t;

extern test_allocator_ctx_t *g_test_allocator_ctx;
extern test_urpc_ctx_t g_test_urpc_ctx;
extern urpc_allocator_t g_test_allocator;
extern log_file_info_t *g_test_log_file;
extern bool g_server_exit;
extern bool g_test_all_queue_ready;

int test_str_to_u32(const char *buf, uint32_t *u32);
void test_urpc_u32_to_eid(uint32_t ipv4, urpc_eid_t *eid);
int test_urpc_str_to_eid(const char *buf,urpc_eid_t *eid);
int set_urpc_server_info(test_urpc_ctx_t *ctx, urpc_server_info_t *server, char ipv4[IPV6_ADDR_SIZE], char ipv6[IPV6_ADDR_SIZE], uint16_t port);
int set_urpc_host_info(test_urpc_ctx_t *ctx, urpc_host_info_t *host, char ipv4[IPV6_ADDR_SIZE], char ipv6[IPV6_ADDR_SIZE], uint16_t port);
int get_urpc_host_info(urpc_host_info_t *host_info, uint32_t idx = 0);
int process_ctrl_msg(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg);
int get_urpc_control_plane_config(urpc_control_plane_config_t *cfg, uint32_t idx = 0);
int get_urpc_server_info(urpc_server_info_t *server_info, uint32_t idx = 0);
test_urpc_ctx_t *test_urpc_ctx_init(int argc, char *argv[], int thread_num);
int test_urpc_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time = 2);

urpc_config_t get_init_mode_config(test_urpc_ctx_t *ctx, urpc_config_t urpc_config);
urpc_config_t get_urpc_server_config(test_urpc_ctx_t *ctx);
urpc_config_t get_urpc_client_config(test_urpc_ctx_t *ctx);
urpc_config_t get_urpc_server_client_config(test_urpc_ctx_t *ctx);

void set_ctx_ctrl_msg_param(test_urpc_ctx_t *ctx, char msg[CTRL_MSG_MAX_SIZE]);
int test_urpc_ctrl_msg_cb_register(test_urpc_ctx_t *ctx);
int test_async_event_ctrl_add(test_urpc_ctx_t *ctx);
int test_server_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config = nullptr);
int test_client_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config = nullptr);
int test_server_client_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config = nullptr);
void test_urpc_uninit(test_urpc_ctx_t *ctx);

int test_allocator_init(test_urpc_ctx_t *ctx);
int test_allocator_dynamic_expansion(test_urpc_ctx_t *ctx);
int test_allocator_register(test_urpc_ctx_t *ctx);
int test_allocator_unregister(test_urpc_ctx_t *ctx);

int test_channel_create(test_urpc_ctx_t *ctx);
int test_channel_destroy(test_urpc_ctx_t *ctx, uint32_t channel_id = URPC_U32_FAIL);

int test_server_start(test_urpc_ctx_t *ctx);

int test_mem_seg_remote_access_enable(test_urpc_ctx_t *ctx);
int test_mem_seg_remote_access_disable(test_urpc_ctx_t *ctx);


int set_queue_ops_interrupt(test_urpc_ctx_t *ctx, int *polling_arr = nullptr, int arr_size = 0);
int test_queue_interrupt_fd_get(test_urpc_ctx_t *ctx, uint32_t qidx);

int test_urpc_queue_rx_post(test_urpc_ctx_t *ctx, uint32_t rx_num, uint64_t urpc_qh = 0);
int test_queue_create(test_urpc_ctx_t *ctx, urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY, urpc_qcfg_create_t *queue_cfg = nullptr);
int test_destroy_one_queue(uint64_t queue_handle, uint32_t wait_time = 2, bool do_rx_post = false);
int test_queue_destroy(test_urpc_ctx_t *ctx, uint32_t wait_time = 2);

void test_urpc_handler_func(urpc_sge_t *args, uint32_t args_sge_num, void *ctx, urpc_sge_t **rsps, uint32_t *rsps_sge_num);
int test_func_register(test_urpc_ctx_t *ctx);
int test_func_unregister(test_urpc_ctx_t *ctx);

int wait_async_event_result(test_urpc_ctx_t *ctx, urpc_async_event_type_t type, int timeout = -1);
int test_async_event_get(urpc_async_event_type_t type, size_t wait_time_ms = 3000);

urpc_channel_connect_option_t get_channel_connect_option(bool set_ctrl_msg = false, int timeout = -1);
int test_channel_server_attach(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_host_info_t *host, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_channel_server_detach(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_host_info_t *host, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_channel_server_refresh(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_channel_queue_add(uint32_t channel_id, uint64_t queue_handle, bool is_remote = false, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_channel_queue_rm(uint32_t channel_id, uint64_t queue_handle, bool is_remote = false, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);

int test_server_attach(test_urpc_ctx_t *ctx, urpc_channel_connect_option_t *connect_option = nullptr);
int test_server_detach(test_urpc_ctx_t *ctx, urpc_channel_connect_option_t *connect_option = nullptr);
int rm_queue_from_channel_and_destroy(uint32_t channel_id, uint64_t queue_handle);
int test_flush_channel_lqueue(channel_ops_t *channel_ops);
int test_channel_add_local_queue(channel_ops_t *channel_ops);
int test_add_local_queue(test_urpc_ctx_t *ctx, bool flush_lqueue = true);
int test_flush_channel_rqueue(channel_ops_t *channel_ops);
int test_channel_add_remote_queue(channel_ops_t *channel_ops);
int test_add_remote_queue(test_urpc_ctx_t *ctx, bool flush_rqueue = true);
int test_channel_rm_local_queue(channel_ops_t *channel_ops, bool is_free = true);
int test_rm_local_queue(test_urpc_ctx_t *ctx, channel_ops_t *channel_ops = nullptr);
int test_channel_rm_remote_queue(channel_ops_t *channel_ops, bool is_free = true);
int test_rm_remote_queue(test_urpc_ctx_t *ctx, channel_ops_t *channel_ops = nullptr);
server_queue_t get_server_queue();
void test_qserver_stop(test_urpc_ctx_t *ctx);
int test_channel_get_server_queue(channel_ops_t *channel_ops);

int test_channel_queue_pair(test_urpc_ctx_t *ctx, uint32_t urpc_chid, uint64_t l_queue, uint64_t r_queue, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_channel_queue_unpair(test_urpc_ctx_t *ctx, uint32_t urpc_chid, uint64_t l_queue, uint64_t r_queue, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_normal_queue_pair(test_urpc_ctx_t *ctx, uint32_t channel_id = URPC_U32_FAIL, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);
int test_normal_queue_unpair(test_urpc_ctx_t *ctx, uint32_t channel_id = URPC_U32_FAIL, urpc_channel_connect_option_t *option = nullptr, size_t wait_time = 3000);

int test_channel_queue_add_attach(test_urpc_ctx_t *ctx);

void test_log_file_close(log_file_info_t **log_file_info = &g_test_log_file);

unsigned int test_client_psk_cb_func(void *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
unsigned int test_server_psk_cb_func(void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
int test_ssl_config_set(test_urpc_ctx_t *ctx);
int test_server_prepare(test_urpc_ctx_t *ctx, urpc_config_t *cfg = nullptr, urpc_queue_trans_mode_t queue_trans_mode = QUEUE_TRANS_MODE_JETTY);
int test_client_prepare(test_urpc_ctx_t *ctx, urpc_config_t *cfg = nullptr, urpc_queue_trans_mode_t queue_trans_mode = QUEUE_TRANS_MODE_JETTY);
int test_server_client_prepare(test_urpc_ctx_t *ctx, urpc_config_t *cfg = nullptr, urpc_queue_trans_mode_t queue_trans_mode = QUEUE_TRANS_MODE_JETTY);

int test_server_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time = 2);
int test_client_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time = 2);
int test_server_client_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time = 2);

const char *parse_poll_event(uint32_t event);
void handle_poll_event_req_recved(urpc_poll_msg_t *msg, uint64_t queue_handle, uint32_t *hit_events = nullptr);
void handle_poll_event_rsp_sended(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_req_acked(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_req_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_req_acked_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_rsp_err(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_req_err(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);
void handle_poll_event_err(urpc_poll_msg_t *msg, uint32_t *hit_events = nullptr);

int test_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint64_t queue_handle, uint32_t *hit_events = nullptr, bool do_rx_post = true);
uint32_t test_func_poll_one_queue(urpc_poll_option_t *option, urpc_poll_msg_t *msg, int num, bool do_rx_post = true);
uint32_t test_poll_one_queue_event(uint64_t queue_handle, uint32_t wait_time, uint32_t expect_nums = 0, bool do_rx_post = true);
void test_func_poll_all_queue(poll_thread_args_t *poll_args);
int start_poll_event_thread(int thread_num, poll_thread_args_t pargs[]);
void stop_poll_event_thread(int thread_num, poll_thread_args_t pargs[], uint32_t wait_time = 2);

void server_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint64_t queue_handle);
void set_server_exit_status(bool status);
int start_server_poll_thread(int thread_num, server_thread_arg_t targ[]);
int stop_server_poll_thread(int thread_num, server_thread_arg_t targ[]);
int test_server_run_response(test_func_args_t *func_args);

uint32_t client_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint32_t *hit_events, uint64_t queue_handle = 0);
int test_client_process_event(test_func_args_t *func_args);
void set_call_option_queue_handle(test_func_args_t *func_args, urpc_call_option_t *option);
void set_call_option_flag_rsp(urpc_call_option_t *option);
void set_call_option_flag_no_ack_rsp(urpc_call_option_t *option);
void set_func_args_hit_events_rsp(test_func_args_t *func_args);
void set_func_args_hit_events_no_ack_rsp(test_func_args_t *func_args);
int test_client_process_normal_call(test_func_args_t *func_args);
int test_client_process_call(test_func_args_t *func_args);
int test_client_run(test_func_args_t *func_args);
int test_func_call_read_custom(test_func_args_t *func_args);
int test_func_call_recv_rsp_no_ack(test_func_args_t *func_args);
int test_func_call_no_rsp_no_ack(test_func_args_t *func_args);
uint64_t create_original_queue(urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY);
uint64_t create_share_rq_queue(uint64_t share_rq_handler, urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY);
urpc_qcfg_get_t print_queue_cfg(uint64_t queue_handle);
int test_get_queue_stats(uint64_t queue_handle, uint64_t *stats_total);
void print_queue_stats(uint64_t *stats_total);
int test_func_call_all_type_by_one_channel(test_urpc_ctx_t *ctx, uint32_t channel_idx = 0);
int test_func_call_all_type(test_urpc_ctx_t *ctx);

int start_ipv6_server(char *ipv6_addr, uint16_t port);
int start_ipv4_server(char *ipv4_addr, uint16_t port);
int start_ipv6_client(char *ipv6_addr, uint16_t port);
int start_ipv4_client(char *ipv4_addr, uint16_t port);
log_file_info_t *test_create_file(const char *file_name);

#define NS_PER_SEC 1000000000UL
#define MS_PER_SEC 1000
#define NS_PER_MS 1000000
#define MAX_CONNECTIONS 100

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

#endif





