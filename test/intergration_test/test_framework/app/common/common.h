/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: common function
*/

#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include "test_log.h"
#include "test_thread_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TEST_SUCCESS
#define TEST_SUCCESS 0
#endif

#ifndef TEST_FAILED
#define TEST_FAILED (-1)
#endif

#define MAX_EXEC_CMD_RET_LEN (1024)
#define MAX_FACOTR_OPTIONS 100
#define MAX_HOST_NUM 2
#define PROC_1 1
#define PROC_2 2
#define PROC_3 3
#define PROC_4 4
#define LETTERS_NUM 26
#ifndef MAX_LINE_LENGTH
#define MAX_LINE_LENGTH 1024
#endif

#define IPV6_ADDR_SIZE 46
#define MAX_FILE_NAME_LEN (1024)

#ifndef MIN
#define MIN(A, B) ((A) < (B) ? (A) : (B))
#endif

#define CHKERR_JUMP(_cond, _msg, _label) \
    do { \
        if (_cond) { \
            if ((_msg) != "") { \
                TEST_LOG_ERROR("%s\n", (_msg)); \
            } \
            goto _label; \
        } \
    } while (0)

#define CHECK_JUMP(_cond, _label, ...) \
    do { \
        if (_cond) { \
            TEST_LOG_ERROR(__VA_ARGS__); \
            goto _label; \
        } \
    } while (0)

#define CHECK_FREE(p) \
    do { \
        if ((p) != NULL) { \
            free(p); \
            p = NULL; \
        } \
    } while (0)

typedef struct test_context {
    uint32_t app_num;
    uint32_t app_id;
    uint16_t tcp_port;
    char *server_ip;
    int listen_sock;
    int *sock;
    bool *not_sync;

    char *device_name;
    char *device_name2;
    uint32_t device_eid;
    char *eid;
    char *test_ip[MAX_HOST_NUM];
    char *test_mac;
    char *test_ipv6[MAX_HOST_NUM];
    uint16_t test_port;
    uint32_t seed;
    uint32_t mode;
    uint32_t tp_kind;
    char *ubsc_ip;
    void *xargs; /* 传入特定参数 */
    uint32_t ip_num;
    char **ip_addrs;
} test_context_t;

test_context_t *get_test_ctx();
void destroy_test_ctx(test_context_t *ctx);
static uint32_t parse_eid_htobe32(char *eid);
int parse_config(int argc, char *argv[]);
void free_config();
int sock_connect();
void sock_disconnect();
int test_recv_data(int sock, char *buf, int len, int timeout);
int sync_data(int src_app_id, char *buf, int len);
int sync_time(char const *local_data);
void get_random_string(char *s, int size, uint32_t *seed);
uint32_t get_random_u32(uint32_t *seed);
int test_common_init(int max_thread_num);
int test_common_deinit();
test_context_t *create_test_ctx(int argc, char *argv[], int thread_num);
int exec_cmd(char *rbuf, uint32_t rbuf_size, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H */