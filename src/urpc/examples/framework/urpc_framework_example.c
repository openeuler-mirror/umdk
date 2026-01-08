/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc example to use urpc lib
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <pthread.h>
#include "urpc_framework_api.h"
#include "urma_types.h"
#include "urpc_framework_errno.h"
#include "urpc_framework_common.h"
#include "urpc_framework_server.h"
#include "urpc_framework_client.h"

#define ALLOCATOR_SIZE (16 * 1024 * 1024)
#define ALLOCATOR_BLOCK_SIZE (4 * 1024)
#define ALLOCATOR_BLOCK_COUNT (ALLOCATOR_SIZE / ALLOCATOR_BLOCK_SIZE)
#define ALLOCATOR_BLOCK_NUM 2
#define MAX_ALLOC_SIZE (2 * 16 * 1024 * 1024)
#define SGE_SIZE 4096
#define STATS_MSG_SIZE 1024
#define KEEPALIVE_CYCLE_TIME 3
#define KEEPALIVE_CHECK_TIME 9
#define KEEPALIVE_RELEASE_TIME 5
#define KEEPALIVE_USER_CTX   123456
#define KEEPALIVE_MSG_SIZE   1024
#define KEEPALIVE_SLEEP_TIME 5
#define GET_ASYNC_EVENT_RETRY_TIMES 5
#define CTRL_MSG_MAX_SIZE (1 << 16)
#define CANCEL_DELAY_SLEEP_TIME 1000
#define CONNECT_TIMEOUT_MS 30000    // Connection timeout after 30000 ms
#define CANCEL_OVER_WAIT_SLEEP_TIME 1
#define ALIGNED_SIZE 4096 // Memory alignment method

urpc_lib_example_config_t g_cfg = { 0 };
volatile sig_atomic_t g_poll_exit = 0;
int g_epoll_fd = -1;

typedef struct example_case {
    example_case_type_t case_idx;
    char *name;
    int (*client)(
        uint32_t chid, uint64_t qh, urpc_channel_qinfos_t *qinfos, uint64_t func_id, const urpc_allocator_t *allocator);
    int (*server)(uint64_t qh, uint64_t qh1, const urpc_allocator_t *allocator);
} example_case_t;

typedef struct allocator_buf {
    char *buf;
    uint32_t block_len;
    uint32_t total_count;
    uint32_t free_count;
    char *block_head;
    uint64_t tsge;
    struct allocator_buf *next;
} allocator_buf_t;

typedef struct allocator_ctx {
    struct allocator_buf *abuf;
    uint32_t tcount;
    uint32_t ecount;
} allocator_ctx_t;

typedef struct remote_qid {
    int num;
    uint32_t rqid[256];
} remote_qid_t;

static struct allocator_ctx *g_allocator_ctx = NULL;
static pthread_mutex_t g_allocator_lock = PTHREAD_MUTEX_INITIALIZER;

static urpc_allocator_t *g_used_allocator = NULL;
static remote_qid_t g_server_rqid_array = {0};
static remote_qid_t g_client_recv_rqid = {0};
static struct option g_long_options[] = {
    {"dev",          required_argument, NULL, 'd'},
    {"file-path",    required_argument, NULL, 'F'},
    {"port",         required_argument, NULL, 'p'},
    {"ip-address",   required_argument, NULL, 'i'},
    {"example-mode", required_argument, NULL, 'e'},
    {"eid",          required_argument, NULL, 'E'},
    {"shared-rq",    no_argument,       NULL, 'R'},
    {"shared-tx-cq", no_argument,       NULL, 'b'},
    /* Long options only */
    {"server",       no_argument,       NULL, 's'},
    {"client",       no_argument,       NULL, 'c'},
    {"ipv6",         required_argument, NULL, 'A'},
    {"func-id",      required_argument, NULL, 'f'},
    {"trans-mode",   required_argument, NULL, 'T'},
    {"use_ssl",      no_argument,       NULL, 'S'},
    {"psk_id",       required_argument, NULL, 'I'},
    {"psk_key",      required_argument, NULL, 'K'},
    {"multiplex",    no_argument,       NULL, 'm'},
    {"cancel",       no_argument,       NULL, 'C'},
    {"assign_mode",  required_argument, NULL, 'a'},
    {NULL,           0,                 NULL,  0 }
};

static const char *g_log_level_to_str[URPC_LOG_LEVEL_MAX] = {"EMERG", "ALERT", "CRIT", "ERROR", "WARNING",
                                                             "NOTICE", "INFO", "DEBUG"};
static char g_tcp_psk_cipher_list[] = "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384";
static char g_tcp_psk_cipher_suites[] = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
static int wait_result(uint16_t *event_list, uint32_t event_num);

void get_current_time(char *buffer, uint32_t len)
{
    if (buffer == NULL || len < 1) {
        return;
    }

    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    if (localtime_r(&tv.tv_sec, &tm) == NULL) {
        buffer[0] = '\0';
        return;
    }

    int ret = snprintf(
        buffer, len - 1, "%02d%02d %02d:%02d:%02d", tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (ret < 0) {
        buffer[0] = '\0';
    }
}

void urpc_allocator_buf_init(struct allocator_buf *ptr)
{
    uint32_t i;
    for (i = 0; i < ptr->total_count - 1; i++) {
        *(uint32_t *)(ptr->buf + i * ALLOCATOR_BLOCK_SIZE) = i + 1;
    }
    *(uint32_t *)(ptr->buf + i * ALLOCATOR_BLOCK_SIZE) = UINT32_MAX;
}

static void keepalive_callback(urpc_keepalive_event_type_t type, urpc_keepalive_event_info_t info)
{
    switch (type) {
        case URPC_KEEPALIVE_FAILED:
            LOG_PRINT("client id[%lu] peer_pid[%u] keep alive failed for [%u] seconds\n",
                info.user_ctx, info.peer_pid, info.inactivated_time);
            break;
        case URPC_KEEPALIVE_MSG_RECEIVED:
            LOG_PRINT("client id[%lu] peer_pid[%u] send keep alive msg=%s\n",
                info.user_ctx, info.peer_pid, (char *)(uintptr_t)info.user_msg.addr);
            break;
        case URPC_KEEPALIVE_RECOVER:
            LOG_PRINT("client id[%lu] recover peer_pid[%u] \n", info.user_ctx, info.peer_pid);
            break;
        default:
            break;
    }
}

static int ctrl_msg_callback(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg)
{
    remote_qid_t *info = (remote_qid_t *)(void *)ctrl_msg->msg;
    if (ctrl_msg->is_server) {
        // send msg
        info->num = g_server_rqid_array.num;
        for (int i = 0; i < info->num; i++) {
            info->rqid[i] = g_server_rqid_array.rqid[i];
        }
        ctrl_msg->msg_size = (uint32_t)sizeof(remote_qid_t);
    } else {
        // recv client ctl msg
        for (int i = 0; i < info->num; i++) {
            g_client_recv_rqid.rqid[i] = info->rqid[i];
            LOG_PRINT("recv rqueue id: %u\n", info->rqid[i]);
        }
        g_client_recv_rqid.num = info->num;
    }
    return URPC_SUCCESS;
}

char *urpc_allocator_buf_get_addr(struct allocator_buf *ptr, uint32_t num)
{
    return ptr->buf + num * ALLOCATOR_BLOCK_SIZE;
}

uint32_t urpc_allocator_buf_get_num(char *base, char *addr)
{
    return (uint32_t)((addr - base) / ALLOCATOR_BLOCK_SIZE);
}

int urpc_allocator_get(struct urpc_sge **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    (void)pthread_mutex_lock(&g_allocator_lock);
    uint32_t i = 0;
    if (num == NULL) {
        LOG_PRINT("num is NULL\n");
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }
    if (total_size > MAX_ALLOC_SIZE) {
        LOG_PRINT("total_size id too large:%lu\n", total_size);
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }
    uint32_t count = total_size % SGE_SIZE == 0 ? total_size / SGE_SIZE : total_size / SGE_SIZE + 1;
    if (g_allocator_ctx->ecount < count) {
        LOG_PRINT("no left room to allocator, left:%u, need:%u\n", g_allocator_ctx->ecount, count);
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }

    /* simulate alloc a send read save addr sge */
    uint32_t sge_alloc_count = (option != NULL && option->qcustom_flag == QCUSTOM_FLAG) ? count + 1 : count;

    struct urpc_sge *pr = (struct urpc_sge *)malloc(sizeof(struct urpc_sge) * sge_alloc_count);
    if (pr == NULL) {
        LOG_PRINT("malloc failed\n");
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }
    allocator_buf_t *ptr = g_allocator_ctx->abuf;
    for (i = 0; i < count; i++) {
        while (ptr != NULL && ptr->free_count <= 1) {
            ptr = ptr->next;
        }
        if (ptr == NULL) {
            LOG_PRINT("ptr is NULL\n");
            free(pr);
            (void)pthread_mutex_unlock(&g_allocator_lock);
            return URPC_FAIL;
        }
        pr[i].length = SGE_SIZE;
        pr[i].flag = 0;
        pr[i].addr = (uint64_t)(uintptr_t)ptr->block_head;
        pr[i].mem_h = ptr->tsge;
        ptr->block_head = urpc_allocator_buf_get_addr(ptr, *(uint32_t *)ptr->block_head);
        ptr->free_count -= 1;
    }

    g_allocator_ctx->ecount -= count;
    *num = (int)sge_alloc_count;
    *sge = pr;
    (void)pthread_mutex_unlock(&g_allocator_lock);
    return URPC_SUCCESS;
}

int urpc_allocator_get_raw_buf(struct urpc_sge *sge, uint64_t total_size, urpc_allocator_option_t *option)
{
    if (sge == NULL) {
        LOG_PRINT("sge or num is NULL\n");
        return URPC_FAIL;
    }
    if (total_size > MAX_ALLOC_SIZE) {
        LOG_PRINT("total_size id too large:%lu\n", total_size);
        return URPC_FAIL;
    }

    allocator_buf_t *ptr = g_allocator_ctx->abuf;
    while (ptr != NULL && ptr->free_count <= 1) {
        ptr = ptr->next;
    }
    if (ptr == NULL) {
        LOG_PRINT("ptr is NULL\n");
        return URPC_FAIL;
    }
    sge->length = total_size;
    sge->flag = 0;
    sge->addr = (uint64_t)(uintptr_t)ptr->block_head;
    sge->mem_h = ptr->tsge;
    ptr->block_head = urpc_allocator_buf_get_addr(ptr, *(uint32_t *)ptr->block_head);
    ptr->free_count -= 1;

    g_allocator_ctx->ecount -= 1;
    return URPC_SUCCESS;
}

int urpc_allocator_put(struct urpc_sge *sge, uint32_t num, urpc_allocator_option_t *option)
{
    (void)pthread_mutex_lock(&g_allocator_lock);
    uint32_t valid_sge_start = 0;
    if (num <= 0) {
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < num; i++) {
        if (sge[i].addr != 0) {
            break;
        }

        valid_sge_start++;
    }

    if (valid_sge_start == num) {
        LOG_PRINT("no valid sge\n");
        free(sge);
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }

    for (uint32_t i = valid_sge_start; i < num; i++) {
        if (sge[i].addr == 0) {
            LOG_PRINT("sge[i].addr is 0\n");
            continue;
        }

        allocator_buf_t *ptr = g_allocator_ctx->abuf;
        while (ptr != NULL) {
            if (sge[i].addr - (uintptr_t)ptr->buf < ALLOCATOR_SIZE) {
                break;
            }
            ptr = ptr->next;
        }

        if (ptr == NULL) {
            LOG_PRINT("ptr is NULL\n");
            free(sge);
            (void)pthread_mutex_unlock(&g_allocator_lock);
            return URPC_FAIL;
        }

        *(uint32_t *)(uintptr_t)sge[i].addr = urpc_allocator_buf_get_num(ptr->buf, ptr->block_head);
        ptr->block_head = (char *)(uintptr_t)sge[i].addr;
        ptr->free_count++;
        g_allocator_ctx->ecount++;
    }

    free(sge);
    (void)pthread_mutex_unlock(&g_allocator_lock);
    return URPC_SUCCESS;
}

int urpc_allocator_put_raw_buf(struct urpc_sge *sge, urpc_allocator_option_t *option)
{
    if (sge == NULL || sge[0].addr == 0) {
        LOG_PRINT("sge is NULL or addr is 0\n");
        return URPC_FAIL;
    }

    allocator_buf_t *ptr = g_allocator_ctx->abuf;
    while (ptr != NULL) {
        if (sge[0].addr - (uintptr_t)ptr->buf < ALLOCATOR_SIZE) {
            break;
        }
        ptr = ptr->next;
    }

    if (ptr == NULL) {
        return URPC_FAIL;
    }

    *(uint32_t *)(uintptr_t)sge->addr = urpc_allocator_buf_get_num(ptr->buf, ptr->block_head);
    ptr->block_head = (char *)(uintptr_t)sge->addr;
    ptr->free_count++;
    g_allocator_ctx->ecount += (uint32_t)1;
    return URPC_SUCCESS;
}

int urpc_allocator_get_sges(urpc_sge_t **sge, uint32_t num, urpc_allocator_option_t *option)
{
    if (num == 0) {
        LOG_PRINT("num is 0\n");
        return URPC_FAIL;
    }

    urpc_sge_t *tmp_sge = calloc(num, sizeof(urpc_sge_t));
    if (tmp_sge == NULL) {
        LOG_PRINT("calloc sge failed\n");
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < num; i++) {
        tmp_sge[i].flag = SGE_FLAG_NO_MEM;
    }

    *sge = tmp_sge;

    return URPC_SUCCESS;
}

int urpc_allocator_put_sges(urpc_sge_t *sge, urpc_allocator_option_t *option)
{
    if (sge == NULL) {
        LOG_PRINT("sge is NULL\n");
        return URPC_FAIL;
    }

    free(sge);
    return URPC_SUCCESS;
}

int urpc_allocator_uninit_default(void)
{
    (void)pthread_mutex_lock(&g_allocator_lock);
    allocator_buf_t *ptr = g_allocator_ctx->abuf;
    allocator_buf_t *ptr1 = NULL;
    while (ptr != NULL) {
        ptr1 = ptr->next;
        (void)urpc_mem_seg_unregister(ptr->tsge);
        free(ptr->buf);
        free(ptr);
        ptr = ptr1;
    }
    free(g_allocator_ctx);
    g_allocator_ctx = NULL;
    (void)pthread_mutex_unlock(&g_allocator_lock);
    return URPC_SUCCESS;
}

int urpc_allocator_init_default(void)
{
    (void)pthread_mutex_lock(&g_allocator_lock);
    g_allocator_ctx = (allocator_ctx_t *)calloc(1, sizeof(allocator_ctx_t));
    if (g_allocator_ctx == NULL) {
        LOG_PRINT("calloc g_allocator_ctx failed\n");
        (void)pthread_mutex_unlock(&g_allocator_lock);
        return URPC_FAIL;
    }

    g_allocator_ctx->abuf = (allocator_buf_t *)calloc(1, sizeof(allocator_buf_t));
    if (g_allocator_ctx->abuf == NULL) {
        LOG_PRINT("calloc g_allocator_ctx abuf failed\n");
        goto free_buf;
    }
    struct allocator_buf *ptr = g_allocator_ctx->abuf;
    for (int i = 0; i < ALLOCATOR_BLOCK_NUM; i++) {
        ptr->buf = (char *)aligned_alloc(ALIGNED_SIZE, sizeof(char) * ALLOCATOR_SIZE);
        if (ptr->buf == NULL) {
            LOG_PRINT("calloc g_allocator_ctx buf failed\n");
            goto free_buf;
        }
        ptr->block_len = ALLOCATOR_SIZE;
        ptr->total_count = ALLOCATOR_BLOCK_COUNT;
        ptr->free_count = ptr->total_count;
        ptr->tsge = urpc_mem_seg_register((uint64_t)(uintptr_t)ptr->buf, (uint64_t)ptr->block_len);
        ptr->block_head = ptr->buf;
        ptr->next = NULL;
        urpc_allocator_buf_init(ptr);
        g_allocator_ctx->tcount += ptr->total_count;
        g_allocator_ctx->ecount += ptr->free_count;

        if (i < ALLOCATOR_BLOCK_NUM - 1) {
            ptr->next = (allocator_buf_t *)calloc(1, sizeof(allocator_buf_t));
            if (ptr->next == NULL) {
                LOG_PRINT("calloc g_allocator_ctx buf failed\n");
                goto free_buf;
            }
        }
        ptr = ptr->next;
    }
    (void)pthread_mutex_unlock(&g_allocator_lock);
    return URPC_SUCCESS;

free_buf:
    (void)pthread_mutex_unlock(&g_allocator_lock);
    (void)urpc_allocator_uninit_default();
    return URPC_FAIL;
}

static urpc_allocator_t g_allocator = {
    .get = urpc_allocator_get,
    .put = urpc_allocator_put,
    .get_raw_buf = urpc_allocator_get_raw_buf,
    .put_raw_buf = urpc_allocator_put_raw_buf,
    .get_sges = urpc_allocator_get_sges,
    .put_sges = urpc_allocator_put_sges,
};

void default_output(int level, char *log_msg)
{
    struct timeval tval;
    struct tm time;
    (void)gettimeofday(&tval, NULL);
    (void)localtime_r(&tval.tv_sec, &time);
    (void)fprintf(stdout, "%02d%02d %02d:%02d:%02d.%06ld|%s|%s", time.tm_mon + 1, time.tm_mday, time.tm_hour,
                  time.tm_min, time.tm_sec, (long)tval.tv_usec, g_log_level_to_str[level], log_msg);
}

example_case_t g_example_case[] = {
    {
        .case_idx = EARLY_RESPONSE,
        .name = "early response",
        .client = client_run,
        .server = server_run_early_response
    }
};

static int fill_client_urpc_config(urpc_lib_example_config_t *cfg, urpc_config_t *urpc_config)
{
    urpc_config->role = URPC_ROLE_CLIENT;
    urpc_config->feature = URPC_FEATURE_TIMEOUT | URPC_FEATURE_DISABLE_TOKEN_POLICY;
    if (cfg->multiplex_enabled) {
        urpc_config->feature |= URPC_FEATURE_MULTIPLEX;
    }
    urpc_config->keepalive_cfg.keepalive_cycle_time = KEEPALIVE_CYCLE_TIME;
    urpc_config->keepalive_cfg.keepalive_check_time = KEEPALIVE_CHECK_TIME;
    urpc_config->keepalive_cfg.delay_release_time = KEEPALIVE_RELEASE_TIME;
    urpc_config->keepalive_cfg.user_ctx = KEEPALIVE_USER_CTX;
    urpc_config->trans_info_num = 1;
    urpc_config->trans_info[0].trans_mode = (urpc_trans_mode_t)cfg->trans_mode;
    urpc_config->trans_info[0].assign_mode = cfg->dev_assign_mode;
    if (cfg->dev_assign_mode == DEV_ASSIGN_MODE_EID) {
        (void)urma_str_to_eid(cfg->eid, (urma_eid_t *)(uintptr_t)&urpc_config->trans_info[0].ub.eid);
    } else {
        if (snprintf(urpc_config->trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", cfg->dev_name) < 0) {
            LOG_PRINT("snprintf dev_name failed\n");
            return URPC_FAIL;
        }
        urpc_config->trans_info[0].dev.is_ipv6 = cfg->ipv6 ? 1 : 0;
    }
    urpc_config->unix_domain_file_path = cfg->path;
    return URPC_SUCCESS;
}

static int fill_client_attach_info(urpc_lib_example_config_t *cfg, urpc_server_info_t *server_info)
{
    if (cfg->attach_ipv6) {
        server_info->server_type = SERVER_TYPE_IPV6;
        server_info->ipv6.port = cfg->port;
        memcpy(server_info->ipv6.ip_addr, cfg->ip_addr, strlen(cfg->ip_addr));
        if (cfg->bind_local_addr_enabled) {
            server_info->assigned_addr.bind_local_addr_enabled = true;
            server_info->assigned_addr.port = cfg->loc_port;
            memcpy(server_info->assigned_addr.ipv6_addr, cfg->loc_ip_addr, strlen(cfg->loc_ip_addr));
        }
        return 0;
    }

    server_info->server_type = SERVER_TYPE_IPV4;
    server_info->ipv4.port = cfg->port;
    memcpy(server_info->ipv4.ip_addr, cfg->ip_addr, strlen(cfg->ip_addr));
    if (cfg->bind_local_addr_enabled) {
        server_info->assigned_addr.bind_local_addr_enabled = true;
        server_info->assigned_addr.port = cfg->loc_port;
        memcpy(server_info->assigned_addr.ipv4_addr, cfg->loc_ip_addr, strlen(cfg->loc_ip_addr));
    }

    return 0;
}

static void show_queue_stats(uint64_t qh)
{
    uint64_t stats[STATS_TYPE_MAX] = {0};
    if (urpc_queue_stats_get(qh, stats, STATS_TYPE_MAX) != URPC_SUCCESS) {
        LOG_PRINT("get queue stats failed\n");
        return;
    }

    char stats_msg[STATS_MSG_SIZE] = {0};
    for (int i = 0; i < STATS_TYPE_MAX; i++) {
        if (stats[i] != 0) {
            if (snprintf(stats_msg + strlen(stats_msg), STATS_MSG_SIZE - strlen(stats_msg),
                "[%s: %lu] ", urpc_queue_stats_name_get(i), stats[i]) < 0) {
                LOG_PRINT("snprintf stats_msg failed\n");
                return;
            }
        }
    }

    if (strlen(stats_msg) == 0) {
        return;
    }

    LOG_PRINT("queue stats: %s\n", stats_msg);
}

int check_and_fill_cfg(urpc_lib_example_config_t *cfg, urpc_config_t *urpc_config)
{
    if (cfg->dev_name == NULL || cfg->ip_addr == NULL) {
        LOG_PRINT("invalid arguments\n");
        return URPC_FAIL;
    }

    if (fill_client_urpc_config(cfg, urpc_config) != URPC_SUCCESS) {
        LOG_PRINT("fill_client_urpc_config failed\n");
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

int client_run_test(uint32_t chid, uint64_t qh, uint64_t qh1, urpc_channel_qinfos_t *qinfos,
    urpc_lib_example_config_t *cfg)
{
    int ret = 0;
    ret = client_run(chid, qh, qinfos, cfg->func_id, g_used_allocator);
    if (ret || (!cfg->enable_shared_jfr && !cfg->enable_shared_jfs_jfc)) {
        return ret;
    }

    ret = client_run(chid, qh1, qinfos, cfg->func_id, g_used_allocator);
    return ret;
}

unsigned int client_psk_cb_func(void *ssl, const char *hint, char *identity,
                                unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len)
{
    if ((strnlen(g_cfg.psk_id, max_identity_len) == max_identity_len) ||
        (strnlen(g_cfg.psk_key, max_psk_len) == max_psk_len)) {
        LOG_PRINT("psk id or psk key buffer is not sufficient\n");
        return 0;
    }
    (void)snprintf(identity, max_identity_len, "%s", g_cfg.psk_id);
    memcpy(psk, g_cfg.psk_key, strlen(g_cfg.psk_key));
    return strnlen(g_cfg.psk_key, max_psk_len);
}

unsigned int server_psk_cb_func(void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
    if (strcmp(g_cfg.psk_id, identity) != 0) {
        LOG_PRINT("unknown client's psk id\n");
        return 0;
    }
    if (strnlen(g_cfg.psk_key, max_psk_len) == max_psk_len) {
        LOG_PRINT("no enough buffer to copy psk key\n");
        return 0;
    }
    memcpy(psk, g_cfg.psk_key, strlen(g_cfg.psk_key));
    return strnlen(g_cfg.psk_key, max_psk_len);
}

static void fill_ssl_config(urpc_lib_example_config_t *cfg, urpc_ssl_config_t *ssl_config, bool is_server)
{
    ssl_config->ssl_mode = SSL_MODE_PSK;
    ssl_config->ssl_flag |= URPC_SSL_FLAG_ENABLE;
    ssl_config->ssl_flag |= cfg->head_encrypt_disabled ? URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE : 0;
    ssl_config->ssl_flag |= cfg->payload_encrypt_disabled ? URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE : 0;
    ssl_config->min_tls_version = URPC_TLS_VERSION_1_2;
    ssl_config->max_tls_version = URPC_TLS_VERSION_1_3;
    ssl_config->psk.cipher_list = g_tcp_psk_cipher_list;
    ssl_config->psk.cipher_suites = g_tcp_psk_cipher_suites;
    if (is_server) {
        ssl_config->psk.server_cb_func = server_psk_cb_func;
    } else {
        ssl_config->psk.client_cb_func = client_psk_cb_func;
    }
}

static int set_ssl_config(urpc_lib_example_config_t *cfg, bool is_server)
{
    if (!cfg->use_ssl) {
        return URPC_SUCCESS;
    }
    if (g_cfg.psk_id == NULL || g_cfg.psk_key == NULL) {
        LOG_PRINT("invalid parameters. g_cfg.psk_id == null or g_cfg.psk_key == null\n");
        return URPC_FAIL;
    }
    urpc_ssl_config_t ssl_config = {0};
    fill_ssl_config(cfg, &ssl_config, is_server);
    if (urpc_ssl_config_set(&ssl_config) != 0) {
        LOG_PRINT("urpc_ssl_config_set() failed\n");
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static int async_task_init(void)
{
    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd == -1) {
        LOG_PRINT("urpc_channel_server_attach epoll_create1 failed\n");
        return URPC_FAIL;
    }
    struct epoll_event event = {0};
    event.data.fd = urpc_async_event_fd_get();
    event.events = EPOLLIN;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, event.data.fd, &event) == -1) {
        LOG_PRINT("epoll_ctl add failed\n");
        close(g_epoll_fd);
        g_epoll_fd = -1;
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static void async_task_uninit(void)
{
    int eventfd = urpc_async_event_fd_get();
    (void)epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, eventfd, NULL);
    close(g_epoll_fd);
    g_epoll_fd = -1;
    return;
}

static int attach_server_v2(urpc_host_info_t *server_host, urpc_host_info_t *local, bool is_non_block, uint32_t chid)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT | URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
    option.timeout = -1;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    if (local != NULL) {
        option.flag |= URPC_CHANNEL_CONN_FLAG_BIND_LOCAL;
        option.local = *local;
    }
    urpc_ctrl_msg_t ctl_msg = {0};
    remote_qid_t queue_info = {
        .num = 0,
    };
    ctl_msg.msg = (char *)(uintptr_t)&queue_info;
    ctl_msg.msg_size = (uint32_t)sizeof(remote_qid_t);
    ctl_msg.msg_max_size = CTRL_MSG_MAX_SIZE;
    option.ctrl_msg = &ctl_msg;
    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_ATTACH] = 1;
    int task = urpc_channel_server_attach(chid, server_host, &option);
    if (is_non_block) {
        if (task < 0 || wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    return task;
}

static inline int sum_event_num(uint16_t *event_list, uint32_t event_num)
{
    uint16_t result = 0;
    for (uint32_t i = 0; i < event_num; ++i) {
        result += event_list[i];
    }
    return result;
}

static int wait_result(uint16_t *event_list, uint32_t event_num)
{
    // get eventfd
    int eventfd = urpc_async_event_fd_get();
    urpc_async_event_t urpc_event[1];
    struct epoll_event events[1];
    int expect_event_num = sum_event_num(event_list, event_num);
    LOG_PRINT("start waiting total %d event\n", expect_event_num);
    for (int i = 0; i < expect_event_num; ++i) {
        int nfds = epoll_wait(g_epoll_fd, events, 1, -1);
        if (nfds == -1) {
            LOG_PRINT("epoll_wait error\n");
            return URPC_FAIL;
        }

        if (events[0].data.fd == eventfd) {
            int num = urpc_async_event_get(urpc_event, 1);
            LOG_PRINT("get complete event num:%d\n", num);
        }

        if (event_list[urpc_event[0].event_type] <= 0) {
            LOG_PRINT("get an unexpected event type: %d\n", urpc_event[0].event_type);
            continue;
        }

        if (urpc_event[0].err_code != URPC_SUCCESS) {
            LOG_PRINT("complete failed\n");
            return URPC_FAIL;
        }
        if (urpc_event[0].err_code == URPC_SUCCESS) {
            --event_list[urpc_event[0].event_type];
            LOG_PRINT("expect event %d complete success\n", urpc_event[0].event_type);
        }
    }

    if (sum_event_num(event_list, event_num) == 0) {
        LOG_PRINT("total %d expect event complete success\n", expect_event_num);
        return URPC_SUCCESS;
    }

    return URPC_FAIL;
}

void parse_server_to_host(urpc_server_info_t *server, urpc_host_info_t *server_host, urpc_host_info_t *local_host)
{
    if (server->server_type == SERVER_TYPE_IPV4) {
        server_host->host_type = HOST_TYPE_IPV4;
        memcpy(server_host->ipv4.ip_addr, server->ipv4.ip_addr, URPC_IPV4_SIZE);
        server_host->ipv4.port = server->ipv4.port;
        if (server->assigned_addr.bind_local_addr_enabled && local_host != NULL) {
            local_host->host_type = HOST_TYPE_IPV4;
            memcpy(local_host->ipv4.ip_addr, server->assigned_addr.ipv4_addr, URPC_IPV4_SIZE);
            local_host->ipv4.port = server->assigned_addr.port;
        }
    } else {
        server_host->host_type = HOST_TYPE_IPV6;
        memcpy(server_host->ipv6.ip_addr, server->ipv6.ip_addr, URPC_IPV6_SIZE);
        server_host->ipv6.port = server->ipv6.port;
        if (server->assigned_addr.bind_local_addr_enabled && local_host != NULL) {
            local_host->host_type = HOST_TYPE_IPV6;
            memcpy(local_host->ipv6.ip_addr, server->assigned_addr.ipv6_addr, URPC_IPV6_SIZE);
            local_host->ipv6.port = server->assigned_addr.port;
        }
    }
}

static int detach_server(urpc_host_info_t *server_host, urpc_host_info_t *local, bool is_non_block, uint32_t chid)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT | URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
    option.timeout = -1;

    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    if (local != NULL) {
        option.flag |= URPC_CHANNEL_CONN_FLAG_BIND_LOCAL;
        option.local = *local;
    }
    urpc_ctrl_msg_t ctl_msg = {0};
    remote_qid_t queue_info = {
        .num = 0,
    };
    ctl_msg.msg = (char *)(uintptr_t)&queue_info;
    ctl_msg.msg_size = (uint32_t)sizeof(remote_qid_t);
    ctl_msg.msg_max_size = CTRL_MSG_MAX_SIZE;
    option.ctrl_msg = &ctl_msg;

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_DETACH] = 1;

    int task = urpc_channel_server_detach(chid, server_host, &option);
    if (is_non_block) {
        if (task < 0 || wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    return task;
}

static int refresh_server(bool is_non_block, uint32_t chid)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT | URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
    option.timeout = -1;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    urpc_ctrl_msg_t ctl_msg = {0};
    remote_qid_t queue_info = {
        .num = 0,
    };
    ctl_msg.msg = (char *)(uintptr_t)&queue_info;
    ctl_msg.msg_size = (uint32_t)sizeof(remote_qid_t);
    ctl_msg.msg_max_size = CTRL_MSG_MAX_SIZE;
    option.ctrl_msg = &ctl_msg;

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_REFRESH] = 1;

    int task = urpc_channel_server_refresh(chid, &option);
    if (is_non_block) {
        if (task < 0 || wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    return task;
}

static int channel_queue_add(bool is_non_block, uint32_t chid, uint64_t urpc_qh, bool is_local_queue)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = CONNECT_TIMEOUT_MS;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    if (!is_local_queue) {
        attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    }

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_ADD] = 1;

    int task = urpc_channel_queue_add(chid, urpc_qh, attr, &option);
    if (is_non_block) {
        if (task < 0 || wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    return task;
}


static int channel_queue_rm(bool is_non_block, uint32_t chid, uint64_t urpc_qh, bool is_local_queue)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = CONNECT_TIMEOUT_MS;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    if (!is_local_queue) {
        attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    }

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_RM] = 1;

    int task = urpc_channel_queue_rm(chid, urpc_qh, attr, &option);
    if (is_non_block) {
        if (task < 0 || wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
        return URPC_SUCCESS;
    }
    return task;
}

static void urpc_example_flush_callback(uint64_t urpc_qh, urpc_poll_msg_t *poll_msg)
{
    switch (poll_msg->event) {
        case POLL_EVENT_REQ_RSPED: { // early rsp mode released client tx here
            g_used_allocator->put(poll_msg->req_rsped.args, poll_msg->req_rsped.args_sge_num, NULL);
            break;
        }
        case POLL_EVENT_RSP_SENDED: { // release server tx buffer
            g_used_allocator->put(poll_msg->rsp_sended.rsps, poll_msg->rsp_sended.rsps_sge_num, NULL);
            break;
        }
        case POLL_EVENT_RSP_ERR: { // release server error rsp buffer
            g_used_allocator->put(poll_msg->rsp_err.rsps, poll_msg->rsp_err.rsps_sge_num, NULL);
            break;
        }
        case POLL_EVENT_REQ_ERR: { // release client error req buffer
            g_used_allocator->put(poll_msg->req_err.args, poll_msg->req_err.args_sge_num, NULL);
            break;
        }
        case POLL_EVENT_ERR: { // release client error req buffer
            g_used_allocator->put(poll_msg->event_err.args, poll_msg->event_err.args_sge_num, NULL);
            break;
        }
        default:
            break;
    }
}

static int urpc_example_flush_queue(uint64_t qh)
{
    int ret = urpc_queue_modify(qh, QUEUE_STATUS_ERR);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("modify queue fail ret %d\n", ret);
        return ret;
    }

    urpc_poll_msg_t msg = {0};
    urpc_poll_option_t option = {
        .urpc_qh = qh,
    };

    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    uint64_t start_timestamp_s = (uint64_t)tc.tv_sec;
    uint64_t end_timestamp_s = 0;
    while (end_timestamp_s < start_timestamp_s + 1) {
        ret = urpc_func_poll(URPC_U32_FAIL, &option, &msg, 1);
        if (ret < 0) {
            break;
        } else if (ret == 1 && msg.event == POLL_EVENT_REQ_ERR &&
            (msg.req_err.err_code == URPC_ERR_CR_WR_FLUSH_ERR_DONE)) {
            LOG_PRINT("urma poll jfc status code is flush err done\n");
            break;
        }

        if (ret == 1) {
            urpc_example_flush_callback(qh, &msg);
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &tc);
        end_timestamp_s = (uint64_t)tc.tv_sec;
    }

    if (msg.req_err.err_code != URPC_ERR_CR_WR_FLUSH_ERR_DONE) {
        LOG_PRINT("urma poll jfc ret %d, err_code %u, but not finish\n", ret, msg.req_err.err_code);
    }

    return URPC_SUCCESS;
}

static int chanel_queue_pair(bool is_non_block, uint32_t chid, urpc_channel_qinfos_t *qinfo)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = -1;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR] = 1;
    int task;
    for (uint32_t i = 0; i < qinfo->l_qnum && i < qinfo->r_qnum; i++) {
        task = urpc_channel_queue_pair(chid, qinfo->l_qinfo[i].urpc_qh, qinfo->r_qinfo[i].urpc_qh, &option);
        LOG_PRINT("pair queue task: %d\n", task);
        expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR] = 1;
        if (is_non_block && wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) == URPC_FAIL) {
            expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR] = 1;
            task = urpc_channel_queue_unpair(chid, qinfo->l_qinfo[i].urpc_qh, qinfo->r_qinfo[i].urpc_qh, &option);
            LOG_PRINT("unpair queue task: %d\n", task);
            if (is_non_block && task > 0 &&
                wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) == URPC_FAIL) {
                LOG_PRINT("unpair queue task: %d\n", task);
            }
            return URPC_FAIL;
        }
        if (!is_non_block) {
            urpc_channel_task_cancel(chid, task);
        }
    }

    return URPC_SUCCESS;
}

static void chanel_queue_unpair(bool is_non_block, uint32_t chid, urpc_channel_qinfos_t *qinfo)
{
    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = -1;
    if (is_non_block) {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }

    uint16_t expect_event_list[URPC_ASYNC_EVENT_TYPE_MAX] = {0};
    expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR] = 1;

    for (uint32_t i = 0; i < qinfo->l_qnum && i < qinfo->r_qnum; i++) {
        expect_event_list[URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR] = 1;
        int task = urpc_channel_queue_unpair(chid, qinfo->l_qinfo[i].urpc_qh, qinfo->r_qinfo[i].urpc_qh, &option);
        LOG_PRINT("unpair queue 1 task: %d\n", task);
        if (is_non_block && task > 0 &&
            wait_result(expect_event_list, URPC_ASYNC_EVENT_TYPE_MAX) == URPC_FAIL) {
            LOG_PRINT("unpair queue1 failed, task: %d\n", task);
        }

        if (!is_non_block) {
            urpc_channel_task_cancel(chid, task);
        }
    }
}

static int post_queue_rx(uint64_t qh, uint32_t num, bool wait_bind)
{
    uint32_t post_num = 0;
    int ret = URPC_SUCCESS;
    while (post_num < num) {
        urpc_sge_t *sges;
        uint32_t sge_num = 0;
        if ((g_used_allocator->get(&sges, &sge_num, DEFAULT_MSG_SIZE, NULL) != 0)) {
            LOG_PRINT("get sges failed\n");
            return URPC_FAIL;
        }

        ret = urpc_queue_rx_post(qh, sges, sge_num);
        if (ret != URPC_SUCCESS) {
            g_used_allocator->put(sges, sge_num, NULL);
            if (wait_bind) {
                sleep(1);
                continue;
            }
            return ret;
        }
        post_num++;
    }
    return ret;
}

int run_client(urpc_lib_example_config_t *cfg)
{
    urpc_log_config_t log_cfg = {
        .log_flag = URPC_LOG_FLAG_FUNC | URPC_LOG_FLAG_LEVEL,
        .func = default_output,
        .level = URPC_LOG_LEVEL_DEBUG
    };
    if (urpc_log_config_set(&log_cfg) != URPC_SUCCESS) {
        LOG_PRINT("urpc_log_config_set failed\n");
        return URPC_FAIL;
    }

    if (urpc_log_config_get(&log_cfg) != URPC_SUCCESS) {
        LOG_PRINT("urpc_log_config_get failed\n");
        return URPC_FAIL;
    }

    LOG_PRINT("log level is %s\n", g_log_level_to_str[log_cfg.level]);
    int ret = URPC_FAIL;

    urpc_config_t urpc_config = {0};
    if (check_and_fill_cfg(cfg, &urpc_config) != URPC_SUCCESS) {
        LOG_PRINT("check_and_fill_cfg failed\n");
        return URPC_FAIL;
    }

    if (urpc_init(&urpc_config) != URPC_SUCCESS) {
        LOG_PRINT("urpc_init failed\n");
        return URPC_FAIL;
    }

    if (urpc_allocator_init_default() != URPC_SUCCESS) {
        LOG_PRINT("urpc_allocator_set failed\n");
        goto UNINIT_URPC;
    }

    uint32_t chid = urpc_channel_create();
    if (chid == URPC_U32_FAIL) {
        LOG_PRINT("urpc_channel_create failed\n");
        goto UNINIT_ALLOCATOR;
    }

    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    queue_cfg.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY;
    if (cfg->enable_shared_jfs_jfc) {
        queue_cfg.create_flag |= QCREATE_FLAG_TX_CQ_DEPTH;
        queue_cfg.tx_cq_depth = 2 * (DEFAULT_TX_DEPTH + 1); // use enough tx_cq_depth when 2 qhs shared_tx_cq
    }
    uint64_t qh = urpc_queue_create(trans_mode, &queue_cfg);
    if (qh == 0) {
        LOG_PRINT("urpc_queue_create failed\n");
        goto DESTROY_CHANNEL;
    }

    g_used_allocator = &g_allocator;
    uint64_t qh1 = URPC_INVALID_HANDLE;
    urpc_qcfg_create_t queue_cfg1 = {0};
    queue_cfg1.create_flag = QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    queue_cfg1.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg1.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg1.tx_depth = DEFAULT_TX_DEPTH;
    if (cfg->enable_shared_jfr) {
        queue_cfg1.create_flag |= QCREATE_FLAG_QH_SHARE_RQ;
        queue_cfg1.urpc_qh_share_rq = qh;
    }
    if (cfg->enable_shared_jfs_jfc) {
        queue_cfg1.create_flag |= QCREATE_FLAG_QH_SHARE_TX_CQ;
        queue_cfg1.urpc_qh_share_tx_cq = qh;
    }
    qh1 = urpc_queue_create(trans_mode, &queue_cfg1);
    if (qh1 == URPC_INVALID_HANDLE) {
        LOG_PRINT("urpc_queue_create failed\n");
        goto DESTROY_QUEUE;
    }

    if (g_allocator_ctx != NULL) {
        struct allocator_buf *ptr = g_allocator_ctx->abuf;
        while (ptr != NULL) {
            if (urpc_mem_seg_remote_access_enable(chid, ptr->tsge) != URPC_SUCCESS) {
                LOG_PRINT("urpc_mem_seg_remote_access_enable failed\n");
                goto MEM_SEG_DISABLE;
            }
            ptr = ptr->next;
        }
    }

    urpc_server_info_t server_info = {0};
    if (fill_client_attach_info(cfg, &server_info) != 0) {
        LOG_PRINT("memory copy ip address failed\n");
        goto DESTROY_QUEUE1;
    }
    urpc_host_info_t server_host;
    urpc_host_info_t local_host;
    parse_server_to_host(&server_info, &server_host, &local_host);
    urpc_host_info_t *local = server_info.assigned_addr.bind_local_addr_enabled ? &local_host : NULL;
    if (set_ssl_config(cfg, false) != URPC_SUCCESS) {
        goto DESTROY_QUEUE1;
    }
    if (async_task_init() != URPC_SUCCESS) {
        goto DESTROY_QUEUE1;
    }

    ret = attach_server_v2(&server_host, local, cfg->nonblock_enabled, chid);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("attach server failed\n");
        goto CLOSE_FD;
    }

    if (cfg->is_cancel && cfg->nonblock_enabled) {
        usleep(CANCEL_DELAY_SLEEP_TIME);
        if (urpc_channel_task_cancel(chid, ret) == URPC_SUCCESS) {
            LOG_PRINT("cancel attach server success\n");
            goto CLOSE_FD;
        }
        LOG_PRINT("cancel attach server failed\n");
    }
    LOG_PRINT("attach server success\n");

    ret =  channel_queue_add(cfg->nonblock_enabled, chid, qh, true);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("add local queue 0 failed\n");
        goto DETACH_SERVER;
    }
    LOG_PRINT("add local queue 0 success\n");

    if (cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) {
        ret = channel_queue_add(cfg->nonblock_enabled, chid, qh1, true);
        if (ret != URPC_SUCCESS) {
            LOG_PRINT("add local queue 1 failed\n");
            goto ASYNC_REMOVE_LOCAL_QUEUE0;
        }
    }

    LOG_PRINT("add local queue 1 success\n");

    ret = channel_queue_add(cfg->nonblock_enabled, chid, (uint64_t)g_client_recv_rqid.rqid[0], false);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("add remote queue failed\n");
        goto ASYNC_REMOVE_LOCAL_QUEUE1;
    }
    LOG_PRINT("add remote queue success, rqid: %u\n", g_client_recv_rqid.rqid[0]);

    if (cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) {
        ret = channel_queue_add(cfg->nonblock_enabled, chid, (uint64_t)g_client_recv_rqid.rqid[1], false);
        if (ret != URPC_SUCCESS) {
            LOG_PRINT("add remote queue failed\n");
            goto ASYNC_REMOVE_REMOTE_QUEUE;
        }
        LOG_PRINT("add remote queue success, rqid: %u\n", g_client_recv_rqid.rqid[1]);
    }

    urpc_channel_qinfos_t *qinfos = calloc(1, sizeof(urpc_channel_qinfos_t));
    if (qinfos == NULL) {
        LOG_PRINT("qinfos calloc failed\n");
        goto ASYNC_REMOVE_REMOTE_QUEUE1;
    }

    if (urpc_channel_queue_query(chid, qinfos) != 0) {
        LOG_PRINT("urpc_channel_queue_query failed\n");
        goto FREE_QINFOS;
    };

    ret = refresh_server(cfg->nonblock_enabled, chid);
    if (ret != 0) {
        goto FREE_QINFOS;
    }
    LOG_PRINT("refresh server success\n");

    if (chanel_queue_pair(cfg->nonblock_enabled, chid, qinfos) != URPC_SUCCESS) {
        LOG_PRINT("chanel_queue_pair failed\n");
        goto FREE_QINFOS;
    }

    uint32_t num = queue_cfg.rx_depth;
    if (num <= 0) {
        goto UNPAIR_QUEUE;
    }

    if (post_queue_rx(qh, num, true) != URPC_SUCCESS) {
        LOG_PRINT("post qh rx failed\n");
        goto UNPAIR_QUEUE;
    }

    num = queue_cfg1.rx_depth;
    if (num <= 0) {
        goto UNPAIR_QUEUE;
    }

    // when shared jfs_jfc, rx is posted in urpc_qh_share_tx_cq
    if ((cfg->enable_shared_jfs_jfc) && post_queue_rx(qh1, num, true) != URPC_SUCCESS) {
        LOG_PRINT("post qh1 rx failed\n");
        goto UNPAIR_QUEUE;
    }

    sleep(1); // wait server post rx
    ret = client_run_test(chid, qh, qh1, qinfos, cfg);

    show_queue_stats(qh);

UNPAIR_QUEUE:
    chanel_queue_unpair(cfg->nonblock_enabled, chid, qinfos);

FREE_QINFOS:
    free(qinfos);

ASYNC_REMOVE_REMOTE_QUEUE1:
    ret = channel_queue_rm(cfg->nonblock_enabled, chid, g_client_recv_rqid.rqid[1], false);
    if (ret != 0) {
        LOG_PRINT("rm remote queue failed\n");
    }

ASYNC_REMOVE_REMOTE_QUEUE:
    ret = channel_queue_rm(cfg->nonblock_enabled, chid, g_client_recv_rqid.rqid[0], false);
    if (ret != 0) {
        LOG_PRINT("rm remote queue failed\n");
    }

ASYNC_REMOVE_LOCAL_QUEUE1:
    if (cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) {
        ret = channel_queue_rm(cfg->nonblock_enabled, chid, qh1, true);
        if (ret != 0) {
            LOG_PRINT("rm local queue 1 failed\n");
        }
    }

ASYNC_REMOVE_LOCAL_QUEUE0:
    ret = channel_queue_rm(cfg->nonblock_enabled, chid, qh, true);
    if (ret != 0) {
        LOG_PRINT("rm local queue 0 failed\n");
    }

DETACH_SERVER:
    ret = detach_server(&server_host, local, cfg->nonblock_enabled, chid);
    if (ret == URPC_FAIL) {
        LOG_PRINT("urpc_channel_server_detach failed\n");
    }

MEM_SEG_DISABLE:
    if (g_allocator_ctx != NULL) {
        struct allocator_buf *ptr = g_allocator_ctx->abuf;
        while (ptr != NULL) {
            if (urpc_mem_seg_remote_access_disable(chid, ptr->tsge) != URPC_SUCCESS) {
                LOG_PRINT("urpc_mem_seg_remote_access_enable failed\n");
                goto CLOSE_FD;
            }
            ptr = ptr->next;
        }
    }

CLOSE_FD:
    async_task_uninit();

DESTROY_QUEUE1:
    if (cfg->enable_shared_jfr) {
        urpc_example_flush_queue(qh1);
        (void)urpc_queue_destroy(qh1);
    }

DESTROY_QUEUE:
    urpc_example_flush_queue(qh);
    (void)urpc_queue_destroy(qh);

DESTROY_CHANNEL:
    (void)urpc_channel_destroy(chid);

UNINIT_ALLOCATOR:
    (void)urpc_allocator_uninit_default();

UNINIT_URPC:
    urpc_uninit();

    return ret;
}

// server print request and set response
static inline void urpc_lib_example_exec_handler(
    struct urpc_sge *args, uint32_t args_sge_num, void *ctx, struct urpc_sge **rsps, uint32_t *rsps_sge_num)
{
    char *client_msg =
        (char *)(uintptr_t)args[0].addr + urpc_hdr_size_get(URPC_REQ, 0) + sizeof(custom_head_t);
    LOG_PRINT("(req msg) %s\n", client_msg);

    int ret = g_allocator.get(rsps, rsps_sge_num, DEFAULT_MSG_SIZE, NULL);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT_ERR("g_allocator get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        return;
    }

    uint32_t hdr_size = urpc_hdr_size_get(URPC_RSP, 0);
    (void)snprintf((char *)(uintptr_t)rsps[0]->addr + hdr_size, DEFAULT_MSG_SIZE - hdr_size, "hello client!");
}

static int urpc_lib_example_func_register(urpc_lib_example_config_t *cfg)
{
    urpc_handler_info_t f_info = {URPC_HANDLER_SYNC, {urpc_lib_example_exec_handler}, NULL, "urpc_lib_example"};

    int ret = urpc_func_register(&f_info, &cfg->func_id);
    if (ret != 0) {
        LOG_PRINT("urpc_func_register return error %d\n", ret);
        return -1;
    }

    LOG_PRINT("server register func_id %lu\n", cfg->func_id);

    return 0;
}

static void urpc_lib_example_func_unregister(urpc_lib_example_config_t *cfg)
{
    (void)urpc_func_unregister(cfg->func_id);
}

static int fill_server_urpc_config(urpc_lib_example_config_t *cfg, urpc_config_t *urpc_config)
{
    urpc_config->role = URPC_ROLE_SERVER;
    urpc_config->feature = URPC_FEATURE_DISABLE_TOKEN_POLICY;
    if (cfg->multiplex_enabled) {
        urpc_config->feature |= URPC_FEATURE_MULTIPLEX;
    }
    urpc_config->keepalive_cfg.keepalive_cycle_time = KEEPALIVE_CYCLE_TIME;
    urpc_config->keepalive_cfg.keepalive_check_time = KEEPALIVE_CHECK_TIME;
    urpc_config->keepalive_cfg.delay_release_time = KEEPALIVE_RELEASE_TIME;
    urpc_config->keepalive_cfg.user_ctx = KEEPALIVE_USER_CTX;
    urpc_config->keepalive_cfg.keepalive_callback = keepalive_callback;
    urpc_config->trans_info_num = 1;
    urpc_config->trans_info[0].trans_mode = (urpc_trans_mode_t)cfg->trans_mode;
    urpc_config->trans_info[0].assign_mode = (urpc_dev_assign_mode_t)cfg->dev_assign_mode;

    if (cfg->dev_assign_mode == DEV_ASSIGN_MODE_EID) {
        (void)urma_str_to_eid(cfg->eid, (urma_eid_t *)(uintptr_t)&urpc_config->trans_info[0].ub.eid);
    } else {
        if (snprintf(urpc_config->trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", cfg->dev_name) < 0) {
            LOG_PRINT("snprintf dev_name failed\n");
            return URPC_FAIL;
        }
        urpc_config->trans_info[0].dev.is_ipv6 = cfg->ipv6 ? 1 : 0;
    }
    urpc_config->unix_domain_file_path = cfg->path;

    return URPC_SUCCESS;
}

static int fill_server_cp_config(urpc_lib_example_config_t *cfg, urpc_control_plane_config_t *cp_cfg)
{
    if (cfg->attach_ipv6) {
        cp_cfg->server.server_type = SERVER_TYPE_IPV6;
        cp_cfg->server.ipv6.port = cfg->port;
        memcpy(cp_cfg->server.ipv6.ip_addr, cfg->ip_addr, strlen(cfg->ip_addr));
        return 0;
    }

    cp_cfg->server.server_type = SERVER_TYPE_IPV4;
    cp_cfg->server.ipv4.port = cfg->port;
    memcpy(cp_cfg->server.ipv4.ip_addr, cfg->ip_addr, strlen(cfg->ip_addr));

    return 0;
}

int run_server(urpc_lib_example_config_t *cfg)
{
    int ret = URPC_FAIL;
    urpc_log_config_t log_cfg = {
        .log_flag = URPC_LOG_FLAG_FUNC | URPC_LOG_FLAG_LEVEL,
        .func = default_output,
        .level = URPC_LOG_LEVEL_DEBUG
    };
    if (urpc_log_config_set(&log_cfg) != URPC_SUCCESS) {
        LOG_PRINT("urpc_log_config_set failed\n");
        return URPC_FAIL;
    }

    if (urpc_log_config_get(&log_cfg) != URPC_SUCCESS) {
        LOG_PRINT("urpc_log_config_get failed\n");
        return URPC_FAIL;
    }

    if (cfg->dev_name == NULL || cfg->ip_addr == NULL) {
        LOG_PRINT("invalid arguments\n");
        return URPC_FAIL;
    }

    urpc_config_t urpc_config = {0};
    if (fill_server_urpc_config(cfg, &urpc_config) != URPC_SUCCESS) {
        LOG_PRINT("fill_server_urpc_config failed\n");
        return URPC_FAIL;
    }

    if (urpc_init(&urpc_config) != URPC_SUCCESS) {
        LOG_PRINT("urpc_init failed\n");
        return URPC_FAIL;
    }

    if (urpc_allocator_init_default() != URPC_SUCCESS) {
        LOG_PRINT("urpc_allocator_set failed\n");
        goto UNINIT_URPC;
    }

    g_used_allocator = &g_allocator;
    urpc_qcfg_create_t queue_cfg = {0};
    queue_cfg.create_flag |= QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH;
    queue_cfg.rx_buf_size = DEFAULT_MSG_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    urpc_queue_trans_mode_t trans_mode = QUEUE_TRANS_MODE_JETTY;
    cfg->qh = urpc_queue_create(trans_mode, &queue_cfg);
    if (cfg->qh == 0) {
        LOG_PRINT("urpc_queue_create failed\n");
        goto UNINIT_ALLOCATOR;
    }

    urpc_qcfg_get_t cfg_get = {0};
    if (urpc_queue_cfg_get(cfg->qh, &cfg_get) != URPC_SUCCESS) {
        LOG_PRINT("query local qh cfg failed\n");
        goto DESTROY_QUEUE;
    } else {
        LOG_PRINT("query local qh qid: %u\n", cfg_get.qid);
    }

    g_server_rqid_array.rqid[0] = cfg_get.qid;
    g_server_rqid_array.num = 1;

    uint64_t qh1 = URPC_INVALID_HANDLE;
    if (cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) {
        qh1 = urpc_queue_create(trans_mode, &queue_cfg);
        if (qh1 == URPC_INVALID_HANDLE) {
            LOG_PRINT("urpc_queue_create failed\n");
            goto DESTROY_QUEUE;
        }

        if (urpc_queue_cfg_get(qh1, &cfg_get) != URPC_SUCCESS) {
            LOG_PRINT("query local qh cfg failed\n");
            goto DESTROY_QUEUE1;
        } else {
            LOG_PRINT("query local qh qid: %u\n", cfg_get.qid);
        }
        g_server_rqid_array.rqid[1] = cfg_get.qid;
        g_server_rqid_array.num++;
    }

    if (urpc_lib_example_func_register(cfg) != 0) {
        goto DESTROY_QUEUE1;
    }

    urpc_control_plane_config_t cp_cfg = {0};
    cp_cfg.user_ctx = &cp_cfg;
    if (fill_server_cp_config(cfg, &cp_cfg) != 0) {
        goto UNREGISTER_FUNC;
    }

    if (set_ssl_config(cfg, true) != URPC_SUCCESS) {
        goto UNREGISTER_FUNC;
    }

    if (urpc_server_start(&cp_cfg) != URPC_SUCCESS) {
        LOG_PRINT("urpc_server_start failed\n");
        goto UNREGISTER_FUNC;
    }

    uint32_t num = queue_cfg.rx_depth;
    if (num <= 0) {
        goto UNREGISTER_FUNC;
    }

    if (post_queue_rx(cfg->qh, num, true) != URPC_SUCCESS) {
        goto UNREGISTER_FUNC;
    }

    if ((cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) &&
        post_queue_rx(qh1, num, true) != URPC_SUCCESS) {
        goto UNREGISTER_FUNC;
    }

    ret = g_example_case[(int)cfg->example_case].server(cfg->qh, qh1, g_used_allocator);

UNREGISTER_FUNC:
    urpc_lib_example_func_unregister(cfg);

DESTROY_QUEUE1:
    if (cfg->enable_shared_jfr || cfg->enable_shared_jfs_jfc) {
        (void)urpc_example_flush_queue(qh1);
        (void)urpc_queue_destroy(qh1);
    }

DESTROY_QUEUE:
    (void)urpc_example_flush_queue(cfg->qh);
    (void)urpc_queue_destroy(cfg->qh);

UNINIT_ALLOCATOR:
    (void)urpc_allocator_uninit_default();

UNINIT_URPC:
    urpc_uninit();

    return ret;
}

/* Parse the command line parameters for client and server */
int parse_arguments(int argc, char **argv, urpc_lib_example_config_t *cfg)
{
    if (argc == 1) {
        return -1;
    }
    cfg->port = DEFAULT_PORT;
    cfg->example_case = EARLY_RESPONSE;
    cfg->func_id = DEFAULT_FUNC_ID;
    cfg->dev_assign_mode = DEV_ASSIGN_MODE_DEV;
    int c = 0;
    while (c != -1) {
        unsigned long param;
        c = getopt_long(argc, argv, "Bd:F:p:q:i:l:e:CRbT:tSI:K:HPNLm", g_long_options, NULL);
        switch (c) {
            case 'a':
                cfg->dev_assign_mode = strtoul(optarg, NULL, 0);;
                break;
            case 'B':
                cfg->bind_local_addr_enabled = true;
                break;
            case 'd':
                /* need to free when exiting */
                cfg->dev_name = strdup(optarg);
                break;
            case 'F':
                /* need to free when exiting */
                cfg->path = strdup(optarg);
                break;
            case 'p':
                param = strtoul(optarg, NULL, 0);
                if (param > PORT_MAX) {
                    return -1;
                }
                cfg->port = (uint16_t)param;
                break;
            case 'q':
                param = strtoul(optarg, NULL, 0);
                if (param > PORT_MAX) {
                    return -1;
                }
                cfg->loc_port = (uint16_t)param;
                break;
            case 'i':
                /* need to free when exiting */
                cfg->ip_addr = strdup(optarg);
                break;
            case 'I':
                cfg->psk_id = strdup(optarg);
                break;
            case 'K':
                cfg->psk_key = strdup(optarg);
                break;
            case 'l':
                cfg->loc_ip_addr = strdup(optarg);
                break;
            case 'e':
                param = strtoul(optarg, NULL, 0);
                if (param >= EXAMPLE_CASE_MAX) {
                    return -1;
                }
                cfg->example_case = (uint16_t)param;
                break;
            case 'E':
                cfg->eid = strdup(optarg);
                break;
            case 's':
                cfg->instance_mode = cfg->instance_mode == NONE ? SERVER : cfg->instance_mode;
                break;
            case 'S':
                cfg->use_ssl = true;
                break;
            case 'c':
                cfg->instance_mode = cfg->instance_mode == NONE ? CLIENT : cfg->instance_mode;
                break;
            case 'R':
                cfg->enable_shared_jfr = true;
                break;
            case 'b':
                cfg->enable_shared_jfs_jfc = true;
                break;
            case 'f':
                cfg->func_id = strtoul(optarg, NULL, 0);
                break;
            case 'A':
                cfg->ipv6 = true;
                cfg->attach_ipv6 = (uint16_t)strtoul(optarg, NULL, 0) == 0 ? false : true;
                break;
            case 'T':
                cfg->trans_mode = strtoul(optarg, NULL, 0);
                break;
            case 'H':
                cfg->head_encrypt_disabled = true;
                break;
            case 'P':
                cfg->payload_encrypt_disabled = true;
                break;
            case 'N':
                cfg->nonblock_enabled = true;
                break;
            case 'L':
                cfg->is_long_connect = true;
                break;
            case 'm':
                cfg->multiplex_enabled = true;
                break;
            case 'C':
                cfg->is_cancel = true;
                break;
            case -1:
                break;
            default:
                return -1;
        }
    }
    return 0;
}

void print_config(urpc_lib_example_config_t *cfg)
{
    (void)printf(" ------------------------------------------------\n");
    (void)printf(" [%d] %s\n", (int)g_example_case[(int)cfg->example_case].case_idx,
        g_example_case[(int)cfg->example_case].name);
    if (cfg->dev_name) {
        (void)printf(" Device name : \"%s\"\n", cfg->dev_name);
    }
    if (cfg->ip_addr) {
        (void)printf(" IP : %s\n", cfg->ip_addr);
    }
    (void)printf(" port : %hu\n", cfg->port);
    (void)printf(" ------------------------------------------------\n\n");
}

static void usage()
{
    (void)printf("Usage:\n");
    (void)printf("  -d, --dev <dev-name>                device name <dev>\n");
    (void)printf("  -F, --file-path <path>              unix domain socket file path <path>\n");
    (void)printf("  -p, --port <port>                   listen on/connect to server's port <port> (default: 19875)\n");
    (void)printf("  -i, --ip-address <ip-address>       listen on/connect to server's ip (default: 127.0.0.1)\n");
    (void)printf("  -e, --example                       0:normal example\n");
    (void)printf("  -R, --shared-rq                     to enable shared rq\n");
    (void)printf("  -b, --shared-tx-cq                  to enable shared tx cq\n");
    (void)printf("      --server                        to launch server.\n");
    (void)printf("      --client                        to launch client.\n");
    (void)printf("      --ipv6                          use ipv6 control plane and ipv6 data plane.\n");
    (void)printf("      --func-id                       client use this func id to send request to server (default: "
                 "8388612).\n");
    (void)printf("      --trans-mode                    set urpc_trans_mode.\n");
}

static void clear_cfg(void)
{
    free(g_cfg.dev_name);
    g_cfg.dev_name = NULL;
    free(g_cfg.ip_addr);
    g_cfg.ip_addr = NULL;
    free(g_cfg.loc_ip_addr);
    g_cfg.loc_ip_addr = NULL;
    free(g_cfg.path);
    g_cfg.path = NULL;
    free(g_cfg.psk_id);
    g_cfg.psk_id = NULL;
    free(g_cfg.psk_key);
    g_cfg.psk_key = NULL;
}

void handle_signal(int sig)
{
    // server stop poll
    g_poll_exit = 1;
}

int main(int argc, char *argv[])
{
    int ret = parse_arguments(argc, argv, &g_cfg);
    if (ret != URPC_SUCCESS) {
        usage();
        goto EXIT;
    }

    print_config(&g_cfg);
    ret = urpc_ctrl_msg_cb_register(ctrl_msg_callback);
    if (ret != URPC_SUCCESS) {
        return ret;
    }
    if (g_cfg.instance_mode == CLIENT) {
        ret = run_client(&g_cfg);
    } else if (g_cfg.instance_mode == SERVER) {
        signal(SIGTERM, handle_signal);
        signal(SIGINT, handle_signal);
        ret = run_server(&g_cfg);
    } else {
        LOG_PRINT("Not indicate server/client to launch\n");
    }

EXIT:
    clear_cfg();
    return ret;
}