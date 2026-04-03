/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urpclib test_framework
*/

#include "urpc_lib_atom.h"

test_urpc_ctx_t g_test_urpc_ctx;
test_allocator_ctx_t *g_test_allocator_ctx;
pthread_mutex_t g_test_allocator_lock;
char g_test_log_dir[MAX_FILE_NAME_LEN];
log_file_info_t *g_test_log_file = nullptr;
const static char *g_test_log_level_to_str[URPC_LOG_LEVEL_MAX] = {"EMERG", "ALERT", "CRIT", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"};

bool g_test_poll_status = false;
bool g_test_worker_status = false;
bool g_server_exit = false;
bool g_test_all_queue_ready = true;
char g_test_ssl_cipher_list[] = "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384";
char g_test_ssl_cipher_suites[] = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";

int g_server_ret[256] = {0};
int g_qserver_fd = -1;
int g_qserver_epoll_fd = -1;
bool g_qserver_status =false;
pthread_t g_qserver_thread = 0;

static void set_poll_direction_truns(test_func_args_t *func_args, urpc_poll_option_t *option, urpc_poll_direction_t *next_direction, uint64_t queue_handle = 0);

int test_str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = nullptr;

    if (buf == nullptr || *buf == '-') {
        return TEST_FAILED;
    }
    errno = 0;
    ret =strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return TEST_FAILED;
    }
    if (end == nullptr || *end != '\0' || end == buf) {
        return TEST_FAILED;
    }
    if (ret > UINT_MAX) {
        return TEST_FAILED;
    }
    *u32 = (uint32_t)ret;
    return TEST_SUCCESS;
}

void test_urpc_u32_to_eid(uint32_t ipv4, urpc_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(URPC_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int test_urpc_str_to_eid(const char *buf, urpc_eid_t *eid)
{
    int ret;
    uint32_t ipv4;
    TEST_LOG_INFO("urpc_init eid=%s\n", buf);
    if (buf == nullptr || strlen(buf) < URPC_EID_STR_MIN_LEN || eid == nullptr) {
        TEST_LOG_ERROR("Invalid argument.\n");
        return TEST_FAILED;
    }

    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return TEST_SUCCESS;
    }

    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        test_urpc_u32_to_eid(be32toh(ipv4), eid);
        return TEST_SUCCESS;
    }

    ret =test_str_to_u32(buf, &ipv4);
    if (ret == TEST_SUCCESS) {
        test_urpc_u32_to_eid(ipv4, eid);
        return TEST_SUCCESS;
    }

    TEST_LOG_ERROR("format error: %s.\n", buf);
    return TEST_FAILED;
}

int set_urpc_server_info(test_urpc_ctx_t *ctx, urpc_server_info_t *server, char ipv4[IPV6_ADDR_SIZE], char ipv6[IPV6_ADDR_SIZE], uint16_t port)
{
    if (ctx->cp_is_ipv6) {
        server->server_type= SERVER_TYPE_IPV6;
        server->ipv6.port = port;
        (void *)strcpy(server->ipv6.ip_addr, ipv6);
    } else {
        server->server_type= SERVER_TYPE_IPV4;
        server->ipv4.port = port;
        (void *)strcpy(server->ipv4.ip_addr, ipv4);
    }
    TEST_LOG_INFO("server->ipv6.ip_addr=%s, port=%d\n", server->ipv6.ip_addr, server->ipv6.port);
    TEST_LOG_INFO("server->ipv4.ip_addr=%s, port=%d\n", server->ipv4.ip_addr, server->ipv4.port);
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

int set_urpc_host_info(test_urpc_ctx_t *ctx, urpc_host_info_t *host, char ipv4[IPV6_ADDR_SIZE], char ipv6[IPV6_ADDR_SIZE], uint16_t port)
{
    if (ctx->cp_is_ipv6) {
        host->host_type = HOST_TYPE_IPV6;
        host->ipv6.port = port;
        (void *)strcpy(host->ipv6.ip_addr, ipv6);
    } else {
        host->host_type = HOST_TYPE_IPV4;
        host->ipv4.port = port;
        (void *)strcpy(host->ipv4.ip_addr, ipv4);
    }

    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

int get_urpc_host_info(urpc_host_info_t *host_info, uint32_t idx)
{
    for (int i= 0; i < g_test_urpc_ctx.server_num; i++) {
        if (set_urpc_host_info(&g_test_urpc_ctx, &host_info[i], g_test_urpc_ctx.ctx->test_ip[idx], g_test_urpc_ctx.ctx->test_ipv6[idx], g_test_urpc_ctx.ctx->test_port + i) != TEST_SUCCESS) {
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int process_ctrl_msg(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg)
{
    static int cnt = 0;
    if (msg_type == URPC_CTRL_MSG_ATTACH) {
        TEST_LOG_INFO("this is %d  attach msg\n", msg_type);
        g_test_urpc_ctx.attach_cb_count++;
    } else if (msg_type == URPC_CTRL_MSG_REFRESH) {
        TEST_LOG_INFO("this is %d  refresh msg\n", msg_type);
        g_test_urpc_ctx.refresh_cb_count++;
    } else if (msg_type == URPC_CTRL_MSG_DETACH) {
        TEST_LOG_INFO("this is %d  detach msg\n", msg_type);
        g_test_urpc_ctx.detach_cb_count++;
    }

    uint64_t *p_id = (uint64_t *)ctrl_msg->user_ctx;
    TEST_LOG_INFO("user_ctx:%p\n", (void *)ctrl_msg->user_ctx);
    if (ctrl_msg->msg_size > 0) {
        ctrl_msg->msg[ctrl_msg->msg_size - 1] = '\0';
        TEST_LOG_INFO("process input msg[%u bytes]: %s\n", ctrl_msg->msg_size, ctrl_msg->msg);
    }

    for (uint32_t i = 0; i < ctrl_msg->id_num; i++) {
        TEST_LOG_DEBUG("queue id of %u is %u\n", i, ctrl_msg->id[i].id);
    }

    (void)sprintf(ctrl_msg->msg, "this is %d server output msg", cnt++);
    ctrl_msg->msg_size = strlen(ctrl_msg->msg) + 1;
    TEST_LOG_INFO("reply msg[%u bytes]: %s user_ctx=%u is_server=%d\n", ctrl_msg->msg_size, ctrl_msg->msg, *(uint32_t *)ctrl_msg->user_ctx, ctrl_msg->is_server);
    return 0;
}

int get_urpc_control_plane_config(urpc_control_plane_config_t *cfg, uint32_t idx)
{
    if (set_urpc_server_info(&g_test_urpc_ctx, &cfg->server, g_test_urpc_ctx.ctx->test_ip[idx], g_test_urpc_ctx.ctx->test_ipv6[idx], g_test_urpc_ctx.ctx->test_port) != TEST_SUCCESS) {
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int get_urpc_server_info(urpc_server_info_t *server_info, uint32_t idx)
{
    for (int i = 0; i < g_test_urpc_ctx.server_num; i++) {
        if (set_urpc_server_info(&g_test_urpc_ctx, &server_info[i], g_test_urpc_ctx.ctx->test_ip[idx], g_test_urpc_ctx.ctx->test_ipv6[idx], g_test_urpc_ctx.ctx->test_port + i) != TEST_SUCCESS) {
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

test_urpc_ctx_t *test_urpc_ctx_init(int argc, char *argv[], int thread_num)
{
    (void)memset(&g_test_urpc_ctx, 0, sizeof(test_urpc_ctx_t));
    pid_t pid = getpid();
    g_test_urpc_ctx.pid = (uint64_t)pid;

    test_context_t *ctx = create_test_ctx(argc, argv, thread_num);
    if (ctx == nullptr) {
        TEST_LOG_ERROR("create_test_ctx failed\n");
        return nullptr;
    }

    g_test_urpc_ctx.ctx = ctx;
    g_test_urpc_ctx.app_id = ctx->app_id;
    g_test_urpc_ctx.app_num = ctx->app_num;

    g_test_urpc_ctx.trans_mode = static_cast<urpc_trans_mode_t>(ctx->mode);
    if (ctx->mode == 0) {
        TEST_LOG_INFO("test case urpc_trans_mode=%d is IP\n", ctx->mode);
    } else if (ctx->mode == 1) {
        TEST_LOG_INFO("test case urpc_trans_mode=%d is UB\n", ctx->mode);
    } else {
        TEST_LOG_INFO("test case urpc_trans_mode=%d is IB\n", ctx->mode);
    }

    g_test_urpc_ctx.channel_num = DEFAULT_CHANNEL_NUM;
    g_test_urpc_ctx.queue_num = DEFAULT_QUEUE_NUM;
    g_test_urpc_ctx.qgrph_num = 0;
    g_test_urpc_ctx.queue_cfg = (urpc_qcfg_create_t *)calloc(1, sizeof(urpc_qcfg_create_t));
    g_test_urpc_ctx.queue_cfg->create_flag |= QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_PRIORITY;
    g_test_urpc_ctx.queue_cfg->rx_buf_size = DEFAULT_RX_BUF_SIZE;
    g_test_urpc_ctx.queue_cfg->rx_depth = DEFAULT_RX_DEPTH;
    g_test_urpc_ctx.queue_cfg->tx_depth = DEFAULT_TX_DEPTH;
    g_test_urpc_ctx.queue_cfg->priority = CLOUD_STORAGE_PRIORITY;
    g_test_urpc_ctx.server_num = DEFAULT_SERVER_NUM;

    g_test_urpc_ctx.cp_is_ipv6 = 0;
    g_test_urpc_ctx.dp_is_ipv6 = 1;

#ifdef LOCK_FREE
    g_test_urpc_ctx.queue_cfg->create_flag |= QCREATE_FLAG_LOCK_FREE;
    g_test_urpc_ctx.queue_cfg->lock_free = 1;
    TEST_LOG_INFO("FLAG_LOCK_FREE come\n");
#endif

    g_test_urpc_ctx.urpc_cp_config = (urpc_control_plane_config_t *)calloc(1, sizeof(urpc_control_plane_config_t));
    g_test_urpc_ctx.urpc_cp_config->user_ctx = (void *)&g_test_urpc_ctx.pid;
    TEST_LOG_INFO("g_test_urpc_ctx.urpc_cp_config->user_ctx=%u\n", *(uint32_t *)g_test_urpc_ctx.urpc_cp_config->user_ctx);
    (void)get_urpc_control_plane_config(g_test_urpc_ctx.urpc_cp_config);

    g_test_urpc_ctx.allocator_config.total_size = MAX_ALLOC_SIZE;
    g_test_urpc_ctx.allocator_config.allocator_size = ALLOCATOR_SIZE;
    g_test_urpc_ctx.allocator_config.block_size = ALLOCATOR_BLOCK_SIZE;
    g_test_urpc_ctx.allocator_config.allocator_num = uint32_t(g_test_urpc_ctx.allocator_config.total_size / g_test_urpc_ctx.allocator_config.allocator_size);
    g_test_urpc_ctx.allocator_config.block_num = uint32_t(g_test_urpc_ctx.allocator_config.allocator_size / g_test_urpc_ctx.allocator_config.block_size);

    g_test_urpc_ctx.log_cfg.log_flag = URPC_LOG_FLAG_LEVEL;
    g_test_urpc_ctx.log_cfg.level = URPC_LOG_LEVEL_DEBUG;
    urpc_log_config_set(&g_test_urpc_ctx.log_cfg);

    g_test_urpc_ctx.ssl_cfg.ssl_mode = SSL_MODE_PSK;
    g_test_urpc_ctx.ssl_cfg.min_tls_version = URPC_TLS_VERSION_1_2;
    g_test_urpc_ctx.ssl_cfg.max_tls_version = URPC_TLS_VERSION_1_3;
    g_test_urpc_ctx.ssl_cfg.psk.cipher_list = g_test_ssl_cipher_list;
    g_test_urpc_ctx.ssl_cfg.psk.cipher_suites = g_test_ssl_cipher_suites;
    g_test_urpc_ctx.ssl_cfg.psk.server_cb_func = test_server_psk_cb_func;
    g_test_urpc_ctx.ssl_cfg.psk.client_cb_func = test_client_psk_cb_func;

    g_test_urpc_ctx.ssl_cfg.ssl_flag = 0;

    return &g_test_urpc_ctx;
}

urpc_config_t get_init_mode_config(test_urpc_ctx_t *ctx, urpc_config_t urpc_config)
{
    urpc_config.feature |= URPC_FEATURE_DISABLE_TOKEN_POLICY;
    urpc_config.unix_domain_file_path = ctx->unix_domain_file_path;
    urpc_config.trans_info_num = 1;
    urpc_config.trans_info[0].trans_mode = ctx->trans_mode;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_EID;
    urpc_eid_t eid = {0};
    int ret = test_urpc_str_to_eid(ctx->ctx->eid, &eid);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_urpc_str_to_eid failed\n");
        return urpc_config;
    }
    (void)memcpy(&urpc_config.trans_info[0].ub.eid, &eid, sizeof(eid));
    g_test_urpc_ctx.server_info = (urpc_server_info_t *)calloc(g_test_urpc_ctx.server_num, sizeof(urpc_server_info_t));
    g_test_urpc_ctx.host_info = (urpc_host_info_t *)calloc(g_test_urpc_ctx.server_num, sizeof(urpc_host_info_t));

    (void)get_urpc_server_info(g_test_urpc_ctx.server_info);
    (void)get_urpc_host_info(g_test_urpc_ctx.host_info);
    return urpc_config;
    
}

urpc_config_t get_urpc_server_config(test_urpc_ctx_t *ctx)
{
    ctx->instance_role = URPC_ROLE_SERVER;
    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_SERVER;
    urpc_config = get_init_mode_config(ctx, urpc_config);
    return urpc_config;
}

urpc_config_t get_urpc_client_config(test_urpc_ctx_t *ctx)
{
    ctx->instance_role = URPC_ROLE_CLIENT;
    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_CLIENT;
    urpc_config = get_init_mode_config(ctx, urpc_config);
    return urpc_config;
}

urpc_config_t get_urpc_server_client_config(test_urpc_ctx_t *ctx)
{
    ctx->instance_role = URPC_ROLE_SERVER_CLIENT;
    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_SERVER_CLIENT;
    urpc_config = get_init_mode_config(ctx, urpc_config);
    return urpc_config;
}

int test_urpc_ctrl_msg_cb_register(test_urpc_ctx_t *ctx)
{
    int ret = 0;
    if (ctx->ctrl_cb != nullptr) {
        ret = urpc_ctrl_msg_cb_register(ctx->ctrl_cb);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_ctrl_msg_cb_register failed ret=%d\n", ret);
            return -1;
        }
    }
    return ret;
}

void set_ctx_ctrl_msg_param(test_urpc_ctx_t *ctx, char msg[CTRL_MSG_MAX_SIZE])
{
    ctx->ctrl_msg = (urpc_ctrl_msg_t *)calloc(1, sizeof(urpc_ctrl_msg_t));
    ctx->ctrl_msg->msg = msg;
    ctx->ctrl_msg->msg_size = strlen(msg) + 1;
    ctx->ctrl_msg->msg_max_size = CTRL_MSG_MAX_SIZE;
    ctx->ctrl_cb = process_ctrl_msg;
    ctx->ctrl_msg->user_ctx = (void *)&ctx->pid;
    ctx->ctrl_msg->is_server = ctx->instance_role == URPC_ROLE_CLIENT ? false : true;
}

int test_async_event_ctrl_add(test_urpc_ctx_t *ctx)
{
    int ret;
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return TEST_SUCCESS;
    }
    ctx->async_ops.event_fd = urpc_async_event_fd_get();
    CHKERR_JUMP(ctx->async_ops.event_fd <= 0, "urpc_async_event_fd_get fd", EXIT);
    ctx->async_ops.epoll_fd = epoll_create1(0);
    CHKERR_JUMP(ctx->async_ops.epoll_fd < 0, "epoll_create1", EXIT);
    struct epoll_event event;
    event.data.fd = ctx->async_ops.event_fd;
    event.events = EPOLLIN;
    ret = epoll_ctl(ctx->async_ops.epoll_fd, EPOLL_CTL_ADD, ctx->async_ops.event_fd, &event);
    CHKERR_JUMP(ret < 0, "epoll_ctl add urpc async event fd", EXIT);
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

int test_server_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config)
{
    int ret;
    if (urpc_config == nullptr) {
        urpc_config_t urpc_cfg = get_urpc_server_config(ctx);
        ret = urpc_init(&urpc_cfg);
    } else {
        ret = urpc_init(urpc_config);
    }
    TEST_LOG_INFO("urpc server init ret=%d\n", ret);
    if (ret != TEST_SUCCESS) {
        return ret;
    } else {
        ret = test_async_event_ctrl_add(ctx);
        if (ret == TEST_SUCCESS) {
            ctx->ctx_flag |= CTX_FLAG_URPC_INIT;
        } else {
            urpc_uninit();
            return ret;
        }
    }
    return ret;
}

int test_client_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config)
{
    int ret;
    if (urpc_config == nullptr) {
        urpc_config_t urpc_cfg = get_urpc_client_config(ctx);
        ret = urpc_init(&urpc_cfg);
    } else {
        ret = urpc_init(urpc_config);
    }
    TEST_LOG_INFO("urpc client init ret=%d\n", ret);
    if (ret != TEST_SUCCESS) {
        return ret;
    } else {
        ret = test_async_event_ctrl_add(ctx);
        if (ret == TEST_SUCCESS) {
            ctx->ctx_flag |= CTX_FLAG_URPC_INIT;
        } else {
            urpc_uninit();
            return ret;
        }
    }
    return ret;
}

int test_server_client_init(test_urpc_ctx_t *ctx, urpc_config_t *urpc_config)
{
    int ret;
    if (urpc_config == nullptr) {
        urpc_config_t urpc_cfg = get_urpc_server_client_config(ctx);
        ret = urpc_init(&urpc_cfg);
    } else {
        ret = urpc_init(urpc_config);
    }
    TEST_LOG_INFO("urpc server client init ret=%d\n", ret);
    if (ret != TEST_SUCCESS) {
        return ret;
    } else {
        ret = test_async_event_ctrl_add(ctx);
        if (ret == TEST_SUCCESS) {
            ctx->ctx_flag |= CTX_FLAG_URPC_INIT;
        } else {
            urpc_uninit();
            return ret;
        }
    }
    return ret;
}

void test_urpc_uninit(test_urpc_ctx_t *ctx)
{
    if ((ctx->ctx_flag & CTX_FLAG_URPC_INIT) != 0) {
        TEST_LOG_INFO("urpc_uninit\n");
        urpc_uninit();
        ctx->ctx_flag &= ~CTX_FLAG_URPC_INIT;
    }
    if (ctx->async_ops.epoll_fd > 0) {
        epoll_ctl(ctx->async_ops.epoll_fd, EPOLL_CTL_DEL, ctx->async_ops.event_fd, NULL);
    }
}

void test_allocator_buf_init(test_allocator_buf_t *ptr)
{
    uint32_t i;
    for (i = 0; i < ptr->total_count - 1; i++) {
        *(uint32_t *)(ptr->buf + i * g_test_urpc_ctx.allocator_config.block_size) = i + 1;
    }
    *(uint32_t *)(ptr->buf + i * g_test_urpc_ctx.allocator_config.block_size) = UINT32_MAX;
}

char *test_allocator_buf_get_addr(test_allocator_buf_t *ptr, uint32_t num)
{
    return ptr->buf + num * g_test_urpc_ctx.allocator_config.block_size;
}

uint32_t test_allocator_buf_get_num(char *base, char *addr)
{
    return (uint32_t)((addr - base) / g_test_urpc_ctx.allocator_config.block_size);
}

static int get_test_allocator(urpc_sge_t **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    pthread_mutex_lock(&g_test_allocator_lock);
    uint32_t i = 0;
    if (num == nullptr) {
        TEST_LOG_ERROR("num is nullptr\n");
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }
    if (total_size > g_test_urpc_ctx.allocator_config.total_size) {
        TEST_LOG_ERROR("total_size is too large:%lu\n", total_size);
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }
    uint32_t count = total_size % g_test_urpc_ctx.allocator_config.block_size == 0 ? total_size / g_test_urpc_ctx.allocator_config.block_size : total_size / g_test_urpc_ctx.allocator_config.block_size + 1;
    if (g_test_allocator_ctx->free_count < count) {
        TEST_LOG_ERROR("no left room to allocator, left:%u, need:%u\n", g_test_allocator_ctx->free_count, count);
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    uint32_t sge_alloc_count = (option != nullptr && option->qcustom_flag == 0x123) ? count + 1 : count;
    urpc_sge_t *pr = (urpc_sge_t *)malloc(sizeof(urpc_sge_t) * sge_alloc_count);
    if (pr == nullptr) {
        TEST_LOG_ERROR("malloc failed\n");
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }
    for (i = 0; i < count; i++) {
        test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
        while (ptr != nullptr && ptr->free_count <= 1) {
            ptr = ptr->next;
        }
        if (ptr == nullptr) {
            TEST_LOG_ERROR("ptr is nullptr\n");
            CHECK_FREE(pr);
            pthread_mutex_unlock(&g_test_allocator_lock);
            return TEST_FAILED;
        }
        pr[i].length = g_test_urpc_ctx.allocator_config.block_size;
        pr[i].flag = 0;
        pr[i].addr = (uint64_t)(uintptr_t)ptr->block_head;
        pr[i].mem_h = ptr->tsge;
        ptr->block_head = test_allocator_buf_get_addr(ptr, *(uint32_t *)ptr->block_head);
        ptr->free_count -= 1;
        g_test_allocator_ctx->free_count--;
    }
    *num = (int)sge_alloc_count;
    *sge = pr;
    pthread_mutex_unlock(&g_test_allocator_lock);
    return TEST_SUCCESS;
}

static int put_test_allocator(urpc_sge_t *sge, uint32_t num, urpc_allocator_option_t *option)
{
    pthread_mutex_lock(&g_test_allocator_lock);
    uint32_t valid_sge_start = 0;
    if (num <= 0) {
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    for (uint32_t i = 0; i < num; i++) {
        if (sge[i].addr != 0) {
            break;
        }
        valid_sge_start++;
    }

    if (valid_sge_start == num) {
        TEST_LOG_ERROR("no valid sge\n");
        CHECK_FREE(sge);
        (void)pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    for (int i = valid_sge_start; i < num; i++) {
        if (sge[i].addr == 0) {
            TEST_LOG_INFO("sge[i].addr is 0\n");
            continue;
        }
        test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
        while (ptr != nullptr) {
            if (sge[i].addr - (uintptr_t)ptr->buf < g_test_urpc_ctx.allocator_config.allocator_size) {
                break;
            }
            ptr = ptr->next;
        }
        if (ptr == nullptr) {
            TEST_LOG_ERROR("ptr is nullptr\n");
            CHECK_FREE(sge);
            pthread_mutex_unlock(&g_test_allocator_lock);
            return TEST_FAILED;
        }

        *(uint32_t *)(uintptr_t)sge[i].addr = test_allocator_buf_get_num(ptr->buf, ptr->block_head);
        ptr->block_head = (char *)(uintptr_t)sge[i].addr;
        ptr->free_count++;
        g_test_allocator_ctx->free_count++;
    }
    CHECK_FREE(sge);
    pthread_mutex_unlock(&g_test_allocator_lock);
    return TEST_SUCCESS;
}

static int test_urpc_allocator_get(urpc_sge_t **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    int ret = 0;
    ret = get_test_allocator(sge, num, total_size, option);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_urpc_allocator_get failed\n");
        return TEST_FAILED;
    }
    return ret;
}

int test_allocator_uninit(void)
{
    if (g_test_allocator_ctx == nullptr) {
        return TEST_SUCCESS;
    }
    test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
    test_allocator_buf_t *ptr1 = nullptr;
    while (ptr != nullptr)  {
        ptr1 = ptr->next;
        (void)urpc_mem_seg_unregister(ptr->tsge);
        CHECK_FREE(ptr->buf);
        CHECK_FREE(ptr);
        ptr = ptr1;
    }
    CHECK_FREE(g_test_allocator_ctx);
    return TEST_SUCCESS;
}

int test_allocator_dynamic_expansion(test_urpc_ctx_t *ctx)
{
    test_allocator_buf_t *current_last = nullptr;
    uint64_t current_total_size = 0;
    uint32_t current_index = 0;
    uint32_t alloc_num = 0;
    uint32_t index = 0;

    if (g_test_allocator_ctx->allocator_buf == nullptr) {
        g_test_allocator_ctx->allocator_buf = (test_allocator_buf_t *)calloc(1, sizeof(test_allocator_buf_t));
        if (g_test_allocator_ctx->allocator_buf == nullptr) {
            TEST_LOG_ERROR("calloc g_test_allocator_ctx allocator_buf failed\n");
            return TEST_FAILED;
        }
        current_last = g_test_allocator_ctx->allocator_buf;
        alloc_num = ctx->allocator_config.allocator_num;
        current_total_size = 0;
    } else {
        test_allocator_buf_t *current = g_test_allocator_ctx->allocator_buf;
        while (current->next != nullptr) {
            current_index++;
            current = current->next;
        }
        current_last = current;
        alloc_num = ctx->allocator_config.total_size / ctx->allocator_config.allocator_size;
        current_total_size = ctx->allocator_config.total_size;
    }
    TEST_LOG_DEBUG("current_last=%p\n", current_last);
    TEST_LOG_DEBUG("current_last->buf=%p\n", current_last->buf);
    for (int i = 0; i < alloc_num; i++) {
        current_last->buf = (char *)aligned_alloc(4096, sizeof(char) * ctx->allocator_config.allocator_size);
        if (current_last->buf == nullptr) {
            TEST_LOG_ERROR("calloc g_test_allocator_ctx buf failed\n");
            return TEST_FAILED;
        }
        current_last->block_len = ctx->allocator_config.allocator_size;
        current_last->total_count = ctx->allocator_config.block_num;
        current_last->free_count = current_last->total_count;
        current_last->tsge = urpc_mem_seg_register((uint64_t)(uintptr_t)current_last->buf, (uint64_t)current_last->block_len);
        TEST_LOG_DEBUG("current_last->tsge : %llu current_last->buf : %p current_last->block_len : %llu\n", current_last->tsge, current_last->buf, current_last->block_len);
        current_last->block_head = current_last->buf;
        current_last->next = nullptr;
        test_allocator_buf_init(current_last);
        g_test_allocator_ctx->total_count += current_last->total_count;
        g_test_allocator_ctx->free_count += current_last->free_count;
        current_last->next = (test_allocator_buf_t *)calloc(1, sizeof(test_allocator_buf_t));
        if (current_last->next == nullptr) {
            TEST_LOG_ERROR("calloc test_allocator_buf_t failed\n");
            return TEST_FAILED;
        }
        current_last = current_last->next;
    }
    TEST_LOG_DEBUG("current_total_size=%lu\n", current_total_size);
    TEST_LOG_DEBUG("ctx->allocator_config.total_size=%lu\n", ctx->allocator_config.total_size);
    ctx->allocator_config.total_size += current_total_size;
    TEST_LOG_DEBUG("g_test_allocator_ctx->total_count=%lu\n", g_test_allocator_ctx->total_count);
    TEST_LOG_DEBUG("g_test_allocator_ctx->free_count=%lu\n", g_test_allocator_ctx->free_count);
    return TEST_SUCCESS;
}

int test_allocator_init(test_urpc_ctx_t *ctx)
{
    int ret;
    g_test_allocator_ctx = (test_allocator_ctx_t *)calloc(1, sizeof(test_allocator_ctx_t));
    if (g_test_allocator_ctx == nullptr) {
        TEST_LOG_ERROR("calloc g_test_allocator_ctx failed\n");
        return TEST_FAILED;
    }
    ret = test_allocator_dynamic_expansion(ctx);
    if (ret != TEST_SUCCESS) {
        goto FREE_BUF;
    }
    return TEST_SUCCESS;
FREE_BUF:
    (void)test_allocator_uninit();
    return TEST_FAILED;
}

int test_urpc_allocator_get_raw_buf(urpc_sge_t *sge, uint64_t total_size, urpc_allocator_option_t *option)
{
    void *dma = nullptr;
    pthread_mutex_lock(&g_test_allocator_lock);
    bool big_dma = (total_size > g_test_urpc_ctx.allocator_config.block_size) ? true : false;
    if (sge == nullptr) {
        TEST_LOG_ERROR("sge or num is nullptr\n");
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }
    
    if (total_size > g_test_urpc_ctx.allocator_config.total_size) {
        TEST_LOG_ERROR("total_size is too large:%lu\n", total_size);
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
    while (ptr != nullptr && ptr->free_count <= 1) {
        ptr = ptr->next;
    }
    if (ptr == nullptr) {
        TEST_LOG_ERROR("ptr is nullptr\n");
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    if (big_dma) {
        dma =malloc(total_size);
        if (dma == nullptr) {
            pthread_mutex_unlock(&g_test_allocator_lock);
            return TEST_FAILED;
        }
    }

    sge->length = g_test_urpc_ctx.allocator_config.block_size;
    sge->flag = 0;
    sge->addr = big_dma ? (uint64_t)(uintptr_t)dma : (uint64_t)(uintptr_t)ptr->block_head;
    sge->mem_h = big_dma ? urpc_mem_seg_register((uint64_t)(uintptr_t)dma, (uint64_t)total_size) : ptr->tsge;
    ptr->block_head = test_allocator_buf_get_addr(ptr, *(uint32_t *)ptr->block_head);
    ptr->free_count -= 1;

    g_test_allocator_ctx->free_count -= 1;
    pthread_mutex_unlock(&g_test_allocator_lock);
    return TEST_SUCCESS;
}

int test_urpc_allocator_put_raw_buf(urpc_sge_t *sge, urpc_allocator_option_t *option)
{
    pthread_mutex_lock(&g_test_allocator_lock);
    if (sge == nullptr) {
        TEST_LOG_ERROR("sge is nullptr\n");
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }
    bool big_dma = (sge->length > g_test_urpc_ctx.allocator_config.block_size) ? true : false;

    if (big_dma) {
        urpc_mem_seg_unregister(sge->mem_h);
        free((void *)sge->addr);
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_SUCCESS;
    }

    test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
    while (ptr != nullptr) {
        if (sge[0].addr - (uintptr_t)ptr->buf < g_test_urpc_ctx.allocator_config.allocator_size) {
            break;
        }
        ptr = ptr->next;
    }
    
    if (ptr == nullptr) {
        pthread_mutex_unlock(&g_test_allocator_lock);
        return TEST_FAILED;
    }

    *(uint32_t *)(uintptr_t)sge->addr = test_allocator_buf_get_num(ptr->buf, ptr->block_head);
    ptr->block_head = (char *)(uintptr_t)sge->addr;
    ptr->free_count++;
    g_test_allocator_ctx->free_count += (uint32_t)1;
    pthread_mutex_unlock(&g_test_allocator_lock);
    return TEST_SUCCESS;
}

int test_urpc_plog_allocator_get_sges(urpc_sge_t **sge, uint32_t num, urpc_allocator_option_t *option)
{
    if (num == 0) {
        TEST_LOG_ERROR("num is 0\n");
        return TEST_FAILED;
    }

    urpc_sge_t *tmp_sge = (urpc_sge_t *)calloc(num, sizeof(urpc_sge_t));
    if (tmp_sge == nullptr) {
        TEST_LOG_ERROR("calloc sge failed\n");
        return TEST_FAILED;
    }

    for (uint32_t i = 0; i < num; i++) {
        tmp_sge[i].flag = SGE_FLAG_NO_MEM;
    }

    *sge = tmp_sge;
    return TEST_SUCCESS;
}

int test_urpc_plog_allocator_put_sges(urpc_sge_t *sge, urpc_allocator_option_t *option)
{
    if (sge == nullptr) {
        TEST_LOG_ERROR("sge is nullptr\n");
        return TEST_FAILED;
    }

    CHECK_FREE(sge);
    return TEST_SUCCESS;
}

urpc_allocator_t g_test_allocator = {.get = test_urpc_allocator_get, .put = put_test_allocator, .get_raw_buf = test_urpc_allocator_get_raw_buf, 
    .put_raw_buf = test_urpc_allocator_put_raw_buf, .get_sges = test_urpc_plog_allocator_get_sges, .put_sges = test_urpc_plog_allocator_put_sges};

int test_allocator_register(test_urpc_ctx_t *ctx)
{
    int ret = 0;
    ret = test_allocator_init(ctx);
    TEST_LOG_INFO("test_allocator_init ret=%d\n", ret);
    return ret;
}

int test_allocator_unregister(test_urpc_ctx_t *ctx)
{
    int ret = 0;
    ret += test_allocator_uninit();
    TEST_LOG_INFO("test_allocator_uninit ret=%d\n", ret);
    return ret;
}

int set_queue_ops_interrupt(test_urpc_ctx_t *ctx, int *polling_arr, int arr_size)
{
    ctx->queue_ops.is_epoll = true;
    ctx->queue_cfg->create_flag |= QCREATE_FLAG_MODE;
    ctx->queue_cfg->mode = QUEUE_MODE_INTERRUPT;
    ctx->queue_ops.epoll_fd = epoll_create(1024);
    TEST_LOG_INFO("ctx->queue_ops.epoll_fd=%d\n", ctx->queue_ops.epoll_fd);
    if (ctx->queue_ops.epoll_fd < 0) {
        TEST_LOG_ERROR("epoll_fd create failed, epoll_fd=%d\n", ctx->queue_ops.epoll_fd);
        return TEST_FAILED;
    }
    ctx->queue_ops.queue_fd = (int *)calloc(ctx->queue_num, sizeof(int));
    if (ctx->queue_ops.queue_fd == nullptr) {
        TEST_LOG_ERROR("queue_fd calloc failed\n");
        return TEST_FAILED;
    }
    ctx->queue_ops.epoll_timeout = MILLISECOND_PER_SECOND;
    ctx->queue_ops.is_polling = (bool *)calloc(ctx->queue_num, sizeof(bool));
    if (ctx->queue_ops.is_polling == nullptr) {
        TEST_LOG_ERROR("queue_interrupt calloc failed\n");
        return TEST_FAILED;
    }
    for (uint32_t j = 0; j < ctx->queue_num; j++) {
        ctx->queue_ops.is_polling[j] = false;
    }
    if (polling_arr) {
        for (uint32_t j = 0; j < arr_size; j++) {
            ctx->queue_ops.is_polling[polling_arr[j]] = true;
        }
    }
    return TEST_SUCCESS;
}

int test_queue_interrupt_fd_get(test_urpc_ctx_t * ctx, uint32_t qidx)
{
    if (ctx->queue_ops.is_epoll && ctx->queue_ops.is_polling[qidx] == false) {
        ctx->queue_ops.queue_fd[qidx] = urpc_queue_interrupt_fd_get(ctx->queue_handles[qidx]);
        TEST_LOG_INFO("interrupt_fd_get queue_fd[%d]: %d\n", qidx, ctx->queue_ops.queue_fd[qidx]);
        if (ctx->queue_ops.queue_fd[qidx] < 0) {
            TEST_LOG_ERROR("urpc_queue_interrupt_fd_get failed\n");
            return TEST_FAILED;
        }
        struct epoll_event ep_event;
        ep_event.data.fd = ctx->queue_ops.queue_fd[qidx];
        ep_event.events = EPOLLIN;
        if (epoll_ctl(ctx->queue_ops.epoll_fd, EPOLL_CTL_ADD, ctx->queue_ops.queue_fd[qidx], &ep_event) == -1) {
            TEST_LOG_ERROR("epoll_ctl failed, qidx=%u errno:%d, message: %s.\n", qidx, errno, strerror(errno));
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int test_urpc_queue_rx_post(test_urpc_ctx_t *ctx, uint32_t rx_num, uint64_t urpc_qh)
{
    urpc_sge_t *sges;
    uint32_t sge_num = 0;
    urpc_qcfg_get_t cfg = {};
    uint32_t post_rx_num = rx_num;
    uint32_t rx_buf_size = 0;
    if (rx_num != 1) {
        if (urpc_qh == 0) {
            for (int i = 0; i < ctx->queue_num; i++ ) {
                urpc_queue_cfg_get(ctx->queue_handles[i], &cfg);
                post_rx_num = cfg.rx_depth;
                rx_buf_size = cfg.rx_buf_size;
                for (int k = 0; k < post_rx_num; k++) {
                    if ((g_test_allocator.get(&sges, &sge_num, rx_buf_size, nullptr)) != 0) {
                        TEST_LOG_ERROR("get sges failed\n");
                        return TEST_FAILED;
                    }
                    if (urpc_queue_rx_post(ctx->queue_handles[i], sges, sge_num) != URPC_SUCCESS) {
                        g_test_allocator.put(sges, sge_num, nullptr);
                        return TEST_FAILED;
                    }
                }
            }
        } else {
            urpc_queue_cfg_get(urpc_qh, &cfg);
            post_rx_num = cfg.rx_depth;
            rx_buf_size = cfg.rx_buf_size;
            for (int k = 0; k < post_rx_num; k++) {
                if ((g_test_allocator.get(&sges, &sge_num, rx_buf_size, nullptr)) != 0) {
                    TEST_LOG_ERROR("get sges failed\n");
                    return TEST_FAILED;
                }
                if (urpc_queue_rx_post(urpc_qh, sges, sge_num) != URPC_SUCCESS) {
                    g_test_allocator.put(sges, sge_num, nullptr);
                    return TEST_FAILED;
                }
            }
        }
    } else {
        urpc_queue_cfg_get(urpc_qh, &cfg);
         rx_buf_size = cfg.rx_buf_size;
         for (int k = 0; k < post_rx_num; k++) {
            if ((g_test_allocator.get(&sges, &sge_num, rx_buf_size, nullptr)) != 0) {
                TEST_LOG_ERROR("get sges failed\n");
                return TEST_FAILED;
            }
            if (urpc_queue_rx_post(urpc_qh, sges, sge_num) != URPC_SUCCESS) {
                g_test_allocator.put(sges, sge_num, nullptr);
                return TEST_FAILED;
            }
        }
    }
    return TEST_SUCCESS;
}

int test_queue_create(test_urpc_ctx_t *ctx, urpc_queue_trans_mode_t trans_mode, urpc_qcfg_create_t *queue_cfg)
{
    TEST_LOG_INFO("ctx->queue_num=%u\n",ctx->queue_num);
    if (ctx->queue_num == 0) {
        return TEST_SUCCESS;
    }
    ctx->queue_handles = (uint64_t *)calloc(ctx->queue_num, sizeof(uint64_t));
    if (ctx->queue_handles == nullptr) {
        TEST_LOG_ERROR("queue_handles calloc failed\n");
        return TEST_FAILED;
    }
    urpc_qcfg_create_t qcfg = {};
    if (queue_cfg == nullptr) {
        ctx->queue_cfg->rx_buf_size = ctx->allocator_config.block_size;
        ctx->queue_cfg->rx_depth = DEFAULT_RX_DEPTH;
        (void)memcpy(&qcfg, ctx->queue_cfg, sizeof(urpc_qcfg_create_t));
    } else {
        (void)memcpy(&qcfg, queue_cfg, sizeof(urpc_qcfg_create_t));
    }
    uint32_t queue_num = ctx->queue_num;
    ctx->queue_num = 0;
    for (uint32_t i = 0; i < queue_num; i++) {
        ctx->queue_handles[i] = urpc_queue_create(trans_mode, &qcfg);
        if (ctx->queue_handles[i] == URPC_INVALID_HANDLE) {
            TEST_LOG_ERROR("urpc_queue_create idx=%u failed\n", i);
        } else {
            ctx->queue_num++;
        }
        if (test_queue_interrupt_fd_get(ctx, i) != TEST_SUCCESS) {
            return TEST_FAILED;
        }
    }
    if (ctx->queue_num > 0) {
        ctx->ctx_flag |= CTX_FLAG_QUEUE_CREATE;
    }
    if (ctx->queue_num == queue_num) {
        return TEST_SUCCESS;
    }
    return TEST_FAILED;
}

static const char *parse_queue_stats(uint32_t status)
{
    if (status == QUEUE_STATUS_IDLE) {
        return "QUEUE_STATUS_IDLE";
    } else if (status == QUEUE_STATUS_RUNNING) {
        return "QUEUE_STATUS_RUNNING";
    } else if (status == QUEUE_STATUS_RESET) {
        return "QUEUE_STATUS_RESET";
    } else if (status == QUEUE_STATUS_READY) {
        return "QUEUE_STATUS_READY";
    } else if (status == QUEUE_STATUS_FAULT) {
        return "QUEUE_STATUS_FAULT";
    } else if (status == QUEUE_STATUS_ERR) {
        return "QUEUE_STATUS_ERR";
    } else {
        return "QUEUE_STATUS_MAX";
    }
}

int test_channel_create(test_urpc_ctx_t *ctx)
{
    TEST_LOG_INFO("ctx->channel_num=%u\n", ctx->channel_num);
    if (ctx->channel_num == 0) {
        return TEST_SUCCESS;
    }
    ctx->channel_ids = (uint32_t *)calloc(ctx->channel_num, sizeof(uint32_t));
    if (ctx->channel_ids == nullptr) {
        TEST_LOG_ERROR("channel_ids calloc failed\n");
        return TEST_FAILED;
    }
    ctx->channel_ops = (channel_ops_t *)calloc(ctx->channel_num, sizeof(channel_ops_t));
    if (ctx->channel_ops == nullptr) {
        TEST_LOG_ERROR("channel_ops calloc failed\n");
        return TEST_FAILED;
    }
    uint32_t channel_num = ctx->channel_num;
    ctx->channel_num = 0;
    for (uint32_t i = 0; i< channel_num; i++) {
        ctx->channel_ids[i] = urpc_channel_create();
        ctx->channel_ops[i].idx = i;
        ctx->channel_ops[i].id = ctx->channel_ids[i];
        if (ctx->channel_ids[i] == URPC_U32_FAIL) {
            TEST_LOG_ERROR("urpc_channel_create idx=%u failed\n", i);
        } else {
            ctx->channel_num++;
        }
    }
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        TEST_LOG_DEBUG("channel idx=%u, id=%u\n", i, ctx->channel_ids[i]);
    }
    if (ctx->channel_num > 0) {
        ctx->ctx_flag |= CTX_FLAG_CHANNEL_CREATE;
    }
    if (ctx->channel_num == channel_num) {
        return TEST_SUCCESS;
    }
    return TEST_FAILED;
}

int test_channel_queue_add(uint32_t channel_id, uint64_t queue_handle, bool is_remote, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret, task_id;
    urpc_channel_queue_attr_t attr = {};
    attr.type = CHANNEL_QUEUE_TYPE_LOCAL;
    if (is_remote) {
        attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    }
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_queue_add(channel_id, queue_handle, attr, &coption);
    } else {
        task_id = urpc_channel_queue_add(channel_id, queue_handle, attr, option);
    }
    if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_BLOCK) {
        return task_id;
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_queue_add", EXIT);
    if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_ENABLE || g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(&g_test_urpc_ctx, URPC_ASYNC_EVENT_CHANNEL_QUEUE_ADD, wait_time);
    } else if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NOT_EPOLL || g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_QUEUE_ADD, wait_time);
    }
    return ret;
EXIT:
    return TEST_FAILED;
}

int test_channel_queue_rm(uint32_t channel_id, uint64_t queue_handle, bool is_remote, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret, task_id;
    urpc_channel_queue_attr_t attr = {};
    attr.type = CHANNEL_QUEUE_TYPE_LOCAL;
    if (is_remote) {
        attr.type = CHANNEL_QUEUE_TYPE_REMOTE;
    }
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_queue_rm(channel_id, queue_handle, attr, &coption);
    } else {
        task_id = urpc_channel_queue_rm(channel_id, queue_handle, attr, option);
    }
    if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_BLOCK) {
        return task_id;
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_queue_rm", EXIT);
    if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_ENABLE || g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(&g_test_urpc_ctx, URPC_ASYNC_EVENT_CHANNEL_QUEUE_RM, wait_time);
    } else if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NOT_EPOLL || g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_QUEUE_RM, wait_time);
    }
    return ret;
EXIT:
    return TEST_FAILED;
}

static int link_log_failure(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_host_info_t *host, int ret, const char *op_type)
{
    if (ret != TEST_SUCCESS) {
        if (ctx->cp_is_ipv6) {
            TEST_LOG_ERROR("urpc_channel_server_%s channel_id=%lu server ip_addr=%s port=%u ret=%d, failed\n", op_type,
            urpc_chid, host->ipv6.ip_addr, host->ipv6.port, ret);
        } else {
            TEST_LOG_ERROR("urpc_channel_server_%s channel_id=%lu server ip_addr=%s port=%u ret=%d, failed\n", op_type,
            urpc_chid, host->ipv4.ip_addr, host->ipv4.port, ret);
        }
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int wait_async_event_result(test_urpc_ctx_t *ctx, urpc_async_event_type_t type, int timeout)
{
    urpc_async_event_t event = {};
    struct epoll_event epoll_event;
    int ret, num;
    do {
        ret = epoll_wait(ctx->async_ops.epoll_fd, &epoll_event, 1, timeout);
    } while (ret== -1 && errno == EINTR);
    if (ret == -1 && errno != EINTR) {
        TEST_LOG_ERROR("epoll_wait, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        goto EXIT;
    }
    if (epoll_event.data.fd != ctx->async_ops.event_fd) {
        TEST_LOG_ERROR("epoll_event.data.fd != ctx->async_ops.event_fd.\n");
        goto EXIT;
    }
    num = urpc_async_event_get(&event, 1);
    CHKERR_JUMP(num < 0, "urpc_async_event_get num", EXIT);
    TEST_LOG_DEBUG("get event err_code=%d event_type=%u\n", event.err_code, event.event_type);
    if (event.err_code != URPC_SUCCESS || event.event_type != type) {
        TEST_LOG_ERROR("check async event type=%d is failed. event.type=%u err_code=%d\n", type, event.event_type, event.err_code);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

int test_async_event_get(urpc_async_event_type_t type, size_t wait_time_ms)
{
    urpc_async_event_t event = {};
    int num;
    uint64_t start_time = get_timestamp_ms();
    uint64_t current_time = start_time;
    while (current_time - start_time < wait_time_ms) {
        num = urpc_async_event_get(&event, 1);
        CHKERR_JUMP(num < 0, "urpc_async_event_get ret", EXIT);
        if (num > 0) {
            break;
        }
        current_time = get_timestamp_ms();
    }
    TEST_LOG_DEBUG("get event num=%d err_code=%d event_type=%u\n", num, event.err_code, event.event_type);
    if (event.err_code != URPC_SUCCESS || event.event_type != type) {
        TEST_LOG_ERROR("check async event is failed\n");
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

urpc_channel_connect_option_t get_channel_connect_option(bool set_ctrl_msg, int timeout)
{
    urpc_channel_connect_option_t option = {};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    if (g_test_urpc_ctx.async_ops.flag == ASYNC_FLAG_BLOCK) {
        option.feature = 0;
    } else {
        option.feature = URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
    }
    option.timeout = timeout;
    if (set_ctrl_msg || g_test_urpc_ctx.ctrl_cb != nullptr) {
        if (g_test_urpc_ctx.ctrl_msg == nullptr) {
            char msg[CTRL_MSG_MAX_SIZE] = "=======this is client ctrl msg";
            set_ctx_ctrl_msg_param(&g_test_urpc_ctx, msg);
        }
        option.ctrl_msg = g_test_urpc_ctx.ctrl_msg;
        option.flag |= URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
    }
    return option;
}

int test_channel_server_attach(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_host_info_t *host, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret, task_id;
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_server_attach(urpc_chid, host, &coption);
    } else {
        task_id = urpc_channel_server_attach(urpc_chid, host, option);
    }
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return link_log_failure(ctx, urpc_chid, host, task_id, "attach");
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_server_attach", EXIT);
    if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(ctx, URPC_ASYNC_EVENT_CHANNEL_ATTACH);
    } else if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_ATTACH, wait_time);
    }
    return link_log_failure(ctx, urpc_chid, host, ret, "attach");
EXIT:
    return TEST_FAILED;
}

int test_channel_server_detach(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_host_info_t *host, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret, task_id;
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_server_detach(urpc_chid, host, &coption);
    } else {
        task_id = urpc_channel_server_detach(urpc_chid, host, option);
    }
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return link_log_failure(ctx, urpc_chid, host, task_id, "detach");
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_server_detach", EXIT);
    if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(ctx, URPC_ASYNC_EVENT_CHANNEL_DETACH, wait_time);
    } else if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_DETACH, wait_time);
    }
    return link_log_failure(ctx, urpc_chid, host, ret, "detach");
EXIT:
    return TEST_FAILED;
}

int test_channel_server_refresh(test_urpc_ctx_t *ctx, uint32_t urpc_chid, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret, task_id;
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_server_refresh(urpc_chid, &coption);
    } else {
        task_id = urpc_channel_server_refresh(urpc_chid, option);
    }
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return task_id;
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_server_refresh", EXIT);
    if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(ctx, URPC_ASYNC_EVENT_CHANNEL_REFRESH);
    } else if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_REFRESH, wait_time);
    }
    return ret;
EXIT:
    return TEST_FAILED;
}

int test_server_attach(test_urpc_ctx_t *ctx, urpc_channel_connect_option_t *connect_option)
{
    int ret;
    if (ctx->server_num == DEFAULT_SERVER_NUM) {
        for (uint32_t i = 0; i < ctx->channel_num; i++) {
            (void)memcpy(&ctx->channel_ops[i].server, ctx->host_info, sizeof(urpc_host_info_t));
            ret = test_channel_server_attach(ctx, ctx->channel_ops[i].id, ctx->host_info, connect_option);
            if (ret != TEST_SUCCESS) {
                return TEST_FAILED;
            }
            
        }
    } else {
        for (uint32_t i = 0; i < ctx->server_num; i++) {
            (void)memcpy(&ctx->channel_ops[i].server, &ctx->host_info[i], sizeof(urpc_host_info_t));
            ret = test_channel_server_attach(ctx, ctx->channel_ops[i].id, &ctx->host_info[i], connect_option);
            if (ret != TEST_SUCCESS) {
                return TEST_FAILED;
            }
            
        }
    }
    ctx->ctx_flag |= CTX_FLAG_SERVER_ATTACH;
    return TEST_SUCCESS;
}

int test_server_detach(test_urpc_ctx_t *ctx, urpc_channel_connect_option_t *connect_option)
{
    int rc = 0, ret;
    if ((ctx->ctx_flag & CTX_FLAG_SERVER_ATTACH) != 0) {
        if (ctx->server_num == DEFAULT_SERVER_NUM) {
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                ret = test_channel_server_detach(ctx, ctx->channel_ops[i].id, ctx->host_info, connect_option);
                rc += ret;
            }
        } else {
            for (uint32_t i = 0; i < ctx->server_num; i++) {
                ret = test_channel_server_detach(ctx, ctx->channel_ops[i].id, &ctx->host_info[i], connect_option);
                rc += ret;
            }
        }
        if (rc == 0) {
            ctx->ctx_flag &= ~CTX_FLAG_SERVER_ATTACH;
        }
    }
    return rc;
}

static channel_ops_t *get_channel_ops_by_id(uint32_t channel_id)
{
    for (uint32_t i = 0; i < g_test_urpc_ctx.channel_num; i++) {
        if (channel_id == g_test_urpc_ctx.channel_ops[i].id) {
            return &g_test_urpc_ctx.channel_ops[i];
        }
    }
    return nullptr;
}

int rm_queue_from_channel_and_destroy(uint32_t channel_id, uint64_t queue_handle)
{
    return test_channel_queue_rm(channel_id, queue_handle) && test_destroy_one_queue(queue_handle);
}

int test_flush_channel_lqueue(channel_ops_t *channel_ops)
{
    if (!channel_ops->flush_lqueue) {
        return TEST_SUCCESS;
    }
    channel_ops->lqueue_num = 0;
    CHECK_FREE(channel_ops->lqueue_ops);
    channel_ops->lqueue_num = !channel_ops->not_one_by_one ? 1 : g_test_urpc_ctx.queue_num;
    channel_ops->lqueue_ops = (lqueue_ops_t *)calloc(channel_ops->lqueue_num, sizeof(lqueue_ops_t));
    if (channel_ops->lqueue_ops == NULL) {
        TEST_LOG_ERROR("channel_ops->lqueue_ops calloc failed\n", channel_ops->lqueue_ops);
        return TEST_FAILED;
    }
    for (uint32_t j = 0; j < channel_ops->lqueue_num; j++) {
        channel_ops->lqueue_ops[j].qh = !channel_ops->not_one_by_one ? g_test_urpc_ctx.queue_handles[channel_ops->idx] : g_test_urpc_ctx.queue_handles[j];
    }
    channel_ops->flush_rqueue = false;
    return TEST_SUCCESS;
}

int test_channel_add_local_queue(channel_ops_t *channel_ops)
{
    int ret;
    for (uint32_t j = 0; j < channel_ops->lqueue_num; j++) {
        ret = test_channel_queue_add(channel_ops->id, channel_ops->lqueue_ops[j].qh);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_channel_queue_add channel_ops->id=%u lqueue_ops[%u].qh=%p failed\n", channel_ops->id, j, channel_ops->lqueue_ops[j].qh);
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int test_add_local_queue(test_urpc_ctx_t *ctx, bool flush_lqueue)
{
    int ret;
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        ctx->channel_ops[i].flush_lqueue = flush_lqueue;
        ctx->channel_ops[i].not_one_by_one = ctx->not_one_by_one;
        ret = test_flush_channel_lqueue(&ctx->channel_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_flush_channel_lqueue channel_ops[%u] failed\n", i);
            return TEST_FAILED;
        }
        ret = test_channel_add_local_queue(&ctx->channel_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_channel_add_local_queue channel_ops[%u] failed\n", i);
            return TEST_FAILED;
        }
    }
    ctx->ctx_flag |= CTX_FLAG_CHANNEL_ADD_LOCAL_QUEUE;
    return TEST_SUCCESS;
}

int test_flush_channel_rqueue(channel_ops_t *channel_ops)
{
    if (!channel_ops->flush_rqueue) {
        return TEST_SUCCESS;
    }
    channel_ops->rqueue_num = 0;
    CHECK_FREE(channel_ops->rqueue_ops);
    int ret = test_channel_get_server_queue(channel_ops);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_channel_get_server_queue failed\n");
        return TEST_FAILED;
    }
    channel_ops->rqueue_num = !channel_ops->not_one_by_one ? 1 : channel_ops->squeue.num;
    channel_ops->rqueue_ops = (rqueue_ops_t *)calloc(channel_ops->rqueue_num, sizeof(rqueue_ops_t));
    if (channel_ops->rqueue_ops == NULL) {
        TEST_LOG_ERROR("ctx->channel_ops[%u].rqueue_ops calloc failed\n", channel_ops->rqueue_ops);
        return TEST_FAILED;
    }
    for (uint32_t j = 0; j < channel_ops->rqueue_num; j++) {
        if (g_test_urpc_ctx.server_num == DEFAULT_SERVER_NUM) {
            channel_ops->rqueue_ops[j].qid = !channel_ops->not_one_by_one ? channel_ops->squeue.qid[channel_ops->idx] : channel_ops->squeue.qid[j];
        } else {
            channel_ops->rqueue_ops[j].qid = channel_ops->squeue.qid[0];
        }
    }
    channel_ops->flush_rqueue = false;
    return TEST_SUCCESS;
}

int test_channel_add_remote_queue(channel_ops_t *channel_ops)
{
    int ret;
    urpc_channel_qinfos_t qinfos;
    for (uint32_t j = 0; j < channel_ops->rqueue_num; j++) {
        ret = test_channel_queue_add(channel_ops->id, channel_ops->rqueue_ops[j].qid, true);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_channel_queue_add channel_ops->id=%u rqueue_ops[%u].qid=%u failed\n", channel_ops->id, j, channel_ops->rqueue_ops[j].qid);
            return TEST_FAILED;
        }

    }
    ret = urpc_channel_queue_query(channel_ops->id, &qinfos);
    CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
    for (int j = 0; j < qinfos.r_qnum; j++) {
        channel_ops->rqueue_ops[j].qh = qinfos.r_qinfo[j].urpc_qh;
    }

    return TEST_SUCCESS;
EXIT:
    return TEST_FAILED;
}

int test_add_remote_queue(test_urpc_ctx_t *ctx, bool flush_rqueue)
{
    int retry = 0, ret = TEST_FAILED;
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        ctx->channel_ops[i].flush_rqueue = flush_rqueue;
        ctx->channel_ops[i].not_one_by_one = ctx->not_one_by_one;
        ret = test_flush_channel_rqueue(&ctx->channel_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_flush_channel_rqueue channel_ops[%u] failed\n", i);
            return TEST_FAILED;
        }
        ret = test_channel_add_remote_queue(&ctx->channel_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_channel_add_remote_queue channel_ops[%u] failed\n", i);
            return TEST_FAILED;
        }
    }
    ctx->func_id = DEFAULT_FUNC_ID;
    ctx->ctx_flag |= CTX_FLAG_CHANNEL_ADD_REMOTE_QUEUE;
    return TEST_SUCCESS;
}

int test_channel_rm_local_queue(channel_ops_t *channel_ops, bool is_free)
{
    int rc = 0, task_id, ret;
    for (uint32_t j = 0; j < channel_ops->lqueue_num; j++) {
        ret = test_channel_queue_rm(channel_ops->id, channel_ops->lqueue_ops[j].qh);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_channel_queue_rm channel_ops->id=%u lqueue_ops[%u].qh=%p failed\n",channel_ops->id, j, channel_ops->lqueue_ops[j].qh);
        }
        rc += ret;
    }
    if (is_free) {
        channel_ops->lqueue_num = 0;
        channel_ops->flush_lqueue = false;
        CHECK_FREE(channel_ops->lqueue_ops);
    }
    return rc;
}

int test_rm_local_queue(test_urpc_ctx_t *ctx, channel_ops_t *channel_ops)
{
    if (channel_ops != NULL) {
        return test_channel_rm_local_queue(channel_ops);
    }
    int rc = 0, ret;
    if ((ctx->ctx_flag & CTX_FLAG_CHANNEL_ADD_LOCAL_QUEUE) == 0) {
        return TEST_SUCCESS;
    }
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        rc += test_channel_rm_local_queue(&ctx->channel_ops[i]);
    }
    if (rc == 0) {
        ctx->ctx_flag &= ~CTX_FLAG_CHANNEL_ADD_LOCAL_QUEUE;
    }
    return rc;
}

int test_channel_rm_remote_queue(channel_ops_t *channel_ops, bool is_free)
{
    int rc = 0, task_id, ret;
    for (uint32_t j = 0; j < channel_ops->rqueue_num; j++) {
        ret = test_channel_queue_rm(channel_ops->id, channel_ops->rqueue_ops[j].qid, true);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_channel_queue_rm channel_ops->id=%u rqueue_ops[%u].qid=%u failed\n", channel_ops->id, j, channel_ops->rqueue_ops[j].qid);
        }
        rc += ret;
    }
    if (is_free) {
        channel_ops->rqueue_num = 0;
        channel_ops->flush_rqueue = false;
        CHECK_FREE(channel_ops->rqueue_ops);
    }
    return rc;
}

int test_rm_remote_queue(test_urpc_ctx_t *ctx, channel_ops_t *channel_ops)
{
    if (channel_ops != NULL) {
        return test_channel_rm_remote_queue(channel_ops);
    }
    int rc = 0, ret;
    if ((ctx->ctx_flag & CTX_FLAG_CHANNEL_ADD_REMOTE_QUEUE) == 0) {
        return TEST_SUCCESS;
    }
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        rc += test_channel_rm_remote_queue(&ctx->channel_ops[i]);
    }
    if (rc == 0) {
        ctx->ctx_flag &= ~CTX_FLAG_CHANNEL_ADD_REMOTE_QUEUE;
    }
    return rc;
}

server_queue_t get_server_queue()
{
    int ret = 0;
    urpc_qcfg_get_t qcfg_get_cfg = {0};
    server_queue_t server_queue = {};
    memset(&server_queue, 0, sizeof(server_queue_t));
    server_queue.num = g_test_urpc_ctx.queue_num;
    server_queue.app_id = g_test_urpc_ctx.app_id;
    if (g_test_urpc_ctx.queue_handles == nullptr || g_test_urpc_ctx.queue_num == 0) {
        TEST_LOG_WARN("server queue_handles is %p, queue_num is %u\n", g_test_urpc_ctx.queue_handles, g_test_urpc_ctx.queue_num);
        return server_queue;
    }
    for (uint32_t i = 0; i < g_test_urpc_ctx.queue_num; i++) {
        ret = urpc_queue_cfg_get(g_test_urpc_ctx.queue_handles[i], &qcfg_get_cfg);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("queue %u urpc_queue_cfg_get failed\n", i);
        }
        server_queue.qid[i] = qcfg_get_cfg.qid;
    }
    return server_queue;
}

static void *qserver_worker_func(void *args)
{
    struct epoll_event event;
    while (g_qserver_status) {
        usleep(1);
        int ret = epoll_wait(g_qserver_epoll_fd, &event, 1, 100);
        if (ret == -1 && errno == EINTR){
            continue;
        }
        if (ret > 0 && event.data.fd == g_qserver_fd) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(g_qserver_fd, (struct sockaddr *)&client_addr, &addr_len);
            if (client_fd == -1) {
                if (errno == EBADF) {
                    break;
                }
                continue;
            }
            char buffer[1024];
            recv(client_fd, buffer, sizeof(buffer), 0);
            if (strcmp(buffer, "GET_QID") == 0) {
                server_queue_t server_queue = get_server_queue();
                send(client_fd, (char *)&server_queue, sizeof(server_queue_t), 0);
            }
            close(client_fd);
        }
    }
    return NULL;
}

static int test_qserver_start(test_urpc_ctx_t *ctx)
{
    if (ctx->cp_is_ipv6) {
        g_qserver_fd = start_ipv6_server(ctx->urpc_cp_config->server.ipv6.ip_addr, ctx->urpc_cp_config->server.ipv6.port + 10000);
    } else {
        g_qserver_fd = start_ipv4_server(ctx->urpc_cp_config->server.ipv4.ip_addr, ctx->urpc_cp_config->server.ipv4.port + 10000);
    }
    if (g_qserver_fd < 0) {
        TEST_LOG_ERROR("create qserver socket failed, %s\n", strerror(errno));
        return TEST_FAILED;
    }

    g_qserver_epoll_fd = epoll_create1(0);
    if (g_qserver_epoll_fd < 0) {
        TEST_LOG_ERROR("qserver epoll_create1 failed, %s\n", strerror(errno));
        return TEST_FAILED;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = g_qserver_fd;
    if (epoll_ctl(g_qserver_epoll_fd, EPOLL_CTL_ADD, g_qserver_fd, &ev) != 0) {
        TEST_LOG_ERROR("qserver epoll_ctl failed, %s\n", strerror(errno));
        return TEST_FAILED;
    }
    g_qserver_status = true;
    if (pthread_create(&g_qserver_thread, NULL, qserver_worker_func, NULL) != 0) {
        TEST_LOG_ERROR("qserver pthread_create failed, %s\n", strerror(errno));
        return TEST_FAILED;
    }
    const char *thread_name = "qserver_listen";
    if (pthread_setname_np(g_qserver_thread, thread_name) != 0) {
        TEST_LOG_ERROR("qserver pthread_setname_np failed, %s\n", strerror(errno));
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

void test_qserver_stop(test_urpc_ctx_t *ctx)
{
    g_qserver_status = false;
    if (g_qserver_epoll_fd >= 0) {
        epoll_ctl(g_qserver_epoll_fd, EPOLL_CTL_DEL, g_qserver_fd, NULL);
    }
    if (g_qserver_fd >= 0) {
        close(g_qserver_fd);
    }
    if (g_qserver_thread != 0) {
        pthread_join(g_qserver_thread, NULL);
        g_qserver_thread = 0;
    }
}

int test_channel_get_server_queue(channel_ops_t *channel_ops)
{
    int ret, client_fd;
    char buffer[MAX_LINE_LENGTH] = {0};
    const char *message = "GET_QID";
    size_t len = strlen(message);
    if (g_test_urpc_ctx.cp_is_ipv6) {
        client_fd = start_ipv6_client(channel_ops->server.ipv6.ip_addr, channel_ops->server.ipv6.port + 10000);
    } else {
        client_fd = start_ipv4_client(channel_ops->server.ipv4.ip_addr, channel_ops->server.ipv4.port + 10000);
    }
    CHKERR_JUMP(client_fd < 0, "create client socket", EXIT);
    ret = send(client_fd, message, len, 0);
    server_queue_t server_queue;
    CHKERR_JUMP(ret < len, "send", EXIT);
    ret = read(client_fd, &server_queue, sizeof(server_queue_t));
    CHKERR_JUMP(ret < len, "read", EXIT);
    memset(&channel_ops->squeue, 0, sizeof(server_queue_t));
    (void)memcpy(&channel_ops->squeue, &server_queue, sizeof(server_queue_t));
    close(client_fd);
    return TEST_SUCCESS;
EXIT:
    close(client_fd);
    return TEST_FAILED;
}

int test_channel_queue_pair(test_urpc_ctx_t *ctx, uint32_t urpc_chid, uint64_t l_queue, uint64_t r_queue, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret = TEST_FAILED, task_id;
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_queue_pair(urpc_chid, l_queue, r_queue, &coption);
    } else {
        task_id = urpc_channel_queue_pair(urpc_chid, l_queue, r_queue, option);
    }
    TEST_LOG_INFO("urpc_channel_queue_pair task_id=%d\n",task_id);
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return task_id;
    }
    CHKERR_JUMP(task_id <= 0, "test_channel_queue_pair", EXIT);
    if (ctx->async_ops.flag == ASYNC_FLAG_ENABLE || ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(ctx, URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR);
        CHKERR_JUMP(ret != TEST_SUCCESS, "wait_async_event_result", EXIT);
    } else if (ctx->async_ops.flag == ASYNC_FLAG_NOT_EPOLL || ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR, wait_time);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_async_event_get", EXIT);
    }
    ctx->ctx_flag |= CTX_FLAG_QUEUE_PAIR;
    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

int test_normal_queue_pair(test_urpc_ctx_t *ctx, uint32_t channel_id, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret = TEST_FAILED;
    int pair_num_each_channel = 0;
    int queue_mod_channel = 0;
    urpc_channel_qinfos_t qinfos;

    if (channel_id == URPC_U32_FAIL) {
        if (!ctx->not_one_by_one) {
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                if (ctx->channel_ids[i] == URPC_U32_FAIL) {
                    continue;
                }
                memset(&qinfos, 0, sizeof(qinfos));
                ret = urpc_channel_queue_query(ctx->channel_ids[i], &qinfos);
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
                for (uint32_t j = 0; j < ctx->channel_ops[i].rqueue_num; j++) {
                    TEST_LOG_DEBUG("test round channel id=%u lqueue id=%u rqueue id=%u\n",i ,j ,j);
                    TEST_LOG_DEBUG("test_channel_queue_pair %u lqh=%p rqh=%p\n",j ,ctx->channel_ops[i].lqueue_ops[j].qh, ctx->channel_ops[i].rqueue_ops[j].qh);
                    if (qinfos.r_qinfo[j].status == QUEUE_STATUS_READY) {
                        ret = test_channel_queue_pair(ctx, ctx->channel_ids[i], ctx->channel_ops[i].lqueue_ops[j].qh, ctx->channel_ops[i].rqueue_ops[j].qh, option, wait_time);
                        if (ret != TEST_SUCCESS) {
                            TEST_LOG_INFO("test round channel id=%u lqueue id=%u rqueue id=%u\n",i ,j ,j);
                            TEST_LOG_ERROR("test_channel_queue_pair %u lqh=%p\n", j, ctx->channel_ops[i].lqueue_ops[j].qh);
                            TEST_LOG_ERROR("test_channel_queue_pair %u rqh=%p\n", j, ctx->channel_ops[i].rqueue_ops[j].qh);
                        }
                        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_pair", EXIT);
                    }
                }
            }
        } else {
            pair_num_each_channel = ctx->queue_num / ctx->channel_num;
            queue_mod_channel = ctx->queue_num % ctx->channel_num;
            int loop = pair_num_each_channel;
            TEST_LOG_INFO("pair_num_each_channel:%d queue_mod_channel:%d\n", pair_num_each_channel, queue_mod_channel);
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                if (ctx->channel_ids[i] == URPC_U32_FAIL) {
                    continue;
                }
            
                memset(&qinfos, 0, sizeof(qinfos));
                ret = urpc_channel_queue_query(ctx->channel_ids[i], &qinfos);
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
                if (queue_mod_channel != 0) {
                    if (i == ctx->channel_num - 1) {
                        loop = queue_mod_channel + pair_num_each_channel;
                    }
                }
            
                for (uint32_t j = 0; j < loop; j++) {
                    TEST_LOG_DEBUG("test round channel id=%u lqueue id=%u rqueue id=%u\n",i , i * pair_num_each_channel + j, i * pair_num_each_channel + j);
                    TEST_LOG_DEBUG("test_channel_queue_pair %u lqh=%llu rqh=%llu\n", i * pair_num_each_channel + j, ctx->channel_ops[i].lqueue_ops[i*pair_num_each_channel+j].qh, 
                    ctx->channel_ops[i].rqueue_ops[i * pair_num_each_channel + j].qh);
                    if (qinfos.r_qinfo[i * pair_num_each_channel + j].status == QUEUE_STATUS_READY) {
                        ret = test_channel_queue_pair(ctx, ctx->channel_ids[i], ctx->channel_ops[i].lqueue_ops[i * pair_num_each_channel + j].qh,
                        ctx->channel_ops[i].rqueue_ops[i * pair_num_each_channel + j].qh, option, wait_time);
                        if (ret != TEST_SUCCESS) {
                            TEST_LOG_INFO("test round channel id=%u lqueue id=%u rqueue id=%u\n",i , i * pair_num_each_channel + j, i * pair_num_each_channel + j);
                            TEST_LOG_ERROR("test_channel_queue_pair %u lqh=%llu\n", i * pair_num_each_channel + j, ctx->channel_ops[i].lqueue_ops[i*pair_num_each_channel+j].qh);
                            TEST_LOG_ERROR("test_channel_queue_pair %u rqh=%llu\n", i * pair_num_each_channel + j, ctx->channel_ops[i].rqueue_ops[i * pair_num_each_channel + j].qh);
                        }
                        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_pair", EXIT);
                    }
                }
            }
        }
    } else {
        channel_ops_t *channel_ops = get_channel_ops_by_id(channel_id);
        memset(&qinfos, 0, sizeof(qinfos));
        ret = urpc_channel_queue_query(channel_id, &qinfos);
        CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
        for (uint32_t j = 0; j < channel_ops->rqueue_num; j++) {
            if (qinfos.r_qinfo[j].status == QUEUE_STATUS_READY) {
                ret = test_channel_queue_pair(ctx, channel_id, channel_ops->lqueue_ops[j].qh, channel_ops->rqueue_ops[j].qh, option, wait_time);
                CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_pair", EXIT);
            }
        }
    }
    ctx->ctx_flag |= CTX_FLAG_QUEUE_PAIR;
    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

int test_channel_queue_unpair(test_urpc_ctx_t *ctx, uint32_t urpc_chid, uint64_t l_queue, uint64_t r_queue, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret = TEST_FAILED, task_id;
    if (option == nullptr) {
        urpc_channel_connect_option_t coption = get_channel_connect_option();
        task_id = urpc_channel_queue_unpair(urpc_chid, l_queue, r_queue, &coption);
    } else {
        task_id = urpc_channel_queue_unpair(urpc_chid, l_queue, r_queue, option);
    }
    if (ctx->async_ops.flag == ASYNC_FLAG_BLOCK) {
        return task_id;
    }
    CHKERR_JUMP(task_id <= 0, "urpc_channel_queue_unpair", EXIT);
    if (ctx->async_ops.flag == ASYNC_FLAG_ENABLE || ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK) {
        ret = wait_async_event_result(ctx, URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR);
        CHKERR_JUMP(ret != TEST_SUCCESS, "wait_async_event_result", EXIT);
    } else if (ctx->async_ops.flag == ASYNC_FLAG_NON_BLOCK_NOT_POLL) {
        ret = test_async_event_get(URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR, wait_time);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_async_event_get", EXIT);
    }
    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

int test_normal_queue_unpair(test_urpc_ctx_t *ctx, uint32_t channel_id, urpc_channel_connect_option_t *option, size_t wait_time)
{
    int ret = TEST_FAILED;
    urpc_channel_qinfos_t qinfos;
    if ((ctx->ctx_flag & CTX_FLAG_QUEUE_PAIR) != 0) {
        if (channel_id == URPC_U32_FAIL) {
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                if (ctx->channel_ids[i] == URPC_U32_FAIL) {
                    continue;
                }
                memset(&qinfos, 0, sizeof(qinfos));
                ret = urpc_channel_queue_query(ctx->channel_ids[i], &qinfos);
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
                for (uint32_t j = 0; j < ctx->channel_ops[i].rqueue_num; j++) {
                    if (qinfos.r_qinfo[j].status == QUEUE_STATUS_READY) {
                        ret = test_channel_queue_unpair(ctx, ctx->channel_ids[i], ctx->channel_ops[i].lqueue_ops[j].qh, ctx->channel_ops[i].rqueue_ops[j].qh, option, wait_time);
                        CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
                    }
                }
            }
        } else {
            channel_ops_t *channel_ops = get_channel_ops_by_id(channel_id);
            memset(&qinfos, 0, sizeof(qinfos));
            ret = urpc_channel_queue_query(channel_id, &qinfos);
            CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_channel_queue_query", EXIT);
            for (uint32_t j = 0; j < channel_ops->rqueue_num; j++) {
                if (qinfos.r_qinfo[j].status == QUEUE_STATUS_READY) {
                    ret = test_channel_queue_unpair(ctx, channel_id, channel_ops->lqueue_ops[j].qh, channel_ops->rqueue_ops[j].qh, option, wait_time);
                    CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_queue_unpair", EXIT);
                }
            }
        }
        ctx->ctx_flag &= ~CTX_FLAG_QUEUE_PAIR;
    }
    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

void test_urpc_handler_func(urpc_sge_t *args, uint32_t args_sge_num, void *ctx, urpc_sge_t **rsps, uint32_t *rsps_sge_num)
{
    char *client_msg = (char *)(uintptr_t)args[0].addr + urpc_hdr_size_get(URPC_REQ, 0);
    g_test_urpc_ctx.rsp_size = (g_test_urpc_ctx.rsp_size == 0) ? g_test_urpc_ctx.allocator_config.block_size : g_test_urpc_ctx.rsp_size;
    int ret = g_test_allocator.get(rsps, rsps_sge_num, g_test_urpc_ctx.rsp_size, nullptr);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("g_test_allocator get failed, ret:%d, errno:%d, message: %s.", ret, errno, strerror(errno));
        return;
    }
    uint32_t hdr_size = urpc_hdr_size_get(URPC_RSP, 0);
    (void)sprintf((char *)(uintptr_t)rsps[0]->addr + hdr_size, "hello client!");
    rsps[0]->length = g_test_urpc_ctx.rsp_size;
    TEST_LOG_DEBUG(">>>>> rsp_size=%lu, sge num=%u\n", g_test_urpc_ctx.rsp_size, *rsps_sge_num);
}

int test_func_register(test_urpc_ctx_t *ctx)
{
    urpc_handler_info_t func_info;
    memset(&func_info, 0, sizeof(func_info));
    func_info.type = URPC_HANDLER_SYNC;
    func_info.sync_handler = test_urpc_handler_func;
    (void)memcpy(&func_info.name, DEFAULT_FUNC_NAME, sizeof(func_info.name));

    int ret = urpc_func_register(&func_info, &ctx->func_id);
    TEST_LOG_INFO("urpc_func_register func_id %lu\n", ctx->func_id);
    if (ret != 0) {
        TEST_LOG_ERROR("urpc_func_register return error %d\n", ret);
        return TEST_FAILED;
    }
    ctx->ctx_flag |= CTX_FLAG_FUNC_REGISTER;
    return TEST_SUCCESS;
}

int test_func_unregister(test_urpc_ctx_t *ctx)
{
    if ((ctx->ctx_flag & CTX_FLAG_FUNC_REGISTER) != 0) {
        ctx->ctx_flag &= ~CTX_FLAG_FUNC_REGISTER;
        return urpc_func_unregister(ctx->func_id);
    }
    return TEST_SUCCESS;
}

int test_server_start(test_urpc_ctx_t *ctx)
{
    int ret = urpc_server_start(ctx->urpc_cp_config);
    if (ctx->cp_is_ipv6) {
        TEST_LOG_INFO("urpc_server_start ip_addr=%s, port=%d user_ctx=%u\n", ctx->urpc_cp_config->server.ipv6.ip_addr, ctx->urpc_cp_config->server.ipv6.port, *(uint32_t *)ctx->urpc_cp_config->user_ctx);
    } else {
        TEST_LOG_INFO("urpc_server_start ip_addr=%s, port=%d user_ctx=%u\n", ctx->urpc_cp_config->server.ipv4.ip_addr, ctx->urpc_cp_config->server.ipv4.port, *(uint32_t *)ctx->urpc_cp_config->user_ctx);
    }
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("urpc_server_start failed\n");
        return TEST_FAILED;
    }
    ret = test_qserver_start(ctx);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_qserver_start failed\n");
        return TEST_FAILED;
    }
    ctx->ctx_flag |= CTX_FLAG_SERVER_START;
    return TEST_SUCCESS;
}

uint32_t g_channel_mem_cnt = 0;

int test_mem_seg_remote_access_enable(test_urpc_ctx_t *ctx)
{
    int ret;
    
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
        while (ptr != NULL && ptr->tsge != NULL) {
            TEST_LOG_DEBUG("urpc_mem_seg_remote_access_enable ptr=%p ptr->tsge=%llu\n", ptr, ptr->tsge);
            ret = urpc_mem_seg_remote_access_enable(ctx->channel_ids[i], ptr->tsge);
            CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_mem_seg_remote_access_enable", EXIT);
            ptr = ptr->next;
            g_channel_mem_cnt++;
            ctx->ctx_flag |= CTX_FLAG_MEM_SEG_ACCESS_ENABLE;
        }
        
    }
    TEST_LOG_INFO("---test_mem_seg_remote_access_enable g_channel_mem_cnt [%u] \n", g_channel_mem_cnt)
EXIT:
    return ret;
}

int test_mem_seg_remote_access_disable(test_urpc_ctx_t *ctx)
{
    int ret;
    if ((ctx->ctx_flag & CTX_FLAG_MEM_SEG_ACCESS_ENABLE) == 0) {
        return TEST_SUCCESS;
    }

    if (g_test_allocator_ctx != NULL) {
        for (uint32_t i = 0; i < ctx->channel_num; i++) {
            test_allocator_buf_t *ptr = g_test_allocator_ctx->allocator_buf;
            while (ptr != NULL && ptr->tsge != NULL) {
                ret = urpc_mem_seg_remote_access_disable(ctx->channel_ids[i], ptr->tsge);
                CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_mem_seg_remote_access_disable", EXIT);
                ptr = ptr->next;
            }

        }
        ctx->ctx_flag &= ~CTX_FLAG_MEM_SEG_ACCESS_ENABLE;
    }
EXIT:
    return ret;
}

int test_destroy_one_queue(uint64_t queue_handle, uint32_t wait_time, bool do_rx_post)
{
    int ret = urpc_queue_destroy(queue_handle);
    if (ret == TEST_SUCCESS) {
        return TEST_SUCCESS;
    }
    test_poll_one_queue_event(queue_handle, wait_time, 0, do_rx_post);
    ret = urpc_queue_destroy(queue_handle);
    return ret;
}

int test_queue_destroy(test_urpc_ctx_t *ctx, uint32_t wait_time)
{
    int rc = 0, ret;
    urpc_queue_status_t status;
    if (ctx->queue_handles == nullptr) {
        return rc;
    }
    if ((ctx->ctx_flag & CTX_FLAG_QUEUE_CREATE) != 0) {
        for (uint32_t i = 0; i < ctx->queue_num; i++) {
            if (ctx->queue_handles[i] == 0) {
                TEST_LOG_WARN("queue %d is null\n", i);
                continue;
            }
            ret = test_destroy_one_queue(ctx->queue_handles[i], wait_time);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("test_destroy_one_queue ctx->queue_handles[%d] %lu ret=%d\n", i, ctx->queue_handles[i], ret);
            }
            rc += ret;
        }
        
    }
    if (rc == 0) {
        ctx->ctx_flag &= ~CTX_FLAG_QUEUE_CREATE;
        CHECK_FREE(ctx->queue_handles);
    }
    return rc;
}

int test_channel_destroy(test_urpc_ctx_t *ctx, uint32_t channel_id)
{
    int rc = 0, ret;
    if (ctx->channel_ids == nullptr) {
        return rc;
    }
    if (channel_id == URPC_U32_FAIL) {
        if ((ctx->ctx_flag & CTX_FLAG_CHANNEL_CREATE) != 0) {
            for (uint32_t i = 0; i < ctx->channel_num; i++) {
                ret = urpc_channel_destroy(ctx->channel_ids[i]);
                if (ret != TEST_SUCCESS) {
                    TEST_LOG_ERROR("urpc_channel_destroy ctx->channel_ids[%d] %lu ret=%d\n", i, ctx->channel_ids[i], ret);
                }
                rc += ret;
            }
            if (rc == 0) {
                ctx->ctx_flag &=~CTX_FLAG_CHANNEL_CREATE;
                CHECK_FREE(ctx->channel_ids);
                CHECK_FREE(ctx->channel_ops);
            }
            
        }
    } else {
        ret = urpc_channel_destroy(channel_id);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_channel_destroy channel_id=%lu ret=%d\n", channel_id, ret);
            return TEST_FAILED;
        }
    }
    return rc;
}

void test_log_file_close(log_file_info_t **log_file_info)
{
    if (*log_file_info == nullptr) {
        return;
    }
    if (*log_file_info && (*log_file_info)->inited) {
        (void)fclose((*log_file_info)->fd);
        (*log_file_info)->fd = nullptr;
    }
    if (*log_file_info) {
        free(*log_file_info);
        *log_file_info = nullptr;
    }
}

unsigned int test_client_psk_cb_func(void *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len)
{
    if ((strnlen(DEFAULT_SSL_PSK_ID, max_identity_len) == max_identity_len) || (strnlen(DEFAULT_SSL_PSK_KEY, max_psk_len) == max_psk_len)) {
        TEST_LOG_ERROR("psk id or psk key buffer is not sufficient\n");
        return 0;
    }
    (void *)strcpy(identity, DEFAULT_SSL_PSK_ID);
    (void *)memcpy(psk, DEFAULT_SSL_PSK_KEY, strlen(DEFAULT_SSL_PSK_KEY));
    return strnlen(DEFAULT_SSL_PSK_KEY, max_psk_len);
}

unsigned int test_server_psk_cb_func(void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
    if (strcmp(DEFAULT_SSL_PSK_ID, identity) != 0) {
        TEST_LOG_ERROR("unknown client's psk id\n");
        return 0;
    }
    if (strnlen(DEFAULT_SSL_PSK_KEY, max_psk_len) == max_psk_len) {
        TEST_LOG_ERROR("no enough buffer to copy psk key\n");
        return 0;
    }
    (void *)memcpy(psk, DEFAULT_SSL_PSK_KEY, strlen(DEFAULT_SSL_PSK_KEY));

    return strnlen(DEFAULT_SSL_PSK_KEY, max_psk_len);
}

int test_ssl_config_set(test_urpc_ctx_t *ctx)
{
    int ret;
    ret = urpc_ssl_config_set(&ctx->ssl_cfg);
    TEST_LOG_DEBUG("urpc_ssl_config_set ret=%d\n", ret);
    return ret;
}

int test_server_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time)
{
    int ret = 0;
    ret += test_func_unregister(ctx);

    ret += test_queue_destroy(ctx, wait_time);

    ret += test_allocator_unregister(ctx);
    test_urpc_uninit(ctx);
    test_qserver_stop(ctx);
    CHECK_FREE(ctx->server_info);
    CHECK_FREE(ctx->host_info);
    return ret;
}

int test_client_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time)
{
    int ret =0;

    test_mem_seg_remote_access_disable(ctx);
    ret += test_normal_queue_unpair(ctx);
    ret += test_rm_local_queue(ctx);
    ret += test_rm_remote_queue(ctx);
    ret += test_server_detach(ctx);

    ret += test_queue_destroy(ctx, wait_time);
    ret += test_channel_destroy(ctx);
    ret += test_allocator_unregister(ctx);
    test_urpc_uninit(ctx);
    CHECK_FREE(ctx->server_info);
    CHECK_FREE(ctx->host_info);
    return ret;
}

int test_server_client_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time)
{
    int ret =0;

    ret += test_func_unregister(ctx);
    test_mem_seg_remote_access_disable(ctx);
    ret += test_normal_queue_unpair(ctx);
    ret += test_rm_local_queue(ctx);
    ret += test_rm_remote_queue(ctx);
    ret += test_server_detach(ctx);

    ret += test_queue_destroy(ctx, wait_time);
    ret += test_channel_destroy(ctx);
    ret += test_allocator_unregister(ctx);
    test_urpc_uninit(ctx);
    CHECK_FREE(ctx->server_info);
    test_log_file_close(&g_test_log_file);
    return ret;
}

void test_queue_fd_close(test_urpc_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->queue_num; i++) {
        if ( ctx->queue_ops.is_epoll && ctx->queue_ops.is_polling[i] == false) {
            epoll_ctl(ctx->queue_ops.epoll_fd, EPOLL_CTL_DEL, ctx->queue_ops.queue_fd[i], NULL);
            (void)close(ctx->queue_ops.queue_fd[i]);
        }
    }
    if (ctx->queue_ops.is_epoll) {
        (void)close(ctx->queue_ops.epoll_fd);
        CHECK_FREE(ctx->queue_ops.queue_fd);
    }
}

int test_urpc_ctx_uninit(test_urpc_ctx_t *ctx, uint32_t wait_time)
{
    int ret = 0;
    if (ctx->instance_role == URPC_ROLE_CLIENT) {
        ret = test_client_ctx_uninit(ctx, wait_time);
    }
    sync_time("------------------------------");
    if (ctx->instance_role == URPC_ROLE_SERVER) {
        ret = test_server_ctx_uninit(ctx, wait_time);
    }
    CHECK_FREE(ctx->channel_ids);
    CHECK_FREE(ctx->queue_handles);
    CHECK_FREE(ctx->queue_cfg);
    CHECK_FREE(ctx->server_info);
    CHECK_FREE(ctx->host_info);
    CHECK_FREE(ctx->urpc_cp_config);
    test_log_file_close(&g_test_log_file);
    test_queue_fd_close(ctx);
    destroy_test_ctx(g_test_urpc_ctx.ctx);
    return ret;
}

int test_channel_queue_add_attach(test_urpc_ctx_t *ctx)
{
    int ret;
    ret = test_mem_seg_remote_access_enable(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_enable", EXIT);
    ret = test_server_attach(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_attach", EXIT);
    ret = test_add_local_queue(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_local_queue", EXIT);
    ret = test_add_remote_queue(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_remote_queue", EXIT);
    ret = test_normal_queue_pair(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_pair", EXIT);
EXIT:
    return ret;
}

int test_server_prepare(test_urpc_ctx_t *ctx, urpc_config_t *cfg, urpc_queue_trans_mode_t queue_trans_mode)
{
    int ret;

    ret = test_server_init(ctx, cfg);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_init", EXIT);
    ret = test_urpc_ctrl_msg_cb_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_ctrl_msg_cb_register", EXIT);
    ret = test_allocator_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
    ret = test_queue_create(ctx, queue_trans_mode);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);
    ret = test_func_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_register", EXIT);
    ret = test_ssl_config_set(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_ssl_config_set", EXIT);
    ret = test_server_start(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_start", EXIT);
EXIT:
    return ret;
}

int test_client_prepare(test_urpc_ctx_t *ctx, urpc_config_t *cfg, urpc_queue_trans_mode_t queue_trans_mode)
{
    int ret;
    ret = test_client_init(ctx, cfg);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_client_init", EXIT);
    ret = test_urpc_ctrl_msg_cb_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_ctrl_msg_cb_register", EXIT);
    ret = test_allocator_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
    ret = test_queue_create(ctx, queue_trans_mode);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);
    ret = test_channel_create(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_create", EXIT);
    ret = test_ssl_config_set(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_ssl_config_set", EXIT);
    ret = test_mem_seg_remote_access_enable(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_mem_seg_remote_access_enable", EXIT);
    ret = test_server_attach(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_attach", EXIT);
    ret = test_add_local_queue(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_local_queue", EXIT);
    ret = test_add_remote_queue(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_add_remote_queue", EXIT);
    ret =test_normal_queue_pair(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_normal_queue_pair", EXIT);
EXIT:
    return ret;
}

int test_server_client_prepare(test_urpc_ctx_t * ctx, urpc_config_t *cfg, urpc_queue_trans_mode_t queue_trans_mode)
{
    int ret;
    ret = test_server_client_init(ctx, cfg);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_client_init", EXIT);
    ret = test_urpc_ctrl_msg_cb_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_urpc_ctrl_msg_cb_register", EXIT);
    ret = test_allocator_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_allocator_register", EXIT);
    ret = test_queue_create(ctx, queue_trans_mode);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_queue_create", EXIT);
    ret = test_channel_create(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_channel_create", EXIT);
    ret = test_func_register(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_register", EXIT);
    ret = test_ssl_config_set(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_ssl_config_set", EXIT);
    ret = test_server_start(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_server_start", EXIT);
EXIT:
    return ret;
}

const char *parse_poll_event(uint32_t event)
{
    if (event == 0) {
        return "POLL_EVENT_REQ_ACKED";
    } else if (event == 1) {
        return "POLL_EVENT_REQ_RSPED";
    } else if (event == 2) {
        return "POLL_EVENT_REQ_ACKED_RSPED";
    } else if (event == 3) {
        return "POLL_EVENT_REQ_ERR";
    } else if (event == 4) {
        return "POLL_EVENT_REQ_RECVED";
    } else if (event == 5) {
        return "POLL_EVENT_REQ_SENDED";
    } else if (event == 6) {
        return "POLL_EVENT_RSP_SENDED";
    } else if (event == 7) {
        return "POLL_EVENT_RSP_ERR";
    } else if (event == 8) {
        return "POLL_EVENT_READ_RET";
    } else if (event == 9) {
        return "POLL_EVENT_EXT";
    } else if (event == 10) {
        return "POLL_EVENT_ERR";
    } else {
        return "POLL_EVENT_MAX";
    }
}

void handle_poll_event_read_ret_custom(urpc_poll_msg_t *msg, uint64_t qh)
{
    ref_read_idx_t *read_idx = (ref_read_idx_t *)msg->ref_read_result.user_ctx;
    if (read_idx == nullptr) {
        g_test_allocator.put_raw_buf(msg->ref_read_result.l_sges, NULL);
        CHECK_FREE(msg->ref_read_result.l_sges);
        return;
        
    }
    read_idx->dma_idx++;
    TEST_LOG_INFO("(read client data) ret %u, dma_cnt %u , idx %u\n", msg->ref_read_result.ret_code, read_idx->dma_cnt, read_idx->dma_idx);
    if (msg->ref_read_result.l_sges != 0) {
        TEST_LOG_INFO("(read client data) %s ret %u\n", (char *)(uintptr_t)msg->ref_read_result.l_sges[0].addr);
    }
    if (read_idx->dma_cnt == read_idx->dma_idx) {
        urpc_return_wr_t wr;
        urpc_return_option_t option = {0};
        int ret = urpc_func_exec(read_idx->func_id, read_idx->req_sges[0], 1, &wr.rsps, &wr.rsps_sge_num);
        if (ret == URPC_SUCCESS) {
            urpc_func_return(qh, read_idx->req_ctx, &wr, &option);
        }
        
        for (uint32_t i = 0; i < read_idx->dma_idx; i++) {
            g_test_allocator.put_raw_buf(read_idx->req_sges[i], NULL);
            CHECK_FREE(read_idx->req_sges[i]);
        }
        CHECK_FREE(read_idx);
    } else {
        TEST_LOG_INFO("read_idx->dma_cnt != read_idx->dma_idx\n");
    }

}

static uint32_t get_sges_total_size(urpc_sge_t *sge, uint32_t sge_num)
{
    uint32_t total_size = 0;
    for (uint32_t i = 0; i < sge_num; i++) {
        TEST_LOG_DEBUG(">>>>> sge[%u].length=%u, addr=%p\n", i, sge[i].length, sge[i].addr);
        total_size += sge[i].length;
    }
    return total_size;
}

static void handle_poll_event_normal_req_recved(urpc_poll_msg_t *msg, uint64_t queue_handle, uint32_t *hit_events)
{
    urpc_sge_t *sge= msg->req_recved.args;
    custom_head_t *custom_head = (custom_head_t *)(uintptr_t)(sge->addr + urpc_hdr_size_get(URPC_REQ, 0));
    if (custom_head->msg_type == WITH_DMA) {
        TEST_LOG_INFO("### read WITH_DMA\n");
        urpc_ref_option_t option = {.option_flag = FUNC_REF_FLAG_USER_CTX,};
        ref_read_idx_t *read_idx = (ref_read_idx_t *)malloc(sizeof(ref_read_idx_t) + custom_head->dma_num * sizeof(uint64_t));
        if (read_idx == NULL) {
            return;
        }
        option.user_ctx = read_idx;
        read_idx->dma_cnt = 0;
        read_idx->dma_idx = 0;
        read_idx->req_ctx = msg->req_recved.req_ctx;
        read_idx->func_id = msg->req_recved.func_id;

        urpc_ref_sge_t r_ref_sge;
        urpc_ref_wr_t ref_wr = {.l_sges_num = 1, .r_ref_sges = &r_ref_sge, .r_ref_sges_num = 1};

        test_custom_read_dma_t *dma = (test_custom_read_dma_t *)(custom_head + 1);
        TEST_LOG_INFO("### read WITH_DMA custom_head->dma_num %u\n", custom_head->dma_num);
        for (uint32_t j = 0; j < custom_head->dma_num; j ++) {
            TEST_LOG_INFO("### read WITH_DMA dma_ %u\n", j);
            r_ref_sge.addr = dma->address;
            r_ref_sge.length = dma->size;
            r_ref_sge.token_id = dma->token_id;
            r_ref_sge.token_value = dma->token_value;
            g_test_allocator.get_sges(&ref_wr.l_sges, 1, NULL);
            g_test_allocator.get_raw_buf(ref_wr.l_sges, dma->size, NULL);
            if (urpc_ref_read(queue_handle, msg->req_recved.req_ctx, &ref_wr, &option) != URPC_SUCCESS) {
                g_test_allocator.put_raw_buf(ref_wr.l_sges, NULL);
                g_test_allocator.put_sges(ref_wr.l_sges, NULL);
                if (read_idx->dma_cnt == read_idx->dma_idx) {
                    free(read_idx);
                }
                TEST_LOG_INFO("ref read failed\n");
                return;
            }
            read_idx->dma_cnt++;
            read_idx->req_sges[j] = ref_wr.l_sges;
            dma = (dma + 1);
        }
        g_test_allocator.put(msg->req_recved.args, msg->req_recved.args_sge_num, NULL);
        return;
        
    } else {
        TEST_LOG_INFO("### normal WITHOUT_DMA\n");
    }

    urpc_return_wr_t wr;
    urpc_return_option_t option = {0};
    int ret = 0;
    uint64_t func_id = msg->req_recved.func_id;
    uint32_t total_size = get_sges_total_size(msg->req_recved.args, msg->req_recved.args_sge_num);
    TEST_LOG_INFO(">>>>> recv req_size=%lu, sge num=%u\n", total_size, msg->req_recved.args_sge_num);
    ret = urpc_func_exec(func_id, msg->req_recved.args, msg->req_recved.args_sge_num, &wr.rsps, &wr.rsps_sge_num);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("urpc_func_exec failed %d\n", ret);
        (void)urpc_func_return(queue_handle, msg->req_recved.req_ctx, nullptr, nullptr);
        g_test_allocator.put(msg->req_recved.args, msg->req_recved.args_sge_num, nullptr);
        return;
    }
    ret = urpc_func_return(queue_handle, msg->req_recved.req_ctx, &wr, nullptr);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("urpc_func_return failed %d\n", ret);
        g_test_allocator.put(msg->req_recved.args, msg->req_recved.args_sge_num, nullptr);
        return;
    }
    g_test_allocator.put(msg->req_recved.args, msg->req_recved.args_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_REQ_RECVED);
    }
}

void handle_poll_event_req_recved(urpc_poll_msg_t *msg, uint64_t queue_handle, uint32_t *hit_events)
{
    handle_poll_event_normal_req_recved(msg, queue_handle, nullptr);
}

void handle_poll_event_rsp_sended(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    uint32_t total_size = get_sges_total_size(msg->rsp_sended.rsps, msg->rsp_sended.rsps_sge_num);
    TEST_LOG_DEBUG(">>>>> put rsp size=%lu, sge num=%u\n", total_size, msg->rsp_sended.rsps_sge_num);
    g_test_allocator.put(msg->rsp_sended.rsps, msg->rsp_sended.rsps_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_RSP_SENDED);
    }
}

void handle_poll_event_req_acked(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if ((char *)(uintptr_t)msg->req_acked.args == nullptr) {
        TEST_LOG_ERROR("(POLL_EVENT_REQ_ACKED)\n");
        return;
    }
    char *req = nullptr;
    req = (char *)(uintptr_t)msg->req_acked.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
    uint32_t total_size = get_sges_total_size(msg->req_acked.args, msg->req_acked.args_sge_num);
    TEST_LOG_DEBUG("(>>>>> put req size=%lu, sge num=%u\n", total_size, msg->req_acked.args_sge_num);
    g_test_allocator.put(msg->req_acked.args, msg->req_acked.args_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_REQ_ACKED);
    }
    return;
}

void handle_poll_event_req_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if ((char *)(uintptr_t)msg->req_rsped.args == nullptr && (char *)(uintptr_t)msg->req_rsped.rsps == nullptr) {
        TEST_LOG_ERROR("(POLL_EVENT_REQ_RSPED)\n");
        return;
    }
    if ((char *)(uintptr_t)msg->req_rsped.args != nullptr) {
        char *req = nullptr;
        req = (char *)(uintptr_t)msg->req_rsped.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
        uint32_t total_size = get_sges_total_size(msg->req_rsped.args, msg->req_rsped.args_sge_num);
        TEST_LOG_DEBUG("(>>>>> put req size=%lu, sge num=%u\n", total_size, msg->req_rsped.args_sge_num);
        urpc_sge_t *sge = msg->req_recved.args;
        urpc_sge_t sge_one;
        custom_head_t *custom_head = (custom_head_t *)(uintptr_t)(sge->addr + urpc_hdr_size_get(URPC_REQ, 0));
        uint32_t dma_cnt = custom_head->dma_num;
        test_custom_read_dma_t *dma = (test_custom_read_dma_t *)(custom_head + 1);
        if (custom_head->msg_type == WITH_DMA && custom_head->dma_num != 0) {
            if (msg->req_rsped.args_sge_num == 1) {
                for (uint32_t i = 0; i < dma_cnt; i++) {
                    sge_one.addr = dma->address;
                    sge_one.length = dma->size;
                    g_test_allocator.put_raw_buf(&sge_one, NULL);
                    dma = (dma + 1);
                }
            } else {
                for (uint32_t i = 0; i < dma_cnt; i++) {
                    sge_one.addr = dma->address;
                    sge_one.length = dma->size;
                    g_test_allocator.put_raw_buf(&sge_one, NULL);
                    dma = (dma + 1);
                    if (i == MAX_DMC_CNT - 1) {
                        dma = (test_custom_read_dma_t *)sge[1].addr;
                    }
                }
            }
        }
        g_test_allocator.put(msg->req_rsped.args, msg->req_rsped.args_sge_num, nullptr);
    }

    if ((char *)(uintptr_t)msg->req_rsped.rsps != nullptr) {
        char *rsp = nullptr;
        rsp = (char *)(uintptr_t)msg->req_rsped.rsps->addr + urpc_hdr_size_get(URPC_RSP, 0);
        uint32_t total_size = get_sges_total_size(msg->req_rsped.rsps, msg->req_rsped.rsps_sge_num);
        TEST_LOG_DEBUG("(>>>>> put rsp size=%lu, sge num=%u\n", total_size, msg->req_rsped.rsps_sge_num);
        g_test_allocator.put(msg->req_rsped.rsps, msg->req_rsped.rsps_sge_num, nullptr);
    }
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_REQ_RSPED);
    }
    return;
}

void handle_poll_event_req_acked_rsped(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if ((char *)(uintptr_t)msg->req_acked_rsped.args == nullptr && (char *)(uintptr_t)msg->req_acked_rsped.rsps == nullptr) {
        TEST_LOG_ERROR("(POLL_EVENT_REQ_ACKED_RSPED)\n");
        return;
    }
    if ((char *)(uintptr_t)msg->req_acked_rsped.args != nullptr) {
        char *req = nullptr;
        req = (char *)(uintptr_t)msg->req_acked_rsped.args->addr + urpc_hdr_size_get(URPC_REQ, 0);
        uint32_t total_size = get_sges_total_size(msg->req_acked_rsped.args, msg->req_acked_rsped.args_sge_num);
        TEST_LOG_DEBUG("(>>>>> put req size=%lu sge num=%u\n", total_size, msg->req_acked_rsped.args_sge_num);
        g_test_allocator.put(msg->req_acked_rsped.args, msg->req_acked_rsped.args_sge_num, nullptr);
    }
    if ((char *)(uintptr_t)msg->req_acked_rsped.rsps != nullptr) {
        char *rsp = nullptr;
        rsp = (char *)(uintptr_t)msg->req_acked_rsped.rsps->addr + urpc_hdr_size_get(URPC_RSP, 0);
        uint32_t total_size = get_sges_total_size(msg->req_acked_rsped.rsps, msg->req_acked_rsped.rsps_sge_num);
        TEST_LOG_DEBUG("(>>>>> put rsp size=%lu, sge num=%u\n", total_size, msg->req_acked_rsped.rsps_sge_num);
        g_test_allocator.put(msg->req_acked_rsped.rsps, msg->req_acked_rsped.rsps_sge_num, nullptr);
    }
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_REQ_ACKED_RSPED);
    }
    return;
}

void handle_poll_event_rsp_err(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    TEST_LOG_ERROR("(POLL_EVENT_RSP_ERR) err_code is %u\n", msg->rsp_err.err_code);
    uint32_t total_size = get_sges_total_size(msg->rsp_err.rsps, msg->rsp_err.rsps_sge_num);
    TEST_LOG_DEBUG(">>>>> put rsp size=%lu, sge num=%u\n", total_size, msg->rsp_err.rsps_sge_num);
    g_test_allocator.put(msg->rsp_err.rsps, msg->rsp_err.rsps_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_RSP_ERR);
    }
    return;
}

void handle_poll_event_req_err(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    TEST_LOG_WARN("(POLL_EVENT_REQ_ERR), err_code is %u\n", msg->req_err.err_code);
    uint32_t total_size = get_sges_total_size(msg->req_err.args, msg->req_err.args_sge_num);
    TEST_LOG_DEBUG(">>>>> put req size=%lu, sge num=%u\n", total_size, msg->req_err.args_sge_num);
    g_test_allocator.put(msg->req_err.args, msg->req_err.args_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_REQ_ERR);
    }
    return;
}

void handle_poll_event_err(urpc_poll_msg_t *msg, uint32_t *hit_events)
{
    if (msg->event_err.err_code != 0) {
        TEST_LOG_WARN("(POLL_EVENT_ERR), err_code is %u\n", msg->event_err.err_code);
    }
    g_test_allocator.put(msg->event_err.args, msg->event_err.args_sge_num, nullptr);
    if (hit_events != nullptr) {
        *hit_events -= (1 << POLL_EVENT_ERR);
    }
    return;
}

int test_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint64_t queue_handle, uint32_t *hit_events, bool do_rx_post)
{
    for (int i = 0; i < poll_num; i++) {
        if (msgs[i].event == POLL_EVENT_REQ_RECVED || msgs[i].event == POLL_EVENT_REQ_RSPED || msgs[i].event == POLL_EVENT_RSP_ERR || 
        msgs[i].event == POLL_EVENT_ERR || msgs[i].event == POLL_EVENT_REQ_ERR) {
            if (do_rx_post) {
                (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            }
        }
        if (msgs[i].event == POLL_EVENT_REQ_RECVED) {
            handle_poll_event_req_recved(&msgs[i], queue_handle, nullptr);
        } else if (msgs[i].event == POLL_EVENT_READ_RET) {
            handle_poll_event_read_ret_custom(&msgs[i], queue_handle);
        } else if (msgs[i].event == POLL_EVENT_RSP_SENDED) {
            handle_poll_event_rsp_sended(&msgs[i], nullptr);
        } else if (msgs[i].event == POLL_EVENT_REQ_ACKED) {
            handle_poll_event_req_acked(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_RSPED) {
            handle_poll_event_req_rsped(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_ACKED_RSPED) {
            handle_poll_event_req_acked_rsped(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_RSP_ERR) {
            handle_poll_event_rsp_err(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_ERR) {
            handle_poll_event_req_err(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_ERR) {
            handle_poll_event_err(&msgs[i], hit_events);
        } else {
            TEST_LOG_ERROR("other event:%s\n", parse_poll_event(msgs[i].event));
        }
    }
    return poll_num;
}

uint32_t test_func_poll_one_queue(urpc_poll_option_t *option, urpc_poll_msg_t *msg, int num, bool do_rx_post)
{
    uint32_t polled_num = 0;
    int poll_num = urpc_func_poll(URPC_U32_FAIL, option, msg, num);
    if (poll_num < 0) {
        TEST_LOG_ERROR("poll error, error: %d\n", poll_num);
    }
    if (poll_num > 0) {
        test_handle_poll_event(msg, poll_num, option->urpc_qh, nullptr, do_rx_post);
        polled_num++;
    }
    return polled_num;
}

uint32_t test_poll_one_queue_event(uint64_t queue_handle, uint32_t wait_time, uint32_t expect_nums, bool do_rx_post)
{
    uint32_t polled_num = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t start_time = ts.tv_sec;
    time_t current_time = start_time;
    while (current_time - start_time < wait_time) {
        usleep(1);
        urpc_poll_msg_t msg = {};
        urpc_poll_option_t option = {0};
        option.urpc_qh = queue_handle;
        polled_num += test_func_poll_one_queue(&option, &msg, 1, do_rx_post);
        if (expect_nums != 0 && polled_num >= expect_nums) {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        current_time = ts.tv_sec;
    }
    return polled_num;
}

void test_func_poll_all_queue(poll_thread_args_t *poll_args)
{
    int poll_num;
    urpc_poll_msg_t msg = {};
    urpc_poll_option_t option = {0};
    for (uint32_t i = 0; i < g_test_urpc_ctx.queue_num; i++) {
        memset(&msg, 0, sizeof(urpc_poll_msg_t));
        memset(&option, 0, sizeof(urpc_poll_option_t));
        if (g_test_urpc_ctx.queue_handles[i] == 0) {
            continue;
        }
        option.poll_direction = poll_args->direction;
        option.urpc_qh = g_test_urpc_ctx.queue_handles[i];
        test_func_poll_one_queue(&option, &msg, 1, poll_args->do_rx_post);
    }
}

static void *test_poll_event_thread(void *args)
{
    int poll_num;
    urpc_poll_msg_t msg = {};
    urpc_poll_option_t option = {0};
    poll_thread_args_t *thread_args = (poll_thread_args_t *)args;
    while (g_test_poll_status) {
        usleep(500);
        test_func_poll_all_queue(thread_args);
    }
    return nullptr;
}

int start_poll_event_thread(int thread_num, poll_thread_args_t pargs[])
{
    int ret, success_num = 0;
    g_test_poll_status = true;
    for (uint32_t i = 0; i < thread_num; i++) {
        pargs[i].tid = i;
        ret = pthread_create(&pargs[i].thread, nullptr, test_poll_event_thread, (void *)&pargs[i]);
        CHKERR_JUMP(ret != TEST_SUCCESS, "pthread_create", EXIT);
        success_num++;
        char thread_name[THREAD_NAME_MAX_LEN];
        ret = snprintf(thread_name, THREAD_NAME_MAX_LEN, "%s-%u", "poll", i);
        CHKERR_JUMP(ret < TEST_SUCCESS, "snprintf thread_name", EXIT);
        ret = pthread_setname_np(pargs[i].thread, thread_name);
        CHKERR_JUMP(ret != TEST_SUCCESS, "pthread_setname_np", EXIT);
    }
    return TEST_SUCCESS;
EXIT:
    for (uint32_t i = 0; i < success_num; i++) {
        (void)pthread_join(pargs[i].thread, nullptr);
    }
    return TEST_FAILED;
}

void stop_poll_event_thread(int thread_num, poll_thread_args_t pargs[], uint32_t wait_time)
{
    if (g_test_poll_status) {
        sleep(wait_time);
        g_test_poll_status = false;
        for (uint32_t i = 0; i < thread_num; i++) {
            (void)pthread_join(pargs[i].thread, nullptr);
        }
    }
}

void server_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint64_t queue_handle)
{
    if (msgs == nullptr || poll_num > 2 || queue_handle == URPC_INVALID_HANDLE) {
        return;
    }
    for (int i = 0; i < poll_num; i++) {
        TEST_LOG_INFO("server poll----------------------------------------\n");
        TEST_LOG_INFO("msg.event %s\n", parse_poll_event(msgs[i].event));
        if (msgs[i].event == POLL_EVENT_REQ_RECVED) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_req_recved(&msgs[i], queue_handle, nullptr);
        } else if (msgs[i].event == POLL_EVENT_READ_RET) {
            handle_poll_event_read_ret_custom(&msgs[i], queue_handle);
        } else if (msgs[i].event == POLL_EVENT_RSP_SENDED) {
            handle_poll_event_rsp_sended(&msgs[i], nullptr);
        } else if (msgs[i].event == POLL_EVENT_RSP_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_rsp_err(&msgs[i], nullptr);
        } else if (msgs[i].event == POLL_EVENT_REQ_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_req_err(&msgs[i], nullptr);
        } else if (msgs[i].event == POLL_EVENT_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_err(&msgs[i], nullptr);
        } else {
            TEST_LOG_ERROR("other event:%s\n", parse_poll_event(msgs[i].event));
        }
    }
}

static void *test_server_run_response_thread(void *p)
{
    urpc_queue_status_t status;
    server_thread_arg_t *server_arg = (server_thread_arg_t *)p;
    urpc_poll_msg_t msg = {};
    memset(&msg, 0, sizeof(urpc_poll_msg_t));
    urpc_poll_option_t poll_opt = {0};
    uint64_t expect_poll_num = server_arg->func_args.expect_poll_num;
    uint64_t real_poll_num = 0;
    while (!g_server_exit) {
        if (g_test_urpc_ctx.queue_ops.is_epoll) {
            struct epoll_event epoll_events[1];
            int ret = epoll_wait(g_test_urpc_ctx.queue_ops.epoll_fd, epoll_events, 1, g_test_urpc_ctx.queue_ops.epoll_timeout);
        }
        for (uint32_t i = 0; i < g_test_urpc_ctx.queue_num; i++) {
            if (g_test_urpc_ctx.queue_handles[i] == 0) {
                continue;
            }
            poll_opt.urpc_qh = g_test_urpc_ctx.queue_handles[i];
            if (server_arg->func_args.poll_cb != nullptr) {
                server_arg->func_args.poll_cb();
            }
            int poll_num = urpc_func_poll(URPC_U32_FAIL, &poll_opt, &msg, 1);
            if (poll_num < 0) {
                TEST_LOG_ERROR("poll error, error: %d\n", poll_num);
                server_arg->ret += 1;
            }
            if (poll_num > 0) {
                real_poll_num += poll_num;
                if (g_test_all_queue_ready) {
                    server_handle_poll_event(&msg, poll_num, poll_opt.urpc_qh);
                } else {
                    for (uint32_t k = 0; k < g_test_urpc_ctx.queue_num; k++) {
                        urpc_queue_status_query(g_test_urpc_ctx.queue_handles[k], &status);
                        if (status == QUEUE_STATUS_READY) {
                            server_handle_poll_event(&msg, poll_num, g_test_urpc_ctx.queue_handles[k]);
                            break;
                        }
                    }
                }
                
            }
        }
    }
    TEST_LOG_INFO("real_poll_num: %lu\n", real_poll_num);
    if (expect_poll_num != 0) {
        TEST_LOG_INFO("expect_poll_num: %lu\n", expect_poll_num);
        if (real_poll_num != expect_poll_num) {
            server_arg->ret += 1;
        }
    }
    return nullptr;
}

void set_server_exit_status(bool status)
{
    TEST_LOG_INFO("set_server_exit_status status:%d\n", status);
    g_server_exit = status;
}

int start_server_poll_thread(int thread_num, server_thread_arg_t targ[]) {
    int ret = 0;
    set_server_exit_status(false);
    for (int i = 0; i < thread_num; i++) {
        ret += pthread_create(&targ[i].thread, nullptr, test_server_run_response_thread, (void *)&targ[i]);
    }
    return ret;
}

int stop_server_poll_thread(int thread_num, server_thread_arg_t targ[])
{
    int ret = 0;
    set_server_exit_status(true);
    for (int i = 0; i < thread_num; i++) {
        pthread_join(targ[i].thread, nullptr);
        ret += (targ[i].ret != 0);
    }
    return ret;
}

static void set_poll_direction_truns(test_func_args_t *func_args, urpc_poll_option_t *option, urpc_poll_direction_t *next_direction, uint64_t queue_handle)
{
    if (func_args->poll_tx_qh != 0 && *next_direction == POLL_DIRECTION_TX) {
        option->poll_direction = POLL_DIRECTION_TX;
        option->urpc_qh = func_args->poll_tx_qh;
        *next_direction = POLL_DIRECTION_RX;
        return;
    }
    if (func_args->poll_rx_qh != 0 && *next_direction == POLL_DIRECTION_RX) {
        option->poll_direction = POLL_DIRECTION_RX;
        option->urpc_qh = (queue_handle != 0) ? queue_handle : func_args->poll_rx_qh;
        *next_direction = POLL_DIRECTION_TX;
        return;
    } 
}

int test_server_run_response(test_func_args_t *func_args)
{
    urpc_poll_msg_t msg = {};
    memset(&msg, 0, sizeof(urpc_poll_msg_t));
    urpc_poll_option_t poll_opt = {0};
    uint64_t real_poll_num = 0;
    uint64_t timeout = func_args->timeout ? func_args->timeout : SERVER_POLL_TIMEOUT;
    struct timespec ts;
    uint64_t poll_queue_handle = 0;
    if (func_args->poll_opt.urpc_qh != 0) {
        poll_queue_handle = func_args->poll_opt.urpc_qh;
    }
    urpc_poll_direction_t next_direction = POLL_DIRECTION_TX;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t start_time = ts.tv_sec;
    time_t current_time = start_time;
    while (current_time - start_time < timeout) {
        for (uint32_t i = 0; i <g_test_urpc_ctx.queue_num; i++) {
            if (g_test_urpc_ctx.queue_handles[i] == 0) {
                continue;
            }
            if (func_args->poll_cb != nullptr) {
                func_args->poll_cb();
            }
            poll_opt.urpc_qh = (poll_queue_handle == 0) ? g_test_urpc_ctx.queue_handles[i] : poll_queue_handle;

            set_poll_direction_truns(func_args, &poll_opt, &next_direction, g_test_urpc_ctx.queue_handles[i]);
            int poll_num = urpc_func_poll(URPC_U32_FAIL, &poll_opt, &msg, 1);
            if (poll_num < 0) {
                TEST_LOG_ERROR("poll error, error: %d\n", poll_num);
                return TEST_FAILED;
            }
            if (poll_num > 0) {
                real_poll_num += poll_num;
                server_handle_poll_event(&msg, poll_num, poll_opt.urpc_qh);
            }

        }
        if (real_poll_num >= func_args->expect_poll_num) {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        current_time = ts.tv_sec;
    }
    TEST_LOG_INFO("urpc queue expect_poll_num: %d, real_poll_num: %d\n", func_args->expect_poll_num, real_poll_num);
    if (real_poll_num < func_args->expect_poll_num) {
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
    
}

uint32_t client_handle_poll_event(urpc_poll_msg_t *msgs, int poll_num, uint32_t *hit_events, uint64_t queue_handle)
{
    for (int i = 0; i < poll_num; i++) {
        TEST_LOG_INFO("client poll------------------------------------------\n");
        TEST_LOG_INFO("msgs[%d].event: %s\n", i, parse_poll_event(msgs[i].event));
        if (msgs[i].event == POLL_EVENT_REQ_ACKED) {
            handle_poll_event_req_acked(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_RSPED) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_req_rsped(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_ACKED_RSPED) {
            handle_poll_event_req_acked_rsped(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_REQ_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_req_err(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_err(&msgs[i], hit_events);
        } else if (msgs[i].event == POLL_EVENT_RSP_ERR) {
            (void)test_urpc_queue_rx_post(nullptr, 1, queue_handle);
            handle_poll_event_rsp_err(&msgs[i], hit_events);
        } else {
            TEST_LOG_ERROR("other event:%s\n", parse_poll_event(msgs[i].event));
        }
    }
    return poll_num;
}

int test_client_process_event(test_func_args_t *func_args)
{
    bool check_event_ok = false;
    urpc_poll_msg_t *msgs = (urpc_poll_msg_t *)calloc((int)func_args->expect_poll_num, sizeof(urpc_poll_msg_t));
    if (msgs == nullptr) {
        TEST_LOG_ERROR("msgs calloc failed\n");
        return TEST_FAILED;
    }
    urpc_poll_option_t poll_opt = {0};
    if (func_args->lqueue_handle != 0) {
        poll_opt.urpc_qh = func_args->lqueue_handle;
    }
    if (func_args->poll_opt.poll_direction != 0) {
        poll_opt.poll_direction = func_args->poll_opt.poll_direction;
    }
    uint64_t poll_timeout = func_args->poll_timeout ? func_args->poll_timeout : CLINET_POLL_TIMEOUT;
    urpc_poll_direction_t next_direction = POLL_DIRECTION_TX;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t start_time = ts.tv_sec;
    time_t current_time = start_time;
    while (func_args->expect_poll_num != 0) {
        if (g_test_urpc_ctx.queue_ops.is_epoll) {
            struct epoll_event epoll_events[1];
            int ret = epoll_wait(g_test_urpc_ctx.queue_ops.epoll_fd, epoll_events, 1, g_test_urpc_ctx.queue_ops.epoll_timeout);
            if (ret > 0) {
                TEST_LOG_INFO("[epoll get event: %d]\n", ret);
            }
        }
        set_poll_direction_truns(func_args, &poll_opt, &next_direction);
        int poll_num = urpc_func_poll(func_args->channel_id, &poll_opt, msgs, (int)func_args->expect_poll_num);
        if (poll_num < 0) {
            TEST_LOG_ERROR("poll error, error: %d\n", poll_num);
            CHECK_FREE(msgs);
            return TEST_FAILED;
        } else if (poll_num > 0) {
            TEST_LOG_INFO("poll event, poll_num: %d\n", poll_num);
            if (func_args->expect_hit_events == 0) {
                CHECK_FREE(msgs);
                return TEST_SUCCESS;
            }
            func_args->expect_poll_num -= client_handle_poll_event(msgs, poll_num, &func_args->expect_hit_events, poll_opt.urpc_qh);
        }
        
        if (func_args->data_type == RSP_ACK_SEND_PUSH_WITHOUT_PLOG) {
            if (func_args->expect_hit_events == (1 << POLL_EVENT_REQ_ACKED)) {
                check_event_ok = true;
                break;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &ts);
        current_time = ts.tv_sec;
        if (current_time - start_time >= poll_timeout) {
            TEST_LOG_WARN("client poll timeout %lu[s]\n", poll_timeout);
            break;
        }
    }
    TEST_LOG_INFO("expect_hit_events:%u\n", func_args->expect_hit_events);
    CHECK_FREE(msgs);
    if (func_args->expect_hit_events != 0 && !check_event_ok) {
        TEST_LOG_ERROR("check hit_events %u failed\n", func_args->expect_hit_events);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

void set_call_option_queue_handle(test_func_args_t *func_args, urpc_call_option_t *option)
{
    if (func_args->lqueue_handle != 0) {
        option->option_flag |= FUNC_CALL_FLAG_L_QH;
        option->l_qh = func_args->lqueue_handle;
    }
    if (func_args->rqueue_handle != 0) {
        option->option_flag |= FUNC_CALL_FLAG_R_QH;
        option->r_qh = func_args->rqueue_handle;
    }
}

void set_call_option_flag_rsp(urpc_call_option_t *option)
{
    option->option_flag |= FUNC_CALL_FLAG_FUNC_DEFINED;
    option->call_mode = 0;
}

void set_call_option_flag_no_ack_rsp(urpc_call_option_t *option)
{
    option->option_flag |= FUNC_CALL_FLAG_CALL_MODE;
    option->call_mode = FUNC_CALL_MODE_EARLY_RSP;
}

void set_func_args_hit_events_rsp(test_func_args_t *func_args)
{
    func_args->expect_poll_num = (func_args->expect_poll_num == 0) ? 1 : func_args->expect_poll_num;
    func_args->expect_hit_events = (func_args->expect_hit_events == 0) ? (1 << POLL_EVENT_REQ_RSPED) : func_args->expect_hit_events;
}

void set_func_args_hit_events_no_ack_rsp(test_func_args_t *func_args)
{
    func_args->expect_poll_num = (func_args->expect_poll_num == 0) ? 2 : func_args->expect_poll_num;
    func_args->expect_hit_events = (func_args->expect_hit_events == 0) ? (1 << POLL_EVENT_REQ_RSPED) | (1 << POLL_EVENT_RSP_ERR) : func_args->expect_hit_events;
    TEST_LOG_INFO(">>>>> set_func_args_hit_events_no_ack_rsp func_args->expect_hit_events=%d\n", func_args->expect_hit_events);
}

int test_client_process_normal_call(test_func_args_t *func_args)
{
    urpc_call_wr_t wr = {.func_id = func_args->func_id};
    g_test_urpc_ctx.req_size = (g_test_urpc_ctx.req_size == 0) ? g_test_urpc_ctx.allocator_config.block_size : g_test_urpc_ctx.req_size;
    int ret = g_test_allocator.get(&wr.args, (uint32_t *)&wr.args_num, g_test_urpc_ctx.req_size, nullptr);
    TEST_LOG_INFO(">>>>> wr.args=%p\n", wr.args);
    TEST_LOG_INFO(">>>>> req_size=%u, sge num=%u\n", g_test_urpc_ctx.req_size, wr.args_num);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("g_test_allocator.get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        return TEST_FAILED;
    }

    uint32_t urpc_hdr_size = urpc_hdr_size_get(URPC_REQ, 0);
    uint32_t custom_head_size = sizeof(custom_head_t);
    uint32_t hdr_size = urpc_hdr_size + custom_head_size;
    custom_head_t custom_head = {.msg_type = WITHOUT_DMA, .dma_num = 0,};
    memcpy((char *)(uintptr_t)wr.args->addr + urpc_hdr_size, &custom_head, sizeof(custom_head_t));
    (void)sprintf((char *)(uintptr_t)wr.args->addr + hdr_size, "hello server!");
    wr.args[0].length = g_test_urpc_ctx.req_size;
    uint64_t call_ret = urpc_func_call(func_args->channel_id, &wr, &func_args->call_option);
    if (call_ret == URPC_U64_FAIL) {
        func_args->call_errno = errno;
        TEST_LOG_ERROR("urpc_func_call failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        g_test_allocator.put(wr.args, wr.args_num, nullptr);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_client_process_call(test_func_args_t *func_args)
{
    return test_client_process_normal_call(func_args);
}

int test_client_run(test_func_args_t *func_args)
{
    int ret = test_client_process_call(func_args);
    if (ret != TEST_SUCCESS) {
        return TEST_FAILED;
    }

    if (func_args->is_not_poll != true) {
        ret = test_client_process_event(func_args);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_client_process_event failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int test_func_call_recv_rsp_no_ack(test_func_args_t *func_args)
{
    int ret;
    set_call_option_queue_handle(func_args, &func_args->call_option);
    set_call_option_flag_rsp(&func_args->call_option);
    set_func_args_hit_events_rsp(func_args);
    ret = test_client_run(func_args);
    return ret;
}

int test_client_process_normal_call_read(test_func_args_t *func_args)
{
    int ret;
    urpc_call_wr_t wr = {.func_id = func_args->func_id};
    urpc_sge_t sge_one;
    uint64_t call_ret;
    uint32_t dma_cnt = 0;

    urpc_call_option_t option = {.option_flag = FUNC_CALL_FLAG_L_QH, .l_qh = func_args->lqueue_handle};
    option.option_flag |= FUNC_CALL_FLAG_CALL_MODE;
    option.func_defined = FUNC_DEF_NULL;

    uint32_t urpc_hdr_size = urpc_hdr_size_get(URPC_REQ, 0);
    uint32_t custom_head_size = sizeof(custom_head_t);
    uint32_t hdr_size = urpc_hdr_size + custom_head_size;
    ret = g_test_allocator.get(&wr.args, &wr.args_num, g_test_urpc_ctx.allocator_config.block_size, NULL);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("g_test_allocator.get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        return TEST_FAILED;
    }

    uint32_t req_size;
    if (g_test_urpc_ctx.req_size == 0) {
        req_size = g_test_urpc_ctx.allocator_config.block_size;
    } else {
        req_size = g_test_urpc_ctx.req_size;
    }
    TEST_LOG_INFO("get_raw_buf, req_size:%d\n", req_size);
    dma_cnt = req_size / g_test_urpc_ctx.allocator_config.block_size;
    custom_head_t example_head = {.msg_type = WITH_DMA, .dma_num = dma_cnt,};
    mem_seg_token_t token;
    test_custom_read_dma_t dma[dma_cnt];
    (void *)memcpy((char *)(uintptr_t)wr.args->addr + urpc_hdr_size, &example_head, sizeof(custom_head_t));
    for (int i = 0; i < dma_cnt; i++) {
        ret = g_test_allocator.get_raw_buf(&sge_one, g_test_urpc_ctx.allocator_config.block_size, NULL);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("g_test_allocator.get_raw_buf failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
            return TEST_FAILED;
        }
        ret = urpc_mem_seg_token_get(sge_one.mem_h, &token);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("urpc_mem_seg_token_get failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
            return TEST_FAILED;
        }

        dma[i].address = sge_one.addr;
        dma[i].size = sge_one.length;
        dma[i].token_id = token.token_id;
        dma[i].token_value = token.token_value;

        (void *)memcpy((char *)(uintptr_t)wr.args->addr + hdr_size + i * sizeof(test_custom_read_dma_t), &dma[i], sizeof(test_custom_read_dma_t));
        (void)sprintf((char *)(uintptr_t)sge_one.addr, "Data dma %u", i);

    }
    call_ret = urpc_func_call(func_args->channel_id, &wr, &option);
    if (call_ret == URPC_U64_FAIL) {
        TEST_LOG_ERROR("urpc_func_call failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
        g_test_allocator.put(wr.args, wr.args_num, nullptr);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_client_run_read(test_func_args_t *func_args)
{
    int ret = test_client_process_normal_call_read(func_args);
    if (ret != TEST_SUCCESS) {
        return TEST_FAILED;
    }

    if (func_args->is_not_poll != true) {
        ret = test_client_process_event(func_args);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_client_process_event failed, ret:%d, errno:%d, message: %s.\n", ret, errno, strerror(errno));
            return TEST_FAILED;
        }
    }
    return TEST_SUCCESS;
}

int test_func_call_read_custom(test_func_args_t *func_args)
{
    int ret;
    set_call_option_queue_handle(func_args, &func_args->call_option);
    set_call_option_flag_rsp(&func_args->call_option);
    set_func_args_hit_events_rsp(func_args);
    ret = test_client_run_read(func_args);
    return ret;
}

int test_func_call_no_rsp_no_ack(test_func_args_t *func_args)
{
    int ret;
    set_call_option_queue_handle(func_args, &func_args->call_option);
    set_call_option_flag_no_ack_rsp(&func_args->call_option);
    set_func_args_hit_events_no_ack_rsp(func_args);
    ret = test_client_run(func_args);
    return ret;
}

uint64_t create_original_queue(urpc_queue_trans_mode_t trans_mode)
{
    int ret = -1;
    uint64_t queue_handler = 0;
    urpc_qcfg_create_t queue_cfg = {0};
    urpc_qcfg_get_t qcfg_get_cfg = {0};
    memset(&queue_cfg, 0, sizeof(urpc_qcfg_create_t));
    queue_cfg.create_flag = QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_PRIORITY | QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_MAX_TX_SGE;
    queue_cfg.priority = CLOUD_STORAGE_PRIORITY;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.rx_buf_size = DEFAULT_RX_BUF_SIZE;
    queue_cfg.rx_depth = DEFAULT_RX_DEPTH;
    queue_cfg.max_rx_sge = MAX_RX_SGE;
    queue_cfg.max_tx_sge = MAX_TX_SGE;
    if (g_test_urpc_ctx.queue_ops.is_epoll) {
        queue_cfg.create_flag |= QCREATE_FLAG_MODE;
        queue_cfg.mode = QUEUE_MODE_INTERRUPT;
    }

    queue_handler = urpc_queue_create(trans_mode, &queue_cfg);
    if (queue_handler == 0){
        TEST_LOG_ERROR("urpc_queue_create queue handles=%d\n", queue_handler);
        return 0;
    }

    memset(&qcfg_get_cfg, 0, sizeof(urpc_qcfg_get_t));
    ret = urpc_queue_cfg_get(queue_handler, &qcfg_get_cfg);
    TEST_LOG_INFO("urpc_queue_cfg_get queue ret=%d\n", ret);
    CHKERR_JUMP(qcfg_get_cfg.rx_depth != DEFAULT_RX_DEPTH, "check rx_depth", EXIT);
    CHKERR_JUMP(qcfg_get_cfg.rx_buf_size != DEFAULT_RX_BUF_SIZE, "check rx_buf_size", EXIT);
    CHKERR_JUMP(qcfg_get_cfg.max_rx_sge != MAX_RX_SGE, "check max_rx_sge", EXIT);
    CHKERR_JUMP(qcfg_get_cfg.max_tx_sge != MAX_TX_SGE, "check max_tx_sge", EXIT);
    CHKERR_JUMP(qcfg_get_cfg.priority != CLOUD_STORAGE_PRIORITY , "check priority", EXIT);
    CHKERR_JUMP(qcfg_get_cfg.tx_depth != DEFAULT_TX_DEPTH, "check tx_depth", EXIT);

    return queue_handler;
EXIT:
    urpc_queue_destroy(queue_handler);
    return 0;
}

uint64_t create_share_rq_queue(uint64_t share_rq_handler, urpc_queue_trans_mode_t trans_mode)
{
    int ret = -1;
    uint64_t queue_handler =0;
    urpc_qcfg_create_t queue_cfg = {0};
    urpc_qcfg_get_t qcfg_get_cfg1 = {0};
    urpc_qcfg_get_t qcfg_get_cfg2 = {0};

    memset(&queue_cfg, 0, sizeof(urpc_qcfg_create_t));
    queue_cfg.create_flag |= QCREATE_FLAG_TX_DEPTH | QCREATE_FLAG_PRIORITY | QCREATE_FLAG_QH_SHARE_RQ;
    queue_cfg.tx_depth = DEFAULT_TX_DEPTH;
    queue_cfg.priority = CLOUD_STORAGE_PRIORITY;
    queue_cfg.urpc_qh_share_rq = share_rq_handler;
    if (g_test_urpc_ctx.queue_ops.is_epoll) {
        queue_cfg.create_flag |= QCREATE_FLAG_MODE;
        queue_cfg.mode = QUEUE_MODE_INTERRUPT;
    }

    queue_handler = urpc_queue_create(trans_mode, &queue_cfg);
    if (queue_handler == 0) {
        TEST_LOG_ERROR("urpc_queue_create queue handles=%d\n", queue_handler);
        return 0;
    }

    memset(&qcfg_get_cfg1, 0, sizeof(urpc_qcfg_get_t));
    ret = urpc_queue_cfg_get(share_rq_handler, &qcfg_get_cfg1);
    TEST_LOG_INFO("urpc_queue_cfg_get queue ret=%d\n", ret);

    memset(&qcfg_get_cfg2, 0, sizeof(urpc_qcfg_get_t));
    ret = urpc_queue_cfg_get(queue_handler, &qcfg_get_cfg2);
    TEST_LOG_INFO("urpc_queue_cfg_get queue ret=%d\n", ret);

    CHKERR_JUMP(qcfg_get_cfg1.rx_depth != qcfg_get_cfg2.rx_depth, "check rx_depth", EXIT);
    CHKERR_JUMP(qcfg_get_cfg1.rx_buf_size != qcfg_get_cfg2.rx_buf_size, "check rx_buf_size", EXIT);
    CHKERR_JUMP(qcfg_get_cfg1.max_rx_sge != qcfg_get_cfg2.max_rx_sge, "check max_rx_sge", EXIT);
    CHKERR_JUMP(qcfg_get_cfg1.max_tx_sge != qcfg_get_cfg2.max_tx_sge, "check max_tx_sge", EXIT);
    CHKERR_JUMP(qcfg_get_cfg1.priority != CLOUD_STORAGE_PRIORITY , "check priority", EXIT);
    CHKERR_JUMP(qcfg_get_cfg1.tx_depth != DEFAULT_TX_DEPTH, "check tx_depth", EXIT);

    return queue_handler;
EXIT:
    urpc_queue_destroy(queue_handler);
    return 0;
}

urpc_qcfg_get_t print_queue_cfg(uint64_t queue_handle)
{
    urpc_qcfg_get_t qcfg = {0};
    int ret = urpc_queue_cfg_get(queue_handle, &qcfg);
    CHKERR_JUMP(ret!= TEST_SUCCESS, "urpc_queue_cfg_get", EXIT);
    TEST_LOG_INFO("===============print_queue_cfg===============\n");
    TEST_LOG_INFO("custom_flag %p\n", qcfg.custom_flag);
    TEST_LOG_INFO("rx_buf_size %llu\n", qcfg.rx_buf_size);
    TEST_LOG_INFO("rx_depth %llu\n", qcfg.rx_depth);
    TEST_LOG_INFO("tx_depth %llu\n", qcfg.tx_depth);
    TEST_LOG_INFO("urpc_server_info_t info: server_type %llu, version %llu, ip %s\n", qcfg.info.server_type, qcfg.info.version, qcfg.info.ipv4.ip_addr);
    TEST_LOG_INFO("urpc_queue_type_t type %llu\n", qcfg.type);
    TEST_LOG_INFO("trans_mode %llu\n", qcfg.trans_mode);
    TEST_LOG_INFO("trans_qnum %llu\n", qcfg.trans_qnum);
    TEST_LOG_INFO("priority %llu\n", qcfg.priority);
    TEST_LOG_INFO("max_rx_sge %llu\n", qcfg.max_rx_sge);
    TEST_LOG_INFO("max_tx_sge %llu\n", qcfg.max_tx_sge);
    TEST_LOG_INFO("lock_free %llu\n", qcfg.lock_free);
EXIT:
    return qcfg;
}

int test_get_queue_stats(uint64_t queue_handle, uint64_t * stats_total)
{
    int ret = TEST_FAILED;
    uint64_t stats[STATS_TYPE_MAX] = {0};
    memset(&stats, 0, sizeof(uint64_t) * STATS_TYPE_MAX);
    ret = urpc_queue_stats_get(queue_handle, stats, STATS_TYPE_MAX);
    CHKERR_JUMP(ret != TEST_SUCCESS, "urpc_queue_stats_get", EXIT);
    stats_total[STATS_TYPE_REQUEST_SEND] += stats[STATS_TYPE_REQUEST_SEND];
    stats_total[STATS_TYPE_ACK_SEND] += stats[STATS_TYPE_ACK_SEND];
    stats_total[STATS_TYPE_RESPONSE_SEND] += stats[STATS_TYPE_RESPONSE_SEND];
    stats_total[STATS_TYPE_ACK_RESPONSE_SEND] += stats[STATS_TYPE_ACK_RESPONSE_SEND];
    stats_total[STATS_TYPE_REQUEST_SEND_CONFIRMED] += stats[STATS_TYPE_REQUEST_SEND_CONFIRMED];
    stats_total[STATS_TYPE_ACK_SEND_CONFIRMED] += stats[STATS_TYPE_ACK_SEND_CONFIRMED];
    stats_total[STATS_TYPE_RESPONSE_SEND_CONFIRMED] += stats[STATS_TYPE_RESPONSE_SEND_CONFIRMED];
    stats_total[STATS_TYPE_ACK_RESPONSE_SEND_CONFIRMED] += stats[STATS_TYPE_ACK_RESPONSE_SEND_CONFIRMED];
    stats_total[STATS_TYPE_REQUEST_RECEIVE] += stats[STATS_TYPE_REQUEST_RECEIVE];
    stats_total[STATS_TYPE_ACK_RECEIVE] += stats[STATS_TYPE_ACK_RECEIVE];
    stats_total[STATS_TYPE_RESPONSE_RECEIVE] += stats[STATS_TYPE_RESPONSE_RECEIVE];
    stats_total[STATS_TYPE_ACK_RESPONSE_RECEIVE] += stats[STATS_TYPE_ACK_RESPONSE_RECEIVE];

    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

void print_queue_stats(uint64_t *stats_total)
{
    TEST_LOG_INFO("stats req_send_num=%d\n", stats_total[STATS_TYPE_REQUEST_SEND]);
    TEST_LOG_INFO("stats ack_send_num=%d\n", stats_total[STATS_TYPE_ACK_SEND]);
    TEST_LOG_INFO("stats resp_send_num=%d\n", stats_total[STATS_TYPE_RESPONSE_SEND]);
    TEST_LOG_INFO("stats ack_resp_send_num=%d\n", stats_total[STATS_TYPE_ACK_RESPONSE_SEND]);
    TEST_LOG_INFO("stats req_send_conf_num=%d\n", stats_total[STATS_TYPE_REQUEST_SEND_CONFIRMED]);
    TEST_LOG_INFO("stats ack_send_conf_num=%d\n", stats_total[STATS_TYPE_ACK_SEND_CONFIRMED]);
    TEST_LOG_INFO("stats resp_send_conf_num=%d\n", stats_total[STATS_TYPE_RESPONSE_SEND_CONFIRMED]);
    TEST_LOG_INFO("stats ack_resp_send_conf_num=%d\n", stats_total[STATS_TYPE_ACK_RESPONSE_SEND_CONFIRMED]);
    TEST_LOG_INFO("stats req_recv_num=%d\n", stats_total[STATS_TYPE_REQUEST_RECEIVE]);
    TEST_LOG_INFO("stats ack_recv_num=%d\n", stats_total[STATS_TYPE_ACK_RECEIVE]);
    TEST_LOG_INFO("stats resp_recv_num=%d\n", stats_total[STATS_TYPE_RESPONSE_RECEIVE]);
    TEST_LOG_INFO("stats ack_resp_recv_num=%d\n", stats_total[STATS_TYPE_ACK_RESPONSE_RECEIVE]);
}

int test_func_call_all_type_by_one_channel(test_urpc_ctx_t *ctx, uint32_t channel_idx)
{
    int ret = 0;
    test_func_args_t func_args = {0};
    memset(&func_args, 0, sizeof(func_args));
    func_args.channel_id = ctx->channel_ids[channel_idx];
    TEST_LOG_DEBUG("test_func_call_all_type_by_one_channel %u lqh=%p rqh=%p\n", channel_idx, ctx->channel_ops[channel_idx].lqueue_ops[0].qh, ctx->channel_ops[channel_idx].rqueue_ops[0].qh);
    func_args.lqueue_handle = ctx->channel_ops[channel_idx].lqueue_ops[0].qh;
    func_args.rqueue_handle = ctx->channel_ops[channel_idx].rqueue_ops[0].qh;
    func_args.func_id = ctx->func_id;
    ret = test_func_call_recv_rsp_no_ack(&func_args);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_recv_rsp_no_ack", EXIT);
    ret = test_func_call_no_rsp_no_ack(&func_args);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_no_rsp_no_ack", EXIT);
    if ((ctx->ctx_flag & CTX_FLAG_MEM_SEG_ACCESS_ENABLE) != 0) {
        ret =test_func_call_read_custom(&func_args);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_read_custom", EXIT);
    }

EXIT:
    return ret;
}

int test_func_call_all_type(test_urpc_ctx_t *ctx)
{
    int ret = 0;
    for (uint32_t i = 0; i < ctx->channel_num; i++) {
        ret = test_func_call_all_type_by_one_channel(ctx, i);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_INFO("test round channel id=%u failed\n", i);
        }
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_func_call_all_type_by_one_channel", EXIT);
    }
EXIT:
    return ret;
}

int start_ipv6_server(char *ipv6_addr, uint16_t port)
{
    int sockfd;
    struct sockaddr_in6 serv_addr;
    TEST_LOG_INFO("ipv6_addr=%s port=%u\n", ipv6_addr, port);

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        TEST_LOG_ERROR("Failed to create socket, errno=%d, err=%s\n", errno, strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) != 0) {
        TEST_LOG_ERROR("Failed to setsockopt, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(int)) != 0) {
        TEST_LOG_ERROR("Failed to setsockopt, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ipv6_addr, &serv_addr.sin6_addr) <= 0) {
        TEST_LOG_ERROR("Failed to inet_pton, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        TEST_LOG_ERROR("Failed to bind, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, MAX_CONNECTIONS) < 0) {
        TEST_LOG_ERROR("Failed to listen, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int start_ipv4_server(char *ipv4_addr, uint16_t port)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    TEST_LOG_INFO("ipv4_addr=%s port=%u\n", ipv4_addr, port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        TEST_LOG_ERROR("Failed to create socket, errno=%d, err=%s\n", errno, strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) != 0) {
        TEST_LOG_ERROR("Failed to setsockopt, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(int)) != 0) {
        TEST_LOG_ERROR("Failed to setsockopt, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ipv4_addr, &serv_addr.sin_addr) <= 0) {
        TEST_LOG_ERROR("Failed to bind, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        TEST_LOG_ERROR("Failed to bind, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, MAX_CONNECTIONS) < 0) {
        TEST_LOG_ERROR("Failed to listen, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int start_ipv6_client(char *ipv6_addr, uint16_t port)
{
    int sockfd;
    struct sockaddr_in6 serv_addr;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        TEST_LOG_ERROR("Failed to create socket, errno=%d, err=%s\n", errno, strerror(errno));
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ipv6_addr, &serv_addr.sin6_addr) <= 0) {
        TEST_LOG_ERROR("Failed to bind, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        TEST_LOG_ERROR("Failed to connect, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int start_ipv4_client(char *ipv4_addr, uint16_t port)
{
    int sockfd;
    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        TEST_LOG_ERROR("Failed to create socket, errno=%d, err=%s\n", errno, strerror(errno));
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ipv4_addr, &serv_addr.sin_addr) <= 0) {
        TEST_LOG_ERROR("Failed to bind, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        TEST_LOG_ERROR("Failed to connect, errno=%d, err=%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    return sockfd;
}

log_file_info_t *test_create_file(const char *file_name)
{
    int ret;
    if ((file_name == NULL) || (strlen(file_name) > MAX_FILE_NAME_LEN)) {
        TEST_LOG_ERROR("[test_log_set_file_name]file name is null.\n");
        return NULL;
    }

    log_file_info_t *log_file_info = (log_file_info_t *)malloc(sizeof(log_file_info_t));
    if (log_file_info == NULL) {
        TEST_LOG_ERROR("[test_log_set_file_name]malloc memory failed.\n");
        return NULL;
    }
    (void)memset(log_file_info, 0, sizeof(log_file_info_t));
    strncpy(log_file_info->file_name, file_name, strlen(file_name));

    ret = test_log_create_dir(log_file_info->file_name);
    if (ret != 0) {
        TEST_LOG_ERROR("[test_log_set_file_name]mkdir failed,filenale:%s.\n", log_file_info->file_name);
        free(log_file_info);
        log_file_info = NULL;
        return NULL;
    }

    log_file_info->fd = fopen(log_file_info->file_name, "a+");
    if (log_file_info->fd == NULL) {
        TEST_LOG_ERROR("[test_log_set_file_name]open file name:%s failed.\n", log_file_info->file_name);
        free(log_file_info);
        log_file_info = NULL;
        return NULL;
    }
    log_file_info->inited = 1;

    return log_file_info;
}






















































