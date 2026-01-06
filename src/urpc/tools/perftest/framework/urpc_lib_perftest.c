/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc perftest for urpc lib
 * Create: 2024-3-6
 */

#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "perftest_thread.h"
#include "queue.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_framework_types.h"
#include "urpc_util.h"
#include "urpc_framework_errno.h"

#include "urpc_lib_perftest_allocator.h"
#include "urpc_lib_perftest_latency.h"
#include "urpc_lib_perftest_param.h"
#include "urpc_lib_perftest_qps.h"
#include "urpc_lib_perftest_util.h"

#define URPC_PERFTEST_DEPTH_MARGIN 8

#define URPC_PERFTEST_SYN "SYN"
#define URPC_PERFTEST_ACK "ACK"
#define URPC_PERFTEST_SYNC_MSG_SIZE 32
#define URPC_PERFTEST_PAIR_WAIT_S 1
#define CTRL_MSG_MAX_SIZE (1 << 16)

typedef struct urpc_perftest_worker_arg {
    perftest_thread_arg_t thd_arg;
    uint64_t qh;
    perftest_framework_config_t *cfg;
    union {
        urpc_lib_perftest_latency_arg_t lat_arg;
        urpc_lib_perftest_qps_arg_t qps_arg;
    };
} urpc_perftest_worker_arg_t;

// perftest resources
static struct urpc_perftest_ctx {
    uint64_t *qhs;  // one q_handle processed by one single thread
    urpc_perftest_worker_arg_t *args;
    uint64_t r_qh;        // client use this cfg for remote queue
    uint64_t r_qhs[LAT_Q_NUM];
    uint32_t chid;        // client use this cfg for func call/func poll
    uint32_t q_num;       // q_handle number, client only support 1 for now
    uint32_t worker_num;  // worker thread number, client only support 1 for now

    int fd;
    int accept_fd;

    volatile bool force_quit;
} g_urpc_perftest_ctx = {0};

void perftest_force_quit(void)
{
    g_urpc_perftest_ctx.force_quit = true;
}

bool is_perftest_force_quit(void)
{
    return g_urpc_perftest_ctx.force_quit;
}

typedef struct remote_qid {
    int num;
    uint32_t rqid[MAX_QUEUE_SIZE];
} remote_qid_t;

static remote_qid_t g_urpc_perftest_client_recv_rqid = {0};
static remote_qid_t g_urpc_perftest_server_send_rqid = {0};

static int ctrl_msg_callback(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg)
{
    remote_qid_t *info = (remote_qid_t *)(void *)ctrl_msg->msg;
    if (ctrl_msg->msg_size < sizeof(remote_qid_t)) {
        return URPC_FAIL;
    }
    if (info->num > MAX_QUEUE_SIZE) {
        return URPC_FAIL;
    }
    if (ctrl_msg->is_server) {
        info->num = g_urpc_perftest_server_send_rqid.num;
        for (int i = 0; i < info->num; i++) {
            info->rqid[i] = g_urpc_perftest_server_send_rqid.rqid[i];
        }
        ctrl_msg->msg_size = (uint32_t)sizeof(remote_qid_t);
    } else {
        // recv client ctl msg
        for (int i = 0; i < info->num; i++) {
            g_urpc_perftest_client_recv_rqid.rqid[i] = info->rqid[i];
        }
        g_urpc_perftest_client_recv_rqid.num = info->num;
    }
    return URPC_SUCCESS;
}

static uint32_t get_rx_buf_size(uint32_t *size, uint32_t size_len)
{
    uint32_t max_rx_buf_size = size[0];
    for (uint32_t i = 1; i < size_len; i++) {
        max_rx_buf_size = max_rx_buf_size > size[i] ? max_rx_buf_size : size[i];
    }
    return max_rx_buf_size;
}

static int queue_cfg_init(perftest_framework_config_t *cfg, urpc_qcfg_create_t *queue_cfg)
{
    queue_cfg->create_flag |= QCREATE_FLAG_RX_BUF_SIZE | QCREATE_FLAG_RX_DEPTH | QCREATE_FLAG_TX_DEPTH |
                             QCREATE_FLAG_CUSTOM_FLAG | QCREATE_FLAG_MAX_RX_SGE | QCREATE_FLAG_MAX_TX_SGE |
                             QCREATE_FLAG_LOCK_FREE;
    queue_cfg->rx_buf_size = get_rx_buf_size(cfg->size, cfg->size_len);
    queue_cfg->rx_depth = cfg->rx_depth;
    queue_cfg->tx_depth = cfg->tx_depth;
    queue_cfg->max_rx_sge = cfg->size_len;
    queue_cfg->max_tx_sge = cfg->size_len;
    queue_cfg->lock_free = 1;

    return 0;
}

static inline uint32_t get_q_num(perftest_framework_config_t *cfg)
{
    uint32_t q_num = cfg->instance_mode == SERVER ? cfg->thread_num : 1;
    if (cfg->case_type == PERFTEST_CASE_LAT) {
        q_num = cfg->use_one_q ? 1 : LAT_Q_NUM;
    }

    return q_num;
}

static int urpc_perftest_init_queue_handles(perftest_framework_config_t *cfg)
{
    g_urpc_perftest_ctx.q_num = get_q_num(cfg);
    g_urpc_perftest_ctx.qhs = (uint64_t *)calloc(g_urpc_perftest_ctx.q_num, sizeof(uint64_t));
    if (g_urpc_perftest_ctx.qhs == NULL) {
        LOG_PRINT("malloc qhs failed\n");
        return -1;
    }

    urpc_qcfg_create_t queue_cfg = {0};
    if (queue_cfg_init(cfg, &queue_cfg) != 0) {
        goto FREE_QHS;
    }

    for (uint32_t i = 0; i < g_urpc_perftest_ctx.q_num; i++) {
        uint32_t index = perftest_thread_index();
        // make sure queue(urpc_post_rx_buffer) is processed by corresponding thread
        uint32_t fake_index = cfg->case_type == PERFTEST_CASE_LAT ? 1 : i + 1;
        perftest_thread_index_set(fake_index);
        queue_cfg.custom_flag = i;
        g_urpc_perftest_ctx.qhs[i] = urpc_queue_create(QUEUE_TRANS_MODE_JETTY, &queue_cfg);
        perftest_thread_index_set(index);  // recover
        if (g_urpc_perftest_ctx.qhs[i] == URPC_INVALID_HANDLE) {
            LOG_PRINT("create qh %u failed\n", i);
            goto DESTROY_QHS;
        }
    }

    return 0;

DESTROY_QHS:
    for (uint32_t i = 0; i < g_urpc_perftest_ctx.q_num; i++) {
        if (g_urpc_perftest_ctx.qhs[i] == 0) {
            break;
        }

        (void)urpc_queue_destroy(g_urpc_perftest_ctx.qhs[i]);
        g_urpc_perftest_ctx.qhs[i] = 0;
    }

FREE_QHS:
    free(g_urpc_perftest_ctx.qhs);
    g_urpc_perftest_ctx.qhs = NULL;

    return -1;
}

static void urpc_perftest_queue_handles_uninit(void)
{
    if (g_urpc_perftest_ctx.qhs == NULL) {
        return;
    }

    for (uint32_t i = 0; i < g_urpc_perftest_ctx.q_num; i++) {
        if (g_urpc_perftest_ctx.qhs[i] == 0) {
            break;
        }

        (void)urpc_queue_destroy(g_urpc_perftest_ctx.qhs[i]);
        g_urpc_perftest_ctx.qhs[i] = 0;
    }

    free(g_urpc_perftest_ctx.qhs);
    g_urpc_perftest_ctx.qhs = NULL;
}

static inline void urpc_perftest_client_qps_work_load(perftest_thread_arg_t *args)
{
    urpc_perftest_worker_arg_t *arg = CONTAINER_OF_FIELD(args, urpc_perftest_worker_arg_t, thd_arg);
    arg->qps_arg.chid = g_urpc_perftest_ctx.chid;
    arg->qps_arg.cfg = arg->cfg;
    urpc_perftest_client_run_qps(&arg->thd_arg, &arg->qps_arg, arg->qh);
}

static inline void urpc_perftest_server_qps_work_load(perftest_thread_arg_t *args)
{
    urpc_perftest_worker_arg_t *arg = CONTAINER_OF_FIELD(args, urpc_perftest_worker_arg_t, thd_arg);
    arg->qps_arg.cfg = arg->cfg;
    urpc_perftest_server_run_qps(&arg->thd_arg, &arg->qps_arg, arg->qh);
}

static inline void urpc_perftest_latency_work_load(perftest_thread_arg_t *args)
{
    urpc_perftest_worker_arg_t *arg = CONTAINER_OF_FIELD(args, urpc_perftest_worker_arg_t, thd_arg);
    arg->lat_arg.chid = g_urpc_perftest_ctx.chid;
    arg->lat_arg.cfg = arg->cfg;
    for (uint32_t i = 0; i < LAT_Q_NUM; i++) {
        arg->lat_arg.r_qhs[i] = g_urpc_perftest_ctx.r_qhs[i % g_urpc_perftest_ctx.q_num];
        arg->lat_arg.l_qhs[i] = g_urpc_perftest_ctx.qhs[i % g_urpc_perftest_ctx.q_num];
    }

    urpc_perftest_run_latency(&arg->thd_arg, &arg->lat_arg, arg->qh);
}

static int urpc_perftest_start_workers(perftest_framework_config_t *cfg)
{
    g_urpc_perftest_ctx.worker_num = cfg->thread_num;
    g_urpc_perftest_ctx.args =
        (urpc_perftest_worker_arg_t *)calloc(g_urpc_perftest_ctx.worker_num, sizeof(urpc_perftest_worker_arg_t));
    if (g_urpc_perftest_ctx.args == NULL) {
        LOG_PRINT("malloc perftest ctx args failed\n");
        return -1;
    }

    void (*func)(perftest_thread_arg_t *);
    if (cfg->case_type == PERFTEST_CASE_QPS) {
        func = cfg->instance_mode == SERVER ? urpc_perftest_server_qps_work_load : urpc_perftest_client_qps_work_load;
    } else {
        func = urpc_perftest_latency_work_load;
    }

    uint32_t i;
    for (i = 0; i < g_urpc_perftest_ctx.worker_num; i++) {
        g_urpc_perftest_ctx.args[i].thd_arg.func = func;
        g_urpc_perftest_ctx.args[i].thd_arg.state = PERFTEST_THREAD_INIT;
        g_urpc_perftest_ctx.args[i].thd_arg.cpu_affinity = cfg->cpu_affinity + i;
        g_urpc_perftest_ctx.args[i].cfg = cfg;
        g_urpc_perftest_ctx.args[i].qh = g_urpc_perftest_ctx.qhs[i];
        if (perftest_worker_thread_create(&g_urpc_perftest_ctx.args[i].thd_arg) != 0) {
            LOG_PRINT("create worker thread %u failed\n", i);
            break;
        }
    }

    if (i == g_urpc_perftest_ctx.worker_num) {
        return 0;
    }

    for (uint32_t j = 0; j < i; j++) {
        perftest_worker_thread_destroy(&g_urpc_perftest_ctx.args[j].thd_arg);
    }

    free(g_urpc_perftest_ctx.args);
    g_urpc_perftest_ctx.args = NULL;

    return -1;
}

static void urpc_perftest_stop_workers(void)
{
    if (g_urpc_perftest_ctx.args == NULL) {
        return;
    }

    for (uint32_t i = 0; i < g_urpc_perftest_ctx.worker_num; i++) {
        perftest_worker_thread_destroy(&g_urpc_perftest_ctx.args[i].thd_arg);
    }

    free(g_urpc_perftest_ctx.args);
    g_urpc_perftest_ctx.args = NULL;
}

static void urpc_perftest_run(perftest_framework_config_t *cfg)
{
    if (cfg->case_type == PERFTEST_CASE_QPS) {
        urpc_perftest_print_qps(cfg);
    } else {
        urpc_perftest_print_latency(cfg);
    }
}

static void fill_dev_info(urpc_trans_info_t *dev_info, perftest_framework_config_t *cfg)
{
    uint32_t addr;
    dev_info->trans_mode = cfg->trans_mode;
    if (strlen(cfg->dev_name) != 0) {
        LOG_PRINT("umq perftest init with dev: %s\n", cfg->dev_name);
        dev_info->assign_mode = DEV_ASSIGN_MODE_DEV;
        memcpy(dev_info->dev.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    } else if (inet_pton(AF_INET, cfg->local_ip, &addr) == 1) {
        LOG_PRINT("umq perftest init with ipv4: %s\n", cfg->local_ip);
        dev_info->assign_mode = DEV_ASSIGN_MODE_IPV4;
        memcpy(dev_info->ipv4.ip_addr, cfg->local_ip, strlen(cfg->local_ip));
    } else {
        LOG_PRINT("umq perftest init with ipv6: %s\n", cfg->local_ip);
        dev_info->assign_mode = DEV_ASSIGN_MODE_IPV6;
        memcpy(dev_info->ipv6.ip_addr, cfg->local_ip, strlen(cfg->local_ip));
    }
    (void)addr;
}

static int urpc_perftest_server_client_init(perftest_framework_config_t *cfg)
{
    int ret;

    urpc_config_t urpc_config = {0};
    urpc_config.role = URPC_ROLE_SERVER_CLIENT;
    if (cfg->hwub_offlad) {
        urpc_config.feature |= URPC_FEATURE_HWUB_OFFLOAD;
    }

    urpc_config.feature |= (URPC_FEATURE_DISABLE_TOKEN_POLICY | URPC_FEATURE_DISABLE_STATS);
    urpc_config.trans_info_num = 1;
    fill_dev_info(urpc_config.trans_info, cfg);
    urpc_config.trans_info[0].trans_mode = (urpc_trans_mode_t)cfg->trans_mode;

    if (cfg->is_ipv6_dev) {
        urpc_config.trans_info[0].dev.is_ipv6 = true;
    }

    if (strlen(cfg->path) != 0) {
        urpc_config.unix_domain_file_path = cfg->path;
    }
    ret = urpc_init(&urpc_config);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("urpc_init failed %d\n", ret);
        return -1;
    }

    return 0;
}

static int urpc_perftest_server_client_start(perftest_framework_config_t *cfg)
{
    urpc_control_plane_config_t cp_cfg = {0};
    uint32_t addr;
    int ret;
    if (inet_pton(AF_INET, cfg->local_ip, &addr) == 1) {
        LOG_PRINT("urpc_perftest_server_client_start in ipv4 %s\n", cfg->local_ip);
        cp_cfg.server.server_type = SERVER_TYPE_IPV4;
        cp_cfg.server.ipv4.port = cfg->instance_mode == SERVER ? cfg->tcp_port : cfg->tcp_port - 1;
        (void)strcpy(cp_cfg.server.ipv4.ip_addr, cfg->local_ip);
    } else {
        LOG_PRINT("urpc_perftest_server_client_start in ipv6 %s\n", cfg->local_ip);
        cp_cfg.server.server_type = SERVER_TYPE_IPV6;
        cp_cfg.server.ipv6.port = cfg->instance_mode == SERVER ? cfg->tcp_port : cfg->tcp_port - 1;
        (void)strcpy(cp_cfg.server.ipv6.ip_addr, cfg->local_ip);
    }
    uint64_t *qh_list;
    uint32_t qh_cnt = urpc_get_local_qh(&qh_list);
    if (qh_cnt > MAX_QUEUE_SIZE) {
        LOG_PRINT("urpc_perftest_server_client_start qh_cnt %u > MAX_QUEUE_SIZE %u\n", qh_cnt, MAX_QUEUE_SIZE);
        return -1;
    }
    uint32_t j = 0;
    for (uint32_t i = 0; i < qh_cnt; i++) {
        urpc_qcfg_get_t cfg_get = {0};
        if (urpc_queue_cfg_get(qh_list[i], &cfg_get) != URPC_SUCCESS) {
            LOG_PRINT("query local qh qid err\n");
        } else {
            g_urpc_perftest_server_send_rqid.rqid[j++] = cfg_get.qid;
        }
    }
    urpc_dbuf_free(qh_list);
    g_urpc_perftest_server_send_rqid.num = (int)j;
    ret = urpc_server_start(&cp_cfg);
    if (ret != URPC_SUCCESS) {
        LOG_PRINT("urpc_server_start failed %d\n", ret);
        return -1;
    }

    return 0;
}

static void parse_server_to_host(
    urpc_server_info_t *server, urpc_host_info_t *server_host, urpc_host_info_t *local_host)
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

static int urpc_perftest_server_client_channel_attach(perftest_framework_config_t *cfg, uint32_t chid)
{
    urpc_server_info_t server_info = {0};

    uint32_t addr;
    if (inet_pton(AF_INET, cfg->local_ip, &addr) == 1) {
        LOG_PRINT("urpc_perftest_server_client_channel_attach in ipv4 %s\n", cfg->remote_ip);
        server_info.server_type = SERVER_TYPE_IPV4;
        server_info.ipv4.port = cfg->instance_mode == SERVER ? cfg->tcp_port - 1 : cfg->tcp_port;
        (void)strcpy(server_info.ipv4.ip_addr, cfg->remote_ip);
    } else {
        LOG_PRINT("urpc_perftest_server_client_channel_attach in ipv6 %s\n", cfg->remote_ip);
        server_info.server_type = SERVER_TYPE_IPV6;
        server_info.ipv6.port = cfg->instance_mode == SERVER ? cfg->tcp_port - 1 : cfg->tcp_port;
        (void)strcpy(server_info.ipv6.ip_addr, cfg->remote_ip);
    }

    urpc_host_info_t local_host;
    urpc_host_info_t server_host;
    parse_server_to_host(&server_info, &server_host, &local_host);
    urpc_host_info_t *local = server_info.assigned_addr.bind_local_addr_enabled ? &local_host : NULL;

    urpc_channel_connect_option_t channel_option = {0};
    channel_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
    if (local != NULL) {
        channel_option.flag |= URPC_CHANNEL_CONN_FLAG_BIND_LOCAL;
        channel_option.local = *local;
    }

    remote_qid_t queue_info = {
        .num = 0,
    };
    urpc_ctrl_msg_t ctl_msg = {
        .user_ctx = NULL,
        .msg = (char *)(uintptr_t)&queue_info,
        .msg_size = (uint32_t)sizeof(remote_qid_t),
        .msg_max_size = CTRL_MSG_MAX_SIZE,
    };

    channel_option.ctrl_msg = &ctl_msg;
    if (urpc_channel_server_attach(chid, &server_host, &channel_option) != URPC_SUCCESS) {
        LOG_PRINT("urpc_channel_server_attach %s failed\n", cfg->remote_ip);
        return -1;
    }

    return 0;
}

static int urpc_perftest_server_client_remote_queue_add(perftest_framework_config_t *cfg, uint32_t chid)
{
    urpc_channel_qinfos_t *qinfos = (urpc_channel_qinfos_t *)calloc(1, sizeof(urpc_channel_qinfos_t));
    if (qinfos == NULL) {
        LOG_PRINT("malloc qinfos failed\n");
        return -1;
    }
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_REMOTE};
    if (cfg->case_type == PERFTEST_CASE_LAT) {
        if (g_urpc_perftest_client_recv_rqid.num != (int)g_urpc_perftest_ctx.q_num) {
            LOG_PRINT("qnum invalid, %d, %u\n", g_urpc_perftest_client_recv_rqid.num, g_urpc_perftest_ctx.q_num);
            free(qinfos);
            return -1;
        }
        for (int i = 0; i < g_urpc_perftest_client_recv_rqid.num; i++) {
            if (urpc_channel_queue_add(chid, g_urpc_perftest_client_recv_rqid.rqid[i], attr, &queue_option) != 0) {
                LOG_PRINT("urpc_channel_queue_add failed\n");
                free(qinfos);
                return -1;
            }
        }
        if (urpc_channel_queue_query(chid, qinfos) != 0) {
            LOG_PRINT("urpc_channel_queue_query failed\n");
            free(qinfos);
            return -1;
        };
        for (int i = 0; i < qinfos->r_qnum; i++) {
            urpc_qcfg_get_t qcfg_get = {0};
            (void)urpc_queue_cfg_get(qinfos->r_qinfo[i].urpc_qh, &qcfg_get);
            g_urpc_perftest_ctx.r_qhs[qcfg_get.custom_flag] = qinfos->r_qinfo[i].urpc_qh;
        }
        free(qinfos);
        return 0;
    }

    // qps test only add 1 remote queue
    uint8_t target_queue = cfg->target_queue >= g_urpc_perftest_client_recv_rqid.num ? 0 : cfg->target_queue;
    if (urpc_channel_queue_add(chid, g_urpc_perftest_client_recv_rqid.rqid[target_queue], attr, &queue_option) !=
        0) {
        LOG_PRINT("urpc_channel_queue_add failed\n");
        free(qinfos);
        return -1;
    }
    if (urpc_channel_queue_query(chid, qinfos) != 0) {
        LOG_PRINT("urpc_channel_queue_query failed\n");
        free(qinfos);
        return -1;
    };
    bool is_find = false;
    for (int i = 0; i < qinfos->r_qnum; i++) {
        urpc_qcfg_get_t qcfg_get = {0};
        (void)urpc_queue_cfg_get(qinfos->r_qinfo[i].urpc_qh, &qcfg_get);
        if (qcfg_get.qid == g_urpc_perftest_client_recv_rqid.rqid[target_queue]) {
            g_urpc_perftest_ctx.r_qh = qinfos->r_qinfo[i].urpc_qh;
            is_find = true;
            break;
        }
    }
    free(qinfos);
    if (!is_find) {
        return -1;
    }
    return 0;
}

// channel资源 1. client需要创建 2. latency server需要创建
static void urpc_perftest_server_client_channel_uninit(perftest_framework_config_t *cfg)
{
    if (cfg->case_type != PERFTEST_CASE_LAT && cfg->instance_mode == SERVER) {
        return;
    }
    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    (void)urpc_channel_queue_rm(g_urpc_perftest_ctx.chid, g_urpc_perftest_ctx.qhs[0], attr, &queue_option);
    (void)urpc_channel_destroy(g_urpc_perftest_ctx.chid);
}

static int urpc_perftest_server_client_channel_init(perftest_framework_config_t *cfg)
{
    if (cfg->case_type != PERFTEST_CASE_LAT && cfg->instance_mode == SERVER) {
        return 0;
    }

    g_urpc_perftest_ctx.chid = urpc_channel_create();
    if (g_urpc_perftest_ctx.chid == URPC_U32_FAIL) {
        return -1;
    }
    if (urpc_perftest_server_client_channel_attach(cfg, g_urpc_perftest_ctx.chid) != 0) {
        urpc_perftest_server_client_channel_uninit(cfg);
        return -1;
    }

    urpc_channel_connect_option_t queue_option = {0};
    queue_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE;
    urpc_channel_queue_attr_t attr = {.type = CHANNEL_QUEUE_TYPE_LOCAL};
    // local queue 0 for urpc_func_call
    if (urpc_channel_queue_add(g_urpc_perftest_ctx.chid, g_urpc_perftest_ctx.qhs[0], attr, &queue_option) != 0) {
        (void)urpc_channel_destroy(g_urpc_perftest_ctx.chid);
        return -1;
    }

    if (urpc_perftest_server_client_remote_queue_add(cfg, g_urpc_perftest_ctx.chid) != 0) {
        urpc_perftest_server_client_channel_uninit(cfg);
        return -1;
    }

    urpc_channel_connect_option_t channel_option = {0};
    channel_option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_CTRL_MSG;

    remote_qid_t queue_info = {
        .num = 0,
    };
    urpc_ctrl_msg_t ctl_msg = {
        .user_ctx = NULL,
        .msg = (char *)(uintptr_t)&queue_info,
        .msg_size = (uint32_t)sizeof(remote_qid_t),
        .msg_max_size = CTRL_MSG_MAX_SIZE,
    };

    channel_option.ctrl_msg = &ctl_msg;
    if (urpc_channel_server_refresh(g_urpc_perftest_ctx.chid, &channel_option) != 0) {
        // even if failed, don't return
        LOG_PRINT("urpc_channel_server_refresh %s failed\n", cfg->remote_ip);
    }

    return 0;
}

static int urpc_perftest_server_set_fd_ops(void)
{
    int optval = 1;
    if (setsockopt(g_urpc_perftest_ctx.fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) != 0) {
        LOG_PRINT("set socket reuseport failed, %s\n", strerror(errno));
        return -1;
    }

    // set accept non-block
    int fd_flags = fcntl(g_urpc_perftest_ctx.fd, F_GETFL, 0);
    if (fd_flags == -1) {
        LOG_PRINT("get socket fcntl flags failed, %s\n", strerror(errno));
        return -1;
    }

    if (fcntl(g_urpc_perftest_ctx.fd, F_SETFL, ((uint32_t)fd_flags) | O_NONBLOCK) == -1) {
        LOG_PRINT("set socket non-bolck failed, %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int urpc_perftest_server_do_accept(void)
{
    struct sockaddr_in addr;
    socklen_t len = (socklen_t)sizeof(addr);

    do {
        g_urpc_perftest_ctx.accept_fd = accept(g_urpc_perftest_ctx.fd, (struct sockaddr *)(void *)&addr, &len);
        if (g_urpc_perftest_ctx.accept_fd >= 0) {
            break;
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            LOG_PRINT("accept socket failed, %s\n", strerror(errno));
            break;
        }

        usleep(URPC_PERFTEST_ACCEPT_WAIT_US);
    } while (!g_urpc_perftest_ctx.force_quit);

    if (g_urpc_perftest_ctx.accept_fd < 0) {
        return -1;
    }

    return 0;
}

// server wait for "sync" and send "ack", only latency test need sync
static int urpc_perftest_server_wait_sync(perftest_framework_config_t *cfg)
{
    if (cfg->case_type != PERFTEST_CASE_LAT) {
        return 0;
    }

    g_urpc_perftest_ctx.fd = socket(AF_INET, (int)SOCK_STREAM, IPPROTO_TCP);
    if (g_urpc_perftest_ctx.fd < 0) {
        LOG_PRINT("create socket failed, %s\n", strerror(errno));
        return -1;
    }

    if (urpc_perftest_server_set_fd_ops() != 0) {
        goto CLOSE_LISTEN_FD;
    }

    struct sockaddr_in addr;
    socklen_t len = (socklen_t)sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->tcp_port + 1); // temporary use tcp_port + 1
    if (inet_pton(AF_INET, cfg->local_ip, &addr.sin_addr) != 1) {
        LOG_PRINT("format server ip %s failed\n", cfg->local_ip);
        goto CLOSE_LISTEN_FD;
    }

    if (bind(g_urpc_perftest_ctx.fd, (struct sockaddr *)(void *)&addr, len) < 0) {
        LOG_PRINT("bind socket failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    if (listen(g_urpc_perftest_ctx.fd, 1) < 0) {
        LOG_PRINT("listen socket failed, %s\n", strerror(errno));
        goto CLOSE_LISTEN_FD;
    }

    if (urpc_perftest_server_do_accept() != 0) {
        goto CLOSE_LISTEN_FD;
    }

    char msg[URPC_PERFTEST_SYNC_MSG_SIZE] = {0};
    int msg_len = recv(g_urpc_perftest_ctx.accept_fd, msg, URPC_PERFTEST_SYNC_MSG_SIZE, MSG_NOSIGNAL);
    if (msg_len != (int)strlen(URPC_PERFTEST_SYN) || memcmp(msg, URPC_PERFTEST_SYN, msg_len) != 0) {
        LOG_PRINT("recv syn failed, msg %s, %s\n", msg, strerror(errno));
        goto CLOSE_ACCEPT_FD;
    }

    return 0;

CLOSE_ACCEPT_FD:
    (void)close(g_urpc_perftest_ctx.accept_fd);

CLOSE_LISTEN_FD:
    (void)close(g_urpc_perftest_ctx.fd);

    return -1;
}

static int urpc_perftest_server_send_ack(perftest_framework_config_t *cfg)
{
    int ret = 0;
    if (cfg->case_type != PERFTEST_CASE_LAT) {
        return 0;
    }

    int msg_len = send(g_urpc_perftest_ctx.accept_fd, URPC_PERFTEST_ACK, strlen(URPC_PERFTEST_ACK), MSG_NOSIGNAL);
    if (msg_len != (int)strlen(URPC_PERFTEST_ACK)) {
        LOG_PRINT("send ack failed, %s\n", strerror(errno));
        ret = -1;
    } else {
        LOG_PRINT("server sync success\n");
    }

    (void)close(g_urpc_perftest_ctx.accept_fd);
    (void)close(g_urpc_perftest_ctx.fd);

    return ret;
}

// client send "sync" and wait for "ack", only latency test need sync
static int urpc_perftest_client_wait_ack(perftest_framework_config_t *cfg)
{
    if (cfg->case_type != PERFTEST_CASE_LAT) {
        return 0;
    }

    int ret = -1;
    g_urpc_perftest_ctx.fd = socket(AF_INET, (int)SOCK_STREAM, IPPROTO_TCP);
    if (g_urpc_perftest_ctx.fd < 0) {
        LOG_PRINT("create socket failed, %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    socklen_t len = (socklen_t)sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->tcp_port + 1); // temporary use tcp_port + 1
    if (inet_pton(AF_INET, cfg->remote_ip, &addr.sin_addr) != 1) {
        LOG_PRINT("format server ip %s failed\n", cfg->remote_ip);
        goto CLOSE_FD;
    }

    if (connect(g_urpc_perftest_ctx.fd, (struct sockaddr *)(void *)&addr, len) < 0) {
        LOG_PRINT("connect to server failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    char msg[URPC_PERFTEST_SYNC_MSG_SIZE] = {0};
    int msg_len = send(g_urpc_perftest_ctx.fd, URPC_PERFTEST_SYN, strlen(URPC_PERFTEST_SYN), MSG_NOSIGNAL);
    if (msg_len != (int)strlen(URPC_PERFTEST_SYN)) {
        LOG_PRINT("send syn failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    msg_len = recv(g_urpc_perftest_ctx.fd, msg, URPC_PERFTEST_SYNC_MSG_SIZE, MSG_NOSIGNAL);
    if (msg_len != (int)strlen(URPC_PERFTEST_ACK) || memcmp(msg, URPC_PERFTEST_ACK, msg_len) != 0) {
        LOG_PRINT("recv ack failed, msg %s, %s\n", msg, strerror(errno));
        goto CLOSE_FD;
    }

    LOG_PRINT("client sync success\n");

    ret = 0;

CLOSE_FD:
    (void)close(g_urpc_perftest_ctx.fd);

    return ret;
}

static int chanel_queue_pair(perftest_framework_config_t *cfg)
{
    uint32_t chid = g_urpc_perftest_ctx.chid;
    urpc_channel_qinfos_t *qinfo = (urpc_channel_qinfos_t *)calloc(1, sizeof(urpc_channel_qinfos_t));
    if (qinfo == NULL) {
        LOG_PRINT("malloc qinfos failed\n");
        return -1;
    }

    if (urpc_channel_queue_query(chid, qinfo) != 0) {
        LOG_PRINT("urpc_channel_queue_query failed\n");
        free(qinfo);
        return -1;
    };

    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = -1;

    int task;
    for (uint32_t i = 0; i < qinfo->l_qnum && i < qinfo->r_qnum; i++) {
        task = urpc_channel_queue_pair(chid, qinfo->l_qinfo[i].urpc_qh, qinfo->r_qinfo[i].urpc_qh, &option);
        LOG_PRINT("pair queue task: %d\n", task);
        urpc_channel_task_cancel(chid, task);
    }

    return URPC_SUCCESS;
}

static void chanel_queue_unpair(perftest_framework_config_t *cfg)
{
    uint32_t chid = g_urpc_perftest_ctx.chid;
    urpc_channel_qinfos_t *qinfo = (urpc_channel_qinfos_t *)calloc(1, sizeof(urpc_channel_qinfos_t));
    if (qinfo == NULL) {
        LOG_PRINT("malloc qinfos failed\n");
        return;
    }

    if (urpc_channel_queue_query(chid, qinfo) != 0) {
        LOG_PRINT("urpc_channel_queue_query failed\n");
        free(qinfo);
        return;
    };

    urpc_channel_connect_option_t option = {0};
    option.flag = URPC_CHANNEL_CONN_FLAG_FEATURE | URPC_CHANNEL_CONN_FLAG_TIMEOUT;
    option.timeout = -1;
    for (uint32_t i = 0; i < qinfo->l_qnum && i < qinfo->r_qnum; i++) {
        int task = urpc_channel_queue_unpair(chid, qinfo->l_qinfo[i].urpc_qh, qinfo->r_qinfo[i].urpc_qh, &option);
        LOG_PRINT("unpair queue task: %d\n", task);
        urpc_channel_task_cancel(chid, task);
    }
}

static int post_one_queue_rx(uint64_t qh, uint32_t num, uint32_t buf_size, bool wait_bind)
{
    uint32_t post_num = 0;
    int ret = URPC_SUCCESS;
    urpc_allocator_t *allocator = urpc_perftest_allocator_get();
    while (post_num < num) {
        urpc_sge_t *sges;
        uint32_t sge_num = 0;
        if ((allocator->get(&sges, &sge_num, buf_size, NULL) != 0)) {
            LOG_PRINT("get sges failed\n");
            return URPC_FAIL;
        }

        ret = urpc_queue_rx_post(qh, sges, sge_num);
        if (ret != URPC_SUCCESS) {
            allocator->put(sges, sge_num, NULL);
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

static void post_queue_rx(perftest_framework_config_t *cfg)
{
    uint32_t q_num = g_urpc_perftest_ctx.q_num;
    uint32_t post_num = cfg->rx_depth;
    uint32_t buf_size = get_rx_buf_size(cfg->size, cfg->size_len);
    for (uint32_t i = 0; i < q_num; i++) {
        (void)post_one_queue_rx(g_urpc_perftest_ctx.qhs[i], post_num, buf_size, true);
    }
}

// server thread ready之后再执行urpc_server_start
static int urpc_perftest_run_server(perftest_framework_config_t *cfg)
{
    int ret = -1;
    if (urpc_perftest_server_client_init(cfg) != 0) {
        return -1;
    }

    if (urpc_perftest_allocator_init(cfg->thread_num, cfg->size, cfg->size_len,
        get_q_num(cfg) * (cfg->rx_depth + URPC_PERFTEST_DEPTH_MARGIN), cfg->alloc_buf, cfg->align) != 0) {
        goto URPC_UNINIT;
    }

    if (urpc_perftest_init_queue_handles(cfg) != 0) {
        goto ALLOCATOR_UNINIT;
    }

    ret = urpc_perftest_server_client_start(cfg);
    if (ret != URPC_SUCCESS) {
        goto QUEUE_HANDLE_UNINIT;
    }

    if (urpc_perftest_server_wait_sync(cfg) != 0) {
        goto QUEUE_HANDLE_UNINIT;
    }

    if (urpc_perftest_server_client_channel_init(cfg) != 0) {
        goto QUEUE_HANDLE_UNINIT;
    }

    // server workers should be ready for recv as soon as possible
    if (urpc_perftest_start_workers(cfg) != 0) {
        goto QUEUE_HANDLE_UNINIT;
    }

    if (urpc_perftest_server_send_ack(cfg) != 0) {
        goto WORKERS_UNINIT;
    }

    post_queue_rx(cfg);

    urpc_perftest_run(cfg);

WORKERS_UNINIT:
    urpc_perftest_stop_workers();

QUEUE_HANDLE_UNINIT:
    urpc_perftest_queue_handles_uninit();

ALLOCATOR_UNINIT:
    urpc_perftest_allocator_uninit();

URPC_UNINIT:
    urpc_uninit();

    return ret;
}

static int urpc_perftest_run_client(perftest_framework_config_t *cfg)
{
    int ret = -1;
    if (urpc_perftest_server_client_init(cfg) != 0) {
        return -1;
    }

    if (urpc_perftest_allocator_init(cfg->thread_num, cfg->size, cfg->size_len,
        get_q_num(cfg) * (cfg->rx_depth + URPC_PERFTEST_DEPTH_MARGIN), cfg->alloc_buf, cfg->align) != 0) {
        goto URPC_UNINIT;
    }

    if (urpc_perftest_init_queue_handles(cfg) != 0) {
        goto ALLOCATOR_UNINIT;
    }

    if (urpc_perftest_server_client_channel_init(cfg) != 0) {
        goto QUEUE_HANDLE_UNINIT;
    }

    if (chanel_queue_pair(cfg) != 0) {
        goto CHANNEL_UNINIT;
    }

    ret = urpc_perftest_server_client_start(cfg);
    if (ret != URPC_SUCCESS) {
        goto QUEUE_UNPAIR;
    }

    if (urpc_perftest_client_wait_ack(cfg) != 0) {
        goto QUEUE_UNPAIR;
    }

    post_queue_rx(cfg);

    // client workers should be ready for send the later the better
    if (urpc_perftest_start_workers(cfg) != 0) {
        goto QUEUE_UNPAIR;
    }

    ret = 0;
    urpc_perftest_run(cfg);

    urpc_perftest_stop_workers();

QUEUE_UNPAIR:
    chanel_queue_unpair(cfg);

CHANNEL_UNINIT:
    urpc_perftest_server_client_channel_uninit(cfg);

QUEUE_HANDLE_UNINIT:
    urpc_perftest_queue_handles_uninit();

ALLOCATOR_UNINIT:
    urpc_perftest_allocator_uninit();

URPC_UNINIT:
    urpc_uninit();

    return ret;
}

int main(int argc, char *argv[])
{
    init_signal_handler();

    perftest_framework_config_t cfg = {0};
    if (urpc_perftest_parse_arguments(argc, argv, &cfg) != 0) {
        return -1;
    }
    (void)urpc_ctrl_msg_cb_register(ctrl_msg_callback);
    int ret;
    if (cfg.instance_mode == SERVER) {
        ret = urpc_perftest_run_server(&cfg);
    } else {
        ret = urpc_perftest_run_client(&cfg);
    }

    LOG_PRINT("urpc perftest finished\n");

    return ret;
}
