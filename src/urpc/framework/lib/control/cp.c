/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize control plane function
 */

#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <limits.h>

#include "notify.h"
#include "async_event.h"
#include "channel.h"
#include "client_manage_channel.h"
#include "dfx.h"
#include "dp.h"
#include "func.h"
#include "ip_handshaker.h"
#include "keepalive.h"
#include "queue.h"
#include "resource_release.h"
#include "server_manage_channel.h"
#include "state.h"
#include "task_manager.h"
#include "unix_server.h"
#include "urpc_framework_api.h"
#include "urpc_dbuf_stat.h"
#include "urpc_epoll.h"
#include "urpc_lib_log.h"
#include "urpc_manage.h"
#include "urpc_thread.h"
#include "urpc_timer.h"

#include "cp.h"

#define KEEPALIVE_TIME_INTERVAL_MAX 3600 // s
#define URPC_MANAGE_QUEUE_DEFAULT_DEPTH 128
#define URPC_CLIENT_HANDSHAKE_TIMEOUT 30000 // ms
#define KEEPALIVE_MAX_PROB_CNT 127
static urpc_ctx_t g_urpc_ctx = {0};

static urpc_ctrl_cb_t g_urpc_ctrl_msg_cb = NULL;
static urpc_ext_channel_create_cb_t g_ext_channel_create_cb = NULL;
static urpc_ext_channel_destroy_cb_t g_ext_channel_destroy_cb = NULL;

static inline bool urpc_check_not_ready(void)
{
    return URPC_UNLIKELY(urpc_state_get() != URPC_STATE_INIT);
}

void urpc_register_ext_channel_op_func(urpc_ext_channel_create_cb_t create, urpc_ext_channel_destroy_cb_t destroy)
{
    g_ext_channel_create_cb = create;
    g_ext_channel_destroy_cb = destroy;
}

static int urpc_pre_thread_start_callback(void *args)
{
    if (task_manager_init() != URPC_SUCCESS) {
        return URPC_FAIL;
    }
    if (transport_init() != URPC_SUCCESS) {
        goto TASK_MANAGER_UNINIT;
    }

    return URPC_SUCCESS;

TASK_MANAGER_UNINIT:
    task_manager_uninit();

    return URPC_FAIL;
}

static void urpc_post_thread_end_callback(void *args)
{
    transport_uninit();
    task_manager_uninit();
}

static int pre_dp_start_callback(void)
{
    default_allocator_cfg_t cfg = {
        .need_large_sge = false,
        .large_sge_size = DEFAULT_LARGE_SGE_SIZE,
    };
    // g_urpc_ctx.feature already set in check_set_cfg
    if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        cfg.need_large_sge = true;
    }
    if (urpc_default_allocator_init(&cfg) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init default allocator buf failed\n");
        return URPC_FAIL;
    }

    if (is_feature_enable(URPC_TIMER_FEATURE_FLAG)) {
        if (urpc_timing_wheel_init() != URPC_SUCCESS) {
            goto UNINIT_ALLOCATOR;
        }
    }

    if (is_feature_enable(URPC_FEATURE_TIMEOUT) && urpc_notify_table_init() != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("msg table init fialed\n");
        goto UNINIT_TIMER;
    }

    if (is_feature_enable(URPC_FEATURE_KEEPALIVE) && urpc_keepalive_init(&g_urpc_ctx.keepalive_cfg) != URPC_SUCCESS) {
        goto UNINIT_MSG_TABLE;
    }
    urpc_manage_callback_register(urpc_pre_thread_start_callback, urpc_post_thread_end_callback,
        URPC_MANAGE_JOB_TYPE_LISTEN);
    if (urpc_manage_init() != URPC_SUCCESS) {
        goto UNINIT_KA;
    }

    return URPC_SUCCESS;

UNINIT_KA:
    if (is_feature_enable(URPC_FEATURE_KEEPALIVE)) {
        urpc_keepalive_uninit();
    }

UNINIT_MSG_TABLE:
    if (is_feature_enable(URPC_FEATURE_TIMEOUT)) {
        urpc_notify_table_uninit();
    }
UNINIT_TIMER:
    if (is_feature_enable(URPC_TIMER_FEATURE_FLAG)) {
        urpc_timing_wheel_uninit();
    }

UNINIT_ALLOCATOR:
    urpc_default_allocator_uninit();

    return URPC_FAIL;
}

static void post_dp_end_callback(void)
{
    // resource need to force clear first
    urpc_resource_release_clear();

    urpc_manage_uninit();

    if (is_feature_enable(URPC_FEATURE_TIMEOUT) != 0) {
        urpc_notify_table_uninit();
    }

    if (is_feature_enable(URPC_FEATURE_KEEPALIVE) != 0) {
        urpc_keepalive_uninit();
    }

    urpc_default_allocator_uninit();
}

static inline bool is_cfg_timeout(urpc_config_t *cfg)
{
    return (cfg->feature & URPC_TIMER_FEATURE_FLAG) != 0;
}

static int check_set_cfg(urpc_config_t *cfg)
{
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("config is null\n");
        return -URPC_ERR_EINVAL;
    }

    if (cfg->role >= URPC_ROLE_MAX) {
        URPC_LIB_LOG_ERR("config role(%d) error\n", (int)cfg->role);
        return -URPC_ERR_EINVAL;
    }

    /* uRPC supports multi-eid only when URPC_FEATURE_MULTI_EID is enabled */
    if (cfg->trans_info_num == 0 || ((cfg->feature & URPC_FEATURE_MULTI_EID) == 0 && cfg->trans_info_num != 1)) {
        URPC_LIB_LOG_ERR("the number of transmission information(%u) is invalid\n", cfg->trans_info_num);
        return -URPC_ERR_EINVAL;
    }

    for (uint8_t i = 0; i < cfg->trans_info_num; i++) {
        /* uRPC supports multi-eid only when DEV_ASSIGN_MODE_DEV assign mode is used to set all trans_info */
        if ((cfg->feature & URPC_FEATURE_MULTI_EID) != 0 && cfg->trans_info[i].assign_mode != DEV_ASSIGN_MODE_DEV) {
            URPC_LIB_LOG_ERR("multi-eid feature should initialize transmission information by device assign mode\n");
            return -URPC_ERR_EINVAL;
        }
    }

    g_urpc_ctx.role = cfg->role;
    /* Only the features that can be used in all modes are assigned values here.
     * Others:
     * (1) server mode only, defined in 'urpc_server_init()'/'urpc_server_uninit()';
     * (2) client mode only, defined in 'urpc_client_init()'/'urpc_client_uninit()';
     * (3) server client mode only, defined in 'urpc_server_client_init()'/'urpc_server_client_uninit()'; */
    g_urpc_ctx.feature =
        (cfg->feature & (URPC_FEATURE_HWUB_OFFLOAD | URPC_FEATURE_TIMEOUT |
        URPC_FEATURE_DISABLE_TOKEN_POLICY | URPC_FEATURE_DISABLE_STATS | URPC_FEATURE_KEEPALIVE |
        URPC_FEATURE_MULTI_EID | URPC_FEATURE_MULTIPLEX));

    if ((g_urpc_ctx.feature & URPC_FEATURE_DISABLE_STATS) != 0) {
        queue_stats_disable();
        urpc_dbuf_stat_record_disable();
    } else {
        queue_stats_enable();
        urpc_dbuf_stat_record_enable();
    }

    return URPC_SUCCESS;
}

static void urpc_server_uninit(void)
{
    if (urpc_role_get() == URPC_ROLE_CLIENT) {
        return;
    }

    server_manage_channel_uninit();

    ip_handshaker_uninit();
    for (uint32_t i = 0; i < URPC_SERVER_MAX_CHANNELS; i++) {
        (void)server_channel_free(i, false);
    }
    urpc_server_channel_id_allocator_uninit();
    urpc_func_uninit();
}

static int server_keepalive_cfg_init(urpc_config_t *cfg)
{
    if ((cfg->feature & URPC_FEATURE_KEEPALIVE) != 0) {
        if (cfg->keepalive_cfg.keepalive_callback == NULL || cfg->keepalive_cfg.keepalive_cycle_time == 0 ||
            cfg->keepalive_cfg.keepalive_check_time < cfg->keepalive_cfg.keepalive_cycle_time ||
            cfg->keepalive_cfg.keepalive_check_time > KEEPALIVE_TIME_INTERVAL_MAX ||
            cfg->keepalive_cfg.keepalive_check_time / cfg->keepalive_cfg.keepalive_cycle_time >
            KEEPALIVE_MAX_PROB_CNT || cfg->keepalive_cfg.delay_release_time > KEEPALIVE_TIME_INTERVAL_MAX) {
            URPC_LIB_LOG_ERR("invalid keepalive config, check_time divide by cycle_time cannot exceed %d.\n",
                KEEPALIVE_MAX_PROB_CNT);
            return URPC_FAIL;
        }
        g_urpc_ctx.feature |= URPC_FEATURE_KEEPALIVE;
        g_urpc_ctx.keepalive_cfg = cfg->keepalive_cfg;
        // ensure q_depth is valid in [1, 128]
        g_urpc_ctx.keepalive_cfg.q_depth =
            (cfg->keepalive_cfg.q_depth == 0 || cfg->keepalive_cfg.q_depth > URPC_MANAGE_QUEUE_DEFAULT_DEPTH)
                ? URPC_MANAGE_QUEUE_DEFAULT_DEPTH : cfg->keepalive_cfg.q_depth;
    } else {
        URPC_LIB_LOG_INFO("keepalive feature disable\n");
    }
    return URPC_SUCCESS;
}

static void func_cfg_init(urpc_config_t *cfg)
{
    if ((cfg->feature & URPC_FEATURE_GET_FUNC_INFO) != 0) {
        g_urpc_ctx.feature |= URPC_FEATURE_GET_FUNC_INFO;
    }
}

static int urpc_server_init(urpc_config_t *cfg)
{
    if (cfg->role == URPC_ROLE_CLIENT) {
        return URPC_SUCCESS;
    }

    if (server_keepalive_cfg_init(cfg) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    func_cfg_init(cfg);

    g_urpc_ctx.device_class = cfg->device_class;
    g_urpc_ctx.sub_class = cfg->sub_class;
    int ret = urpc_server_channel_id_allocator_init();
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init server channel id allocator failed, ret:%d\n", ret);
        goto UNINIT_MANAGE_CHANNEL;
    }
    return URPC_SUCCESS;
UNINIT_MANAGE_CHANNEL:
    server_manage_channel_uninit();
    return URPC_FAIL;
}

static void urpc_client_uninit(void)
{
    if (urpc_role_get() == URPC_ROLE_SERVER) {
        return;
    }

    client_manage_channel_uninit();
    urpc_client_channel_id_allocator_uninit();
}

static int client_keepalive_cfg_init(urpc_config_t *cfg)
{
    if ((cfg->feature & URPC_FEATURE_KEEPALIVE) != 0) {
        if (cfg->keepalive_cfg.keepalive_cycle_time == 0 ||
            cfg->keepalive_cfg.keepalive_cycle_time > KEEPALIVE_TIME_INTERVAL_MAX ||
            cfg->keepalive_cfg.keepalive_check_time < cfg->keepalive_cfg.keepalive_cycle_time ||
            cfg->keepalive_cfg.keepalive_check_time > KEEPALIVE_TIME_INTERVAL_MAX ||
            cfg->keepalive_cfg.keepalive_check_time / cfg->keepalive_cfg.keepalive_cycle_time >
            KEEPALIVE_MAX_PROB_CNT || cfg->keepalive_cfg.delay_release_time > KEEPALIVE_TIME_INTERVAL_MAX) {
            URPC_LIB_LOG_ERR("invalid keepalive config, check_time divide by cycle_time cannot exceed %d.\n",
                KEEPALIVE_MAX_PROB_CNT);
            return URPC_FAIL;
        }

        g_urpc_ctx.feature |= URPC_FEATURE_KEEPALIVE;
        g_urpc_ctx.keepalive_cfg = cfg->keepalive_cfg;
        // ensure q_depth is valid in [1, 128]
        g_urpc_ctx.keepalive_cfg.q_depth =
            (cfg->keepalive_cfg.q_depth == 0 || cfg->keepalive_cfg.q_depth > URPC_MANAGE_QUEUE_DEFAULT_DEPTH)
                ? URPC_MANAGE_QUEUE_DEFAULT_DEPTH : cfg->keepalive_cfg.q_depth;
    }
    return URPC_SUCCESS;
}

static int urpc_client_init(urpc_config_t *cfg)
{
    if (cfg->role == URPC_ROLE_SERVER) {
        return URPC_SUCCESS;
    }

    if (client_keepalive_cfg_init(cfg) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    func_cfg_init(cfg);

    if (client_manage_channel_init() != 0) {
        return URPC_FAIL;
    }

    int ret = urpc_client_channel_id_allocator_init();
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("init client channel id allocator failed, ret:%d\n", ret);
        goto UNINIT_MANAGE_CHANNEL;
    }

    return URPC_SUCCESS;

UNINIT_MANAGE_CHANNEL:
    client_manage_channel_uninit();

    return URPC_FAIL;
}

static void urpc_server_client_uninit(void)
{}

static int urpc_server_client_init(urpc_config_t *cfg)
{
    if (cfg->role != URPC_ROLE_SERVER_CLIENT) {
        return URPC_SUCCESS;
    }

    if (server_keepalive_cfg_init(cfg) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    func_cfg_init(cfg);

    return URPC_SUCCESS;
}

static int dfx_init(urpc_config_t *cfg)
{
    // if unix_domain_file_path is not set, don't support dfx cmds
    if (cfg->unix_domain_file_path == NULL) {
        URPC_LIB_LOG_NOTICE("unix server is not initialized, unix cmds are unavailable\n");
        return URPC_SUCCESS;
    }

    int ret = unix_server_init(cfg->unix_domain_file_path);
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    ret = urpc_dfx_init();
    if (ret != URPC_SUCCESS) {
        unix_server_uninit();
        return ret;
    }

    return URPC_SUCCESS;
}

static void dfx_uninit(void)
{
    urpc_dfx_uninit();
    unix_server_uninit();
}

int urpc_init(urpc_config_t *cfg)
{
    URPC_LIB_LOG_INFO("urpc init start\n");
    (void)signal(SIGPIPE, SIG_IGN);

    if (urpc_state_get() != URPC_STATE_UNINIT) {
        URPC_LIB_LOG_ERR("urpc is already initialized\n");
        return -URPC_ERR_EPERM;
    }

    int ret = check_set_cfg(cfg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("urpc configure is invalid, ret:%d\n", ret);
        return ret;
    }

    ret = async_event_ctx_init();
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    ret = urpc_thread_ctx_init();
    if (ret != URPC_SUCCESS) {
        goto EVENT_CTX_UNINT;
    }

    ret = dfx_init(cfg);
    if (ret != URPC_SUCCESS) {
        goto THREAD_UNINIT;
    }

    ret = urpc_resource_release_init();
    if (ret != URPC_SUCCESS) {
        goto DFX_UNINIT;
    }

    ret = queue_id_allocator_init();
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("failed to init queue id allocator\n");
        goto RESOURCE_RELEASE_UNINIT;
    }

    provider_flag_t flag = { .bs.multi_eid = (cfg->feature & URPC_FEATURE_MULTI_EID) ? URPC_TRUE : URPC_FALSE};
    ret = provider_init(cfg->trans_info_num, cfg->trans_info, flag);
    if (ret == URPC_FAIL) {
        URPC_LIB_LOG_ERR("queue init failed, ret:%d\n", ret);
        goto QID_ALLOCATOR_UNINIT;
    }

    ret = urpc_server_client_init(cfg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("urpc server client init failed, ret:%d\n", ret);
        goto UNINIT_QUEUE;
    }

    ret = urpc_client_init(cfg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("urpc client init failed, ret:%d\n", ret);
        goto SERVER_CLIENT_UNINIT;
    }

    ret = urpc_server_init(cfg);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("urpc server init failed, ret:%d\n", ret);
        goto CLIENT_UNINIT;
    }

    state_callback_t cb = {
        .service_start_callback = pre_dp_start_callback,
        .service_end_callback = post_dp_end_callback
    };

    (void)urpc_state_set_callback(&cb);
    ret = urpc_state_update(URPC_STATE_INIT);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("urpc state update failed, ret:%d\n", ret);
        goto SERVER_UNINIT;
    }
    g_urpc_ctx.cfg = *cfg;
    URPC_LIB_LOG_INFO("urpc init successful\n");

    return URPC_SUCCESS;

SERVER_UNINIT:
    urpc_server_uninit();

CLIENT_UNINIT:
    urpc_client_uninit();

SERVER_CLIENT_UNINIT:
    urpc_server_client_uninit();

UNINIT_QUEUE:
    provider_uninit();

QID_ALLOCATOR_UNINIT:
    queue_id_allocator_uninit();

RESOURCE_RELEASE_UNINIT:
    urpc_resource_release_uninit();

DFX_UNINIT:
    dfx_uninit();

THREAD_UNINIT:
    urpc_thread_ctx_uninit();

EVENT_CTX_UNINT:
    async_event_ctx_uninit();

    return ret;
}

void urpc_uninit(void)
{
    urpc_state_t state = urpc_state_get();
    if (state == URPC_STATE_UNINIT) {
        URPC_LIB_LOG_ERR("urpc don't support uninit from state %d\n", state);
        return;
    }

    (void)urpc_state_update(URPC_STATE_UNINIT);

    /* The server should be called first to ensure that the listening thread is destroyed first. */
    urpc_server_uninit();
    urpc_client_uninit();
    urpc_server_client_uninit();
    provider_uninit();
    queue_id_allocator_uninit();
    urpc_resource_release_uninit();
    dfx_uninit();

    if (is_feature_enable(URPC_TIMER_FEATURE_FLAG)) {
        urpc_timing_wheel_uninit();
    }

    urpc_thread_ctx_uninit();
    async_event_ctx_uninit();
    (void)urpc_perf_recorder_unregister();

    memset(&g_urpc_ctx, 0, sizeof(g_urpc_ctx));
    URPC_LIB_LOG_INFO("urpc uninit successful\n");
}

static int check_cp_cfg(urpc_control_plane_config_t *cfg)
{
    // only support one listen address for now
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("invalid control plane config\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_server_info_t *server = &cfg->server;
    urpc_host_info_t server_host;
    switch (server->server_type) {
        case SERVER_TYPE_IPV4:
        case SERVER_TYPE_IPV6:
            parse_server_to_host(server, &server_host, NULL);
            if (ip_check_listen_cfg(&server_host) != URPC_SUCCESS) {
                return -URPC_ERR_EINVAL;
            }
            break;
        case SERVER_TYPE_UB:
        default:
            URPC_LIB_LOG_ERR(
                "listen configure for mode type %d is not supported currently(0: IP, 1: UB)\n", server->server_type);
            return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

int urpc_server_start(urpc_control_plane_config_t *cfg)
{
    if (urpc_state_get() == URPC_STATE_UNINIT) {
        URPC_LIB_LOG_ERR("urpc should be initialized first\n");
        return -URPC_ERR_EPERM;
    }

    if (!(urpc_role_get() == URPC_ROLE_SERVER || urpc_role_get() == URPC_ROLE_SERVER_CLIENT)) {
        URPC_LIB_LOG_ERR("error role: %u\n", (uint32_t)urpc_role_get());
        return -URPC_ERR_EPERM;
    }

    if (check_cp_cfg(cfg) != URPC_SUCCESS) {
        return -URPC_ERR_EINVAL;
    }

    if (cfg->server.server_type < SERVER_TYPE_UB) {
        urpc_host_info_t server_host;
        parse_server_to_host(&cfg->server, &server_host, NULL);
        if (ip_handshaker_init(&server_host, cfg->user_ctx) != URPC_SUCCESS) {
            return URPC_FAIL;
        }
    }
    URPC_LIB_LOG_INFO("urpc server start successful\n");

    return URPC_SUCCESS;
}

uint64_t queue_create(urpc_queue_trans_mode_t trans_mode, urpc_qcfg_create_t *cfg, uint16_t flag)
{
    queue_ops_t *ops = queue_get_ops(trans_mode);
    if (ops == NULL) {
        URPC_LIB_LOG_ERR("get queue ops failed\n");
        return URPC_INVALID_HANDLE;
    }

    uint32_t qid;
    int ret = queue_id_allocator_alloc(&qid);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("get queue id failed\n");
        return URPC_INVALID_HANDLE;
    }

    queue_create_option_t option = { 0 };
    option.cfg = cfg;
    option.type = QUEUE_TYPE_NORMAL;
    option.qid = qid;

    queue_t *q = ops->create_local_queue(&option, flag);
    if (q == NULL) {
        queue_id_allocator_free(qid);
        URPC_LIB_LOG_ERR("create local queue failed\n");
        return URPC_INVALID_HANDLE;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(q, queue_local_t, queue);
    if (queue_slab_init(local_q) != 0) {
        ops->delete_local_queue(q, NULL);
        queue_id_allocator_free(qid);
        return URPC_INVALID_HANDLE;
    }

    /* skip post rx when QCREATE_FLAG_SKIP_POST_RX have been set . */
    if ((cfg->create_flag & QCREATE_FLAG_SKIP_POST_RX) && (cfg->skip_post_rx)) {
        goto CREATE_FINISH;
    }

    if (is_feature_enable(URPC_FEATURE_TIMEOUT) && !is_manager_queue(q->flag) &&
        add_queue_notify_msg_table((uint64_t)(uintptr_t)q)) {
        queue_slab_uninit(local_q);
        ops->delete_local_queue(q, NULL);
        queue_id_allocator_free(qid);
        URPC_LIB_LOG_ERR("add queue notify msg info failed\n");
        return URPC_INVALID_HANDLE;
    }

    queue_read_cache_list_init(&local_q->rcache_list, DEFAULT_READ_CACHE_LIST_TIMEOUT_S);

CREATE_FINISH:
    URPC_LIB_LOG_INFO("urpc queue %u create successful\n", qid);

    return (uint64_t)(uintptr_t)q;
}

static bool check_share_queue_cfg(urpc_queue_mode_t mode, urpc_queue_trans_mode_t trans_mode, uint64_t urpc_qh)
{
    if (urpc_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("queue handle invalid\n");
        return false;
    }
    queue_t *l_queue = (queue_t *)(uintptr_t)urpc_qh;
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    return (local_q->queue.flag.is_remote != URPC_TRUE) && (local_q->cfg.trans_mode == trans_mode) &&
           (local_q->cfg.mode == mode);
}

static bool check_qh_cfg(urpc_qcfg_create_t *cfg, urpc_queue_trans_mode_t trans_mode)
{
    urpc_queue_mode_t mode = cfg->mode;
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) != 0 &&
        !check_share_queue_cfg(mode, trans_mode, cfg->urpc_qh_share_rq)) {
        return false;
    }
    if ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_TX_CQ) != 0 &&
        !check_share_queue_cfg(mode, trans_mode, cfg->urpc_qh_share_tx_cq)) {
        return false;
    }
    return true;
}

static bool check_create_queue_cfg(urpc_queue_trans_mode_t trans_mode, urpc_qcfg_create_t *cfg)
{
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("queue config is null\n");
        return false;
    }
    if ((cfg->create_flag & (QCREATE_FLAG_QH_SHARE_RQ | QCREATE_FLAG_QH_SHARE_TX_CQ)) == 0) {
        return true;
    }

    if (cfg->mode == QUEUE_MODE_INTERRUPT) {
        if (((cfg->create_flag & QCREATE_FLAG_QH_SHARE_RQ) != 0) &&
            ((cfg->create_flag & QCREATE_FLAG_QH_SHARE_TX_CQ) != 0)) {
            if ((cfg->urpc_qh_share_rq != cfg->urpc_qh_share_tx_cq)) {
                URPC_LIB_LOG_ERR("urpc_qh_share_rq and urpc_qh_share_tx_cq should use same qh in interrupt mode\n");
                return false;
            }
        }
    }

    // Check whether the qh settings are valid
    if (!check_qh_cfg(cfg, trans_mode)) {
        URPC_LIB_LOG_ERR("queue create cfg is inconsistent with shared queue handle\n");
        return false;
    }
    return true;
}

uint64_t urpc_queue_create(urpc_queue_trans_mode_t trans_mode, urpc_qcfg_create_t *cfg)
{
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("queue create failed, allocator is not registered or data path is not ready\n");
        return URPC_INVALID_HANDLE;
    }

    if (!check_create_queue_cfg(trans_mode, cfg)) {
        return URPC_INVALID_HANDLE;
    }

    return queue_create(trans_mode, cfg, 0);
}

void delete_local_queue_callback(queue_t *l_queue)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    if (is_feature_enable(URPC_FEATURE_TIMEOUT)) {
        rm_queue_notify_msg_table((uint64_t)(uintptr_t)l_queue);
    }
    queue_read_cache_list_uninit(&local_q->rcache_list);
}

int urpc_queue_destroy(uint64_t urpc_qh)
{
    if (urpc_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("queue handle invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)urpc_qh;
    if (l_queue->flag.is_remote == URPC_TRUE) {
        URPC_LIB_LOG_ERR("error type of local queue\n");
        return -URPC_ERR_EINVAL;
    }

    if (l_queue->ref_cnt != 0) {
        URPC_LIB_LIMIT_LOG_WARN("queue is still being added:%u\n", l_queue->ref_cnt);
        return -URPC_ERR_EBUSY;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    uint32_t qid = local_q->qid;
    int ret = l_queue->ops->delete_local_queue(l_queue, delete_local_queue_callback);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("delete local queue failed, ret:%d\n", ret);
        return ret;
    }

    queue_id_allocator_free(qid);
    URPC_LIB_LOG_INFO("destroy queue %u successful\n", qid);

    return URPC_SUCCESS;
}

static queue_t *urpc_local_queue_get(uint64_t urpc_qh)
{
    if (urpc_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("queue handle invalid\n");
        return NULL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)urpc_qh;
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    if (l_queue->flag.is_remote == URPC_TRUE || local_q->cfg.type != QUEUE_TYPE_NORMAL) {
        URPC_LIB_LOG_ERR("error type of local queue\n");
        return NULL;
    }

    return l_queue;
}

int urpc_queue_stats_get(uint64_t urpc_qh, uint64_t *stats, int stats_len)
{
    if (stats == NULL || stats_len <= 0) {
        URPC_LIB_LOG_ERR("stats array invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = urpc_local_queue_get(urpc_qh);
    if (l_queue == NULL) {
        return -URPC_ERR_EINVAL;
    }

    queue_stats_get(l_queue, stats, stats_len);

    return URPC_SUCCESS;
}

int urpc_queue_error_stats_get(uint64_t urpc_qh, uint64_t *stats, int stats_len)
{
    if (stats == NULL || stats_len <= 0) {
        URPC_LIB_LOG_ERR("stats array invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = urpc_local_queue_get(urpc_qh);
    if (l_queue == NULL) {
        URPC_LIB_LOG_ERR("error type of local queue\n");
        return -URPC_ERR_EINVAL;
    }

    queue_error_stats_get(l_queue, stats, stats_len);

    return URPC_SUCCESS;
}

int urpc_error_stats_get(uint64_t *stats, int stats_len)
{
    if (stats == NULL || stats_len <= 0) {
        URPC_LIB_LOG_ERR("stats array invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_common_error_stats_get(stats, stats_len);

    return URPC_SUCCESS;
}

const char *urpc_queue_stats_name_get(urpc_stats_type_t type)
{
    return queue_stats_name_get((int)type);
}

const char *urpc_queue_error_stats_name_get(urpc_error_stats_type_t type)
{
    return queue_error_stats_name_get((int)type);
}

int urpc_channel_destroy(uint32_t urpc_chid)
{
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_wrlock(&channel->rw_lock);
    if (channel->handshaking || !urpc_list_is_empty(&channel->task_ready_list)) {
        URPC_LIB_LOG_ERR("channel[%u] is busy\n", urpc_chid);
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        return -URPC_ERR_EBUSY;
    }

    if (g_ext_channel_destroy_cb != NULL) {
        g_ext_channel_destroy_cb(urpc_chid);
    }

    if (channel->manage_chid != URPC_INVALID_ID_U32) {
        server_node_t *cur_s_node;
        URPC_LIST_FOR_EACH(cur_s_node, node, &channel->server_nodes_list) {
            if (cur_s_node->cap.is_support_quik_reply) {
                continue;
            }
            (void)client_manage_channel_put(&cur_s_node->endpoints.server, channel->manage_chid, true, false);
        }
        channel->manage_chid = URPC_INVALID_ID_U32;
    }
    urpc_func_tbl_release(&channel->func_tbl);
    if (urpc_list_is_in_list(&channel->tcp_node)) {
        urpc_list_remove(&channel->tcp_node);
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    return channel_free(urpc_chid);
}

uint32_t urpc_channel_create(void)
{
    urpc_role_t role = urpc_role_get();
    if (role != URPC_ROLE_CLIENT && role != URPC_ROLE_SERVER_CLIENT) {
        URPC_LIB_LOG_ERR("only support in client mode\n");
        return URPC_U32_FAIL;
    }

    urpc_channel_info_t *info = channel_alloc();
    if (info == NULL) {
        URPC_LIB_LOG_ERR("malloc channel failed\n");
        return URPC_U32_FAIL;
    }

    if ((g_urpc_ctx.feature & URPC_FEATURE_MULTI_EID) == 0) {
        /* When the multiple-eid feature is enabled, the channel must be bound to the specified
         * provider before starting to import remote queues.
         * Otherwise, set the very one provider directly when creating a new channel. */
        info->provider = get_provider(NULL);
    }

    if (g_ext_channel_create_cb != NULL && g_ext_channel_create_cb(info->id) != URPC_SUCCESS) {
        channel_free(info->id);
        URPC_LIB_LOG_INFO("create channel call ext create cb failed\n");
        return URPC_U32_FAIL;
    }
    URPC_LIB_LOG_INFO("create channel[%u] successful\n", info->id);
    return info->id;
}

int urpc_channel_cfg_get(uint32_t urpc_chid, urpc_ccfg_get_t *cfg)
{
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("channel config is null\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_rdlock(&channel->rw_lock);
    cfg->l_max_qnum = MAX_QUEUE_SIZE;
    cfg->r_max_qnum = MAX_QUEUE_SIZE;
    cfg->attr = channel->attr;
    cfg->req_entry_size = channel->req_entry_size;
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    return URPC_SUCCESS;
}

static bool urpc_ctrl_msg_validate(urpc_ctrl_msg_t *ctrl_msg)
{
    if (ctrl_msg == NULL) {
        return true;
    }

    if ((ctrl_msg->msg == NULL && ctrl_msg->msg_size != 0) || (ctrl_msg->msg_size > ctrl_msg->msg_max_size)) {
        URPC_LIB_LOG_ERR(
            "ctrl_msg input parameter invalid, msg size %u, max size %u\n", ctrl_msg->msg_size, ctrl_msg->msg_max_size);
        return false;
    }

    if (ctrl_msg->msg_max_size > CTRL_MSG_MAX_SIZE) {
        URPC_LIB_LOG_ERR("ctrl_msg input size exceed %u\n", CTRL_MSG_MAX_SIZE);
        return false;
    }

    return true;
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

static void convert_host_info_to_server(urpc_endpoints_t *endpoints, urpc_server_info_t *server)
{
    if (endpoints->server.host_type == HOST_TYPE_IPV4) {
        server->server_type = SERVER_TYPE_IPV4;
        memcpy(server->ipv4.ip_addr, endpoints->server.ipv4.ip_addr, URPC_IPV4_SIZE);
        server->ipv4.port = endpoints->server.ipv4.port;
        if (endpoints->bind_local == URPC_TRUE) {
            server->assigned_addr.bind_local_addr_enabled = true;
            memcpy(server->assigned_addr.ipv4_addr, endpoints->local.ipv4.ip_addr, URPC_IPV4_SIZE);
            server->assigned_addr.port = endpoints->local.ipv4.port;
        } else {
            server->assigned_addr.bind_local_addr_enabled = false;
        }
    } else {
        server->server_type = SERVER_TYPE_IPV6;
        memcpy(server->ipv6.ip_addr, endpoints->server.ipv6.ip_addr, URPC_IPV6_SIZE);
        server->ipv6.port = endpoints->server.ipv6.port;
        if (endpoints->bind_local == URPC_TRUE) {
            server->assigned_addr.bind_local_addr_enabled = true;
            memcpy(server->assigned_addr.ipv6_addr, endpoints->local.ipv6.ip_addr, URPC_IPV6_SIZE);
            server->assigned_addr.port = endpoints->local.ipv6.port;
        } else {
            server->assigned_addr.bind_local_addr_enabled = false;
        }
    }
}

bool urpc_channel_connect_option_set(
    urpc_host_info_t *server, urpc_channel_connect_option_t *in, urpc_channel_connect_option_t *out)
{
    bool is_nonblock = false;
    if (in == NULL || in->flag == 0) {
        goto OUT;
    }

    if ((in->flag & URPC_CHANNEL_CONN_FLAG_FEATURE) != 0 && (in->feature & URPC_CHANNEL_CONN_FEATURE_NONBLOCK) != 0) {
        out->flag |= URPC_CHANNEL_CONN_FLAG_FEATURE;
        out->feature |= URPC_CHANNEL_CONN_FEATURE_NONBLOCK;
        is_nonblock = true;
    }

    if ((in->flag & URPC_CHANNEL_CONN_FLAG_CTX) != 0) {
        out->flag |= URPC_CHANNEL_CONN_FLAG_CTX;
        out->ctx = in->ctx;
    }

    if ((in->flag & URPC_CHANNEL_CONN_FLAG_CTRL_MSG) != 0) {
        if (((in->flag & URPC_CHANNEL_CONN_FLAG_CTRL_MSG) != 0) && !urpc_ctrl_msg_validate(in->ctrl_msg)) {
            return false;
        }

        out->flag |= URPC_CHANNEL_CONN_FLAG_CTRL_MSG;
        out->ctrl_msg = in->ctrl_msg;
    }

    if (server != NULL && (in->flag & URPC_CHANNEL_CONN_FLAG_BIND_LOCAL) != 0) {
        out->flag |= URPC_CHANNEL_CONN_FLAG_BIND_LOCAL;
        out->local = in->local;
    }
    // Non-blocking requires checking the timeout duration.
    if (is_nonblock && (in->flag & URPC_CHANNEL_CONN_FLAG_TIMEOUT) != 0) {
        if (in->timeout < -1 || in->timeout == 0) {
            URPC_LIB_LOG_ERR("timeout %d is invalid\n", in->timeout);
            return false;
        }

        out->flag |= URPC_CHANNEL_CONN_FLAG_TIMEOUT;
        out->timeout = in->timeout;
    }

OUT:
    // set default timeout
    if ((out->flag & URPC_CHANNEL_CONN_FLAG_TIMEOUT) == 0 || !is_nonblock) {
        out->flag |= URPC_CHANNEL_CONN_FLAG_TIMEOUT;
        out->timeout = URPC_CLIENT_HANDSHAKE_TIMEOUT;
    }

    return true;
}

static int ip_validate(urpc_host_info_t *server, urpc_channel_connect_option_t *option, socket_addr_t *server_addr)
{
    socklen_t len;
    if (server == NULL || server->host_type >= HOST_TYPE_UB ||
        urpc_socket_addr_format(server, server_addr, &len) != 0) {
        URPC_LIB_LOG_ERR("invalid server param\n");
        return -URPC_ERR_EINVAL;
    }
    socket_addr_t local_addr;
    if (option != NULL && (option->flag & URPC_CHANNEL_CONN_FLAG_BIND_LOCAL) != 0) {
        if (server->host_type != option->local.host_type ||
            urpc_socket_addr_format(&option->local, &local_addr, &len) != 0) {
            URPC_LIB_LOG_ERR("invalid bind local param\n");
            return -URPC_ERR_EINVAL;
        }
    }
    return URPC_SUCCESS;
}

int urpc_channel_server_attach(uint32_t urpc_chid, urpc_host_info_t *server, urpc_channel_connect_option_t *option)
{
    int ret = URPC_FAIL;
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }
    socket_addr_t server_addr;
    ret = ip_validate(server, option, &server_addr);
    if (ret != URPC_SUCCESS) {
        return ret;
    }
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(server, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(
            urpc_chid, URPC_ASYNC_EVENT_CHANNEL_ATTACH, QUEUE_ID_INVALID, QUEUE_ID_INVALID, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .server = server,
        .ctrl_msg = conn_ctx->conn_option.ctrl_msg,
        .callback_ctx = conn_ctx,
        .type = WORKFLOW_TYPE_CLIENT_ATTACH_SERVER,
        .tcp_addr = &server_addr,
    };

    if ((conn_ctx->conn_option.flag & URPC_CHANNEL_CONN_FLAG_BIND_LOCAL) != 0) {
        params.local = &conn_ctx->conn_option.local;
    }
    bool is_nonblock = conn_ctx->nonblock;
    // in non-blocking mode, the task and callback resource is released after the task is completed
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_channel_server_refresh(uint32_t urpc_chid, urpc_channel_connect_option_t *option)
{
    int ret = URPC_FAIL;
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(NULL, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(
            urpc_chid, URPC_ASYNC_EVENT_CHANNEL_REFRESH, QUEUE_ID_INVALID, QUEUE_ID_INVALID, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .ctrl_msg = conn_ctx->conn_option.ctrl_msg,
        .callback_ctx = conn_ctx,
        .type = WORKFLOW_TYPE_CLIENT_REFRESH_SERVER,
    };

    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_channel_server_detach(uint32_t urpc_chid, urpc_host_info_t *server, urpc_channel_connect_option_t *option)
{
    int ret = URPC_FAIL;
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    socket_addr_t server_addr;
    ret = ip_validate(server, option, &server_addr);
    if (ret != URPC_SUCCESS) {
        return ret;
    }
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(server, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(
            urpc_chid, URPC_ASYNC_EVENT_CHANNEL_DETACH, QUEUE_ID_INVALID, QUEUE_ID_INVALID, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .server = server,
        .ctrl_msg = conn_ctx->conn_option.ctrl_msg,
        .callback_ctx = conn_ctx,
        .type = WORKFLOW_TYPE_CLIENT_DETACH_SERVER,
        .tcp_addr = &server_addr,
    };
    if ((conn_ctx->conn_option.flag & URPC_CHANNEL_CONN_FLAG_BIND_LOCAL) != 0) {
        params.local = &conn_ctx->conn_option.local;
    }
    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_channel_queue_query(uint32_t urpc_chid, urpc_channel_qinfos_t *info)
{
    if (info == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return URPC_FAIL;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return URPC_FAIL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return URPC_FAIL;
    }

    channel_queue_query(channel, info);

    return URPC_SUCCESS;
}

int urpc_channel_cfg_set(uint32_t urpc_chid, urpc_ccfg_set_t *cfg)
{
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_wrlock(&channel->rw_lock);
    if ((cfg->set_flag & CHANNEL_CFG_SET_FLAG_REQ_ENTRY_SIZE) != 0) {
        if (channel->req_entry_table != NULL) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            URPC_LIB_LOG_ERR("req entry table is already initialized\n");
            return URPC_FAIL;
        }
        if (channel->req_entry_size != 0) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            URPC_LIB_LOG_ERR("req entry size was already set\n");
            return URPC_FAIL;
        }
        if (cfg->req_entry_size == 0 || cfg->req_entry_size > URPC_MAX_CHANNEL_REQ_ENTRY ||
            (cfg->req_entry_size & (cfg->req_entry_size - 1)) != 0) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            URPC_LIB_LOG_ERR("The value of req entry size invalid\n");
            return URPC_FAIL;
        }
        channel->req_entry_size = cfg->req_entry_size;
        URPC_LIB_LOG_INFO("channel[%u] req entry size set [%u] success\n", urpc_chid, cfg->req_entry_size);
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);

    return URPC_SUCCESS;
}

static int local_queue_is_valid(uint64_t urpc_qh)
{
    int ret = URPC_FAIL;
    if (urpc_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }
    queue_t *queue = (queue_t *)(uintptr_t)urpc_qh;
    if (queue->status > QUEUE_STATUS_READY || queue->status == QUEUE_STATUS_RESET) {
        URPC_LIB_LOG_ERR("queue status invalid: %d\n", queue->status);
        return ret;
    }
    if (queue->ref_cnt == UINT_MAX) {
        URPC_LIB_LOG_DEBUG("queue is added exceeds the threshold: %u\n", queue->ref_cnt);
        return ret;
    }
    return URPC_SUCCESS;
}

int urpc_channel_queue_add(
    uint32_t urpc_chid, uint64_t urpc_qh, urpc_channel_queue_attr_t attr, urpc_channel_connect_option_t *option)
{
    int ret = URPC_SUCCESS;
    uint64_t l_qh = URPC_INVALID_HANDLE;
    uint64_t r_qh = QUEUE_ID_INVALID;
    task_workflow_type_t type = WORKFLOW_TYPE_CHANNEL_ADD_REMOTE_QUEUE;

    if (attr.type != CHANNEL_QUEUE_TYPE_LOCAL && attr.type != CHANNEL_QUEUE_TYPE_REMOTE) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    if (attr.type == CHANNEL_QUEUE_TYPE_LOCAL) {
        l_qh = urpc_qh;
        ret = local_queue_is_valid(urpc_qh);
        type = WORKFLOW_TYPE_CHANNEL_ADD_LOCAL_QUEUE;
    } else {
        if (queue_id_is_invaild(urpc_qh)) {
            URPC_LIB_LOG_ERR("invalid qid\n");
            return -URPC_ERR_EINVAL;
        }
        r_qh = urpc_qh;
    }
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(NULL, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(urpc_chid, URPC_ASYNC_EVENT_CHANNEL_QUEUE_ADD, l_qh, r_qh, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .callback_ctx = conn_ctx,
        .urpc_qh = urpc_qh,
        .attr = attr,
        .type = type,
    };

    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_channel_queue_rm(
    uint32_t urpc_chid, uint64_t urpc_qh, urpc_channel_queue_attr_t attr, urpc_channel_connect_option_t *option)
{
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    int ret = URPC_SUCCESS;
    uint64_t l_qh = URPC_INVALID_HANDLE;
    uint64_t r_qh = QUEUE_ID_INVALID;
    task_workflow_type_t type = WORKFLOW_TYPE_CHANNEL_RM_REMOTE_QUEUE;

    if (attr.type != CHANNEL_QUEUE_TYPE_LOCAL && attr.type != CHANNEL_QUEUE_TYPE_REMOTE) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    if (attr.type == CHANNEL_QUEUE_TYPE_LOCAL) {
        if (urpc_qh == URPC_INVALID_HANDLE) {
            URPC_LIB_LOG_ERR("invalid params\n");
            return -URPC_ERR_EINVAL;
        }
        l_qh = urpc_qh;
        type = WORKFLOW_TYPE_CHANNEL_RM_LOCAL_QUEUE;
    } else {
        if (queue_id_is_invaild(urpc_qh)) {
            URPC_LIB_LOG_ERR("invalid qid\n");
            return -URPC_ERR_EINVAL;
        }
        r_qh = urpc_qh;
    }
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(NULL, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(urpc_chid, URPC_ASYNC_EVENT_CHANNEL_QUEUE_RM, l_qh, r_qh, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .callback_ctx = conn_ctx,
        .urpc_qh = urpc_qh,
        .attr = attr,
        .type = type,
    };

    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

bool check_queue_in_channel(urpc_channel_info_t *channel, uint64_t qh)
{
    queue_node_t *cur_node;
    struct queue_nodes_head *node_list =
        ((queue_t *)(uintptr_t)qh)->flag.is_remote ? &channel->r_queue_nodes_head : &channel->l_queue_nodes_head;
    URPC_SLIST_FOR_EACH(cur_node, node_list, node) {
        if (qh == cur_node->urpc_qh) {
            return true;
        }
    }

    URPC_LIB_LOG_ERR("find %s queue from channel[%d] failed\n",
        ((queue_t *)(uintptr_t)qh)->flag.is_remote ? "remote" : "local", channel->id);
    return false;
}

int urpc_channel_queue_pair(
    uint32_t urpc_chid, uint64_t local_qh, uint64_t remote_qh, urpc_channel_connect_option_t *option)
{
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    task_workflow_type_t type = WORKFLOW_TYPE_CHANNEL_PAIR_QUEUE;
    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    if (local_qh == URPC_INVALID_HANDLE || remote_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    queue_local_t *local_q = (queue_local_t *)(uintptr_t)local_qh;
    if (local_q->is_binded == URPC_TRUE) {
        URPC_LIB_LOG_ERR("local queue is already binded\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)local_qh;
    queue_t *r_queue = (queue_t *)(uintptr_t)remote_qh;
    if (l_queue->status != QUEUE_STATUS_READY || r_queue->status > QUEUE_STATUS_READY) {
        URPC_LIB_LOG_ERR("queue status: %d, %d invalid\n", l_queue->status, r_queue->status);
        return URPC_FAIL;
    }

    if (l_queue->flag.is_remote != URPC_FALSE && r_queue->flag.is_remote != URPC_TRUE) {
        URPC_LIB_LOG_ERR("invalid l_queue with flag %s, r_queue with flag %s\n",
                         l_queue->flag.is_remote ? "remote" : "local", r_queue->flag.is_remote ? "remote" : "local");
        return URPC_FAIL;
    }
    int ret = URPC_SUCCESS;
    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(NULL, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(urpc_chid, URPC_ASYNC_EVENT_CHANNEL_QUEUE_PAIR, local_qh, remote_qh, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .callback_ctx = conn_ctx,
        .type = type,
        .local_q = l_queue,
        .remote_q = r_queue,
    };

    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_channel_queue_unpair(
    uint32_t urpc_chid, uint64_t local_qh, uint64_t remote_qh, urpc_channel_connect_option_t *option)
{
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    urpc_channel_info_t *channel = channel_get(urpc_chid);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get channel[%u] failed\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }
    if (channel->attr == URPC_ATTR_MANAGE) {
        URPC_LIB_LOG_ERR("invalid channel[%u] type\n", urpc_chid);
        return -URPC_ERR_EINVAL;
    }

    if (local_qh == URPC_INVALID_HANDLE || remote_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("invalid params\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)local_qh;
    queue_t *r_queue = (queue_t *)(uintptr_t)remote_qh;
    if (l_queue->flag.is_remote != URPC_FALSE && r_queue->flag.is_remote != URPC_TRUE) {
        URPC_LIB_LOG_ERR("invalid l_queue with flag %s, r_queue with flag %s\n",
                         l_queue->flag.is_remote ? "remote" : "local", r_queue->flag.is_remote ? "remote" : "local");
        return -URPC_ERR_EINVAL;
    }

    int ret = URPC_SUCCESS;
    handshaker_callback_ctx_t *conn_ctx = task_engine_callback_construct(NULL, option);
    if (conn_ctx == NULL) {
        ret = -errno;
        return ret;
    }
    if (conn_ctx->nonblock) {
        task_engine_callback_event_set(urpc_chid, URPC_ASYNC_EVENT_CHANNEL_QUEUE_UNPAIR, local_qh, remote_qh, conn_ctx);
    }

    task_init_params_t params = {
        .channel = channel,
        .callback_ctx = conn_ctx,
        .type = WORKFLOW_TYPE_CHANNEL_UNPAIR_QUEUE,
        .local_q = l_queue,
        .remote_q = r_queue,
    };

    bool is_nonblock = conn_ctx->nonblock;
    int task_id = task_manager_client_task_create(channel, &params);
    if (task_id < 0) {
        task_engine_callback_destruct(conn_ctx);
        return task_id;
    }
    // in non-blocking mode, the task and callback resource is released after the task is completed
    // after task_manager_client_task_create func, the task may have already been completed, cannot use task resource
    if (is_nonblock) {
        return task_id;
    }
    // in blocking mode, the task resource is released after the task is completed
    sem_wait(&(conn_ctx->sem));
    ret = conn_ctx->result;
    task_engine_callback_destruct(conn_ctx);
    return ret;
}

int urpc_queue_cfg_get(uint64_t urpc_qh, urpc_qcfg_get_t *cfg)
{
    if (urpc_qh == URPC_INVALID_HANDLE || cfg == NULL) {
        URPC_LIB_LOG_ERR("queue handle or queue config invalid\n");
        return -URPC_ERR_EINVAL;
    }
    queue_t *queue = (queue_t *)(uintptr_t)urpc_qh;
    if (queue->flag.is_remote == URPC_FALSE) {
        queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
        memcpy(cfg, &local_q->cfg, sizeof(urpc_qcfg_get_t));
    } else {
        queue_remote_t *remote_q = CONTAINER_OF_FIELD(queue, queue_remote_t, queue);
        cfg->custom_flag = remote_q->cfg.custom_flag;
        cfg->rx_buf_size = remote_q->cfg.rx_buf_size;
        cfg->rx_depth = remote_q->cfg.rx_depth;
        /* remote jetty disorder queue and send_recv queue are both implemented by QUEUE_TRANS_MODE_JETTY ops.
         * Thus, the real trans mode is determined by qid. */
        cfg->trans_mode = remote_q->cfg.trans_mode;
        cfg->type = remote_q->cfg.type;
        cfg->qid = remote_q->qid;
        convert_host_info_to_server(&remote_q->cfg.server_node->endpoints, &cfg->info);
    }
    return URPC_SUCCESS;
}

int urpc_queue_cfg_set(uint64_t urpc_qh, urpc_qcfg_set_t *cfg)
{
    if (urpc_qh == URPC_INVALID_HANDLE || cfg == NULL) {
        URPC_LIB_LOG_ERR("queue handle or queue config invalid\n");
        return -URPC_ERR_EINVAL;
    }

    if ((cfg->set_flag & QCFG_SET_FLAG_PRIORITY) != 0) {
        URPC_LIB_LOG_ERR("not support config priority after create\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *q = (queue_t *)(uintptr_t)urpc_qh;
    if (q->flag.is_remote == URPC_TRUE) {
        URPC_LIB_LOG_ERR("remote queue not support config\n");
        return -URPC_ERR_EINVAL;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(q, queue_local_t, queue);
    if ((cfg->set_flag & QCFG_SET_FLAG_TRANS_NUM) != 0) {
        local_q->cfg.trans_qnum = cfg->trans_qnum;
    }

    if ((cfg->set_flag & QCFG_SET_FLAG_FE_IDX)) {
        if (q->ops->mapping_queue_fe_idx == NULL) {
            URPC_LIB_LOG_ERR("mapping jetty fe_idx not support\n");
            return URPC_FAIL;
        }

        int ret = q->ops->mapping_queue_fe_idx(q, cfg->fe_idx);
        if (ret) {
            URPC_LIB_LOG_ERR("mapping jetty fe_idx failed in queue, fe_idx %u\n", cfg->fe_idx);
            return URPC_FAIL;
        }
    }

    URPC_LIB_LOG_INFO("set queue config successful\n");
    return URPC_SUCCESS;
}

int urpc_queue_interrupt_fd_get(uint64_t urpc_qh)
{
    if (urpc_qh == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("queue handle invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *q = (queue_t *)(uintptr_t)urpc_qh;
    if (q->flag.is_remote == URPC_TRUE) {
        URPC_LIB_LOG_ERR("remote queue is not supported\n");
        return -URPC_ERR_EINVAL;
    }

    return q->ops->get_interrupt_fd(q);
}

int urpc_queue_modify(uint64_t urpc_qh, urpc_queue_status_t status)
{
    if (urpc_qh == URPC_INVALID_HANDLE || status >= QUEUE_STATUS_MAX) {
        URPC_LIB_LOG_ERR("queue handle or state[%u] invalid\n", status);
        return -URPC_ERR_EINVAL;
    }

    queue_t *l_queue = (queue_t *)(uintptr_t)urpc_qh;
    if (l_queue->flag.is_remote == URPC_TRUE) {
        URPC_LIB_LOG_ERR("queue modify not support remote queue\n");
        return -URPC_ERR_EINVAL;
    }

    if (l_queue->ops->mode != QUEUE_TRANS_MODE_JETTY) {
        URPC_LIB_LOG_ERR("queue modify not support mode[%u] ops\n", l_queue->ops->mode);
        return -URPC_ERR_EINVAL;
    }

    return l_queue->ops->modify_queue(l_queue, status);
}

int urpc_queue_status_query(uint64_t urpc_qh, urpc_queue_status_t *status)
{
    if (urpc_qh == URPC_INVALID_HANDLE || status == NULL) {
        URPC_LIB_LOG_ERR("queue handle or queue status invalid\n");
        return -URPC_ERR_EINVAL;
    }

    queue_t *queue = (queue_t *)(uintptr_t)urpc_qh;
    *status = queue->status;

    return URPC_SUCCESS;
}

uint64_t urpc_mem_seg_register(uint64_t va, uint64_t len)
{
    if (va == 0 || len == 0) {
        URPC_LIB_LOG_ERR("Invalid addr or len\n");
        return URPC_INVALID_HANDLE;
    }

    mem_seg_register_param_t param = {
        .addr = va,
        .len = len,
        .token = NULL,
        .va = true,
        .fe_idx = 0,
    };

    uint32_t list_size = provider_get_list_size();
    if (list_size == 0) {
        URPC_LIB_LOG_ERR("no provider is avaliable, please init urpc at first\n");
        return URPC_INVALID_HANDLE;
    }

    size_t size = sizeof(mem_handle_t) + list_size * sizeof(uint64_t);
    mem_handle_t *mem_handle = (mem_handle_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_ALLOCATOR, 1, size);
    if (mem_handle == NULL) {
        URPC_LIB_LOG_ERR("calloc failed\n");
        return URPC_INVALID_HANDLE;
    }

    provider_t *provider = NULL;
    urpc_list_t *provider_list = get_provider_list();
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        if (provider->idx >= list_size) {
            URPC_LIB_LOG_ERR("provider idx exceeds limitation\n");
            goto ERR;
        }

        uint64_t handle = provider->ops->register_mem(provider, &param);
        if (handle == URPC_INVALID_HANDLE) {
            urpc_eid_t eid = {0};
            provider->ops->get_eid(provider, &eid);
            URPC_LIB_LOG_ERR("failed to register memory segment on eid: "EID_FMT"\n", EID_ARGS(eid));
            goto ERR;
        }

        mem_handle->handle[provider->idx] = handle;
        urpc_eid_t eid = {0};
        provider->ops->get_eid(provider, &eid);
    }
    mem_handle->num = list_size;

    return (uint64_t)(uintptr_t)mem_handle;

ERR:
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        uint64_t mem_h = mem_handle->handle[provider->idx];
        if (mem_h == URPC_INVALID_HANDLE) {
            continue;
        }

        provider->ops->unregister_mem(provider, mem_h, true);
    }

    urpc_dbuf_free(mem_handle);

    return URPC_INVALID_HANDLE;
}

int urpc_mem_seg_unregister(uint64_t mem_h)
{
    if (mem_h == 0) {
        URPC_LIB_LOG_ERR("Invalid mem_h\n");
        return URPC_FAIL;
    }

    uint32_t list_size = provider_get_list_size();
    if (list_size == 0) {
        URPC_LIB_LOG_ERR("no provider is avaliable, please init urpc at first\n");
        return URPC_FAIL;
    }

    int ret = URPC_SUCCESS;
    mem_handle_t *mem_handle = (mem_handle_t *)(uintptr_t)mem_h;
    provider_t *provider = NULL;
    urpc_list_t *provider_list = get_provider_list();
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        if (provider->idx >= mem_handle->num) {
            URPC_LIB_LOG_ERR("provider idx exceeds limitation\n");
            ret = URPC_FAIL;
            continue;
        }

        if (provider->ops->unregister_mem(provider, mem_handle->handle[provider->idx], true) != URPC_SUCCESS) {
            urpc_eid_t eid = {0};
            provider->ops->get_eid(provider, &eid);
            URPC_LIB_LOG_ERR("failed to unregister memory segment on eid: "EID_FMT"\n", EID_ARGS(eid));
            ret = URPC_FAIL;
        };
    }

    urpc_dbuf_free(mem_handle);

    return ret;
}

int urpc_mem_seg_token_get(uint64_t mem_h, mem_seg_token_t *token)
{
    queue_ops_t *ops = queue_get_ops(QUEUE_TRANS_MODE_JETTY);
    if (ops == NULL) {
        URPC_LIB_LOG_ERR("get queue ops failed\n");
        return URPC_FAIL;
    }

    if (mem_h == 0 || token == NULL) {
        URPC_LIB_LOG_ERR("mem_h or token invalid\n");
        return URPC_FAIL;
    }

    int ret = ops->mem_seg_token_get(mem_h, token);
    if (ret == URPC_SUCCESS) {
        URPC_LIB_LOG_INFO("mem seg token get successful\n");
    }
    return ret;
}

int urpc_ctrl_msg_cb_register(urpc_ctrl_cb_t ctrl_cb)
{
    if (ctrl_cb == NULL) {
        URPC_LIB_LOG_ERR("ctrl_cb invalid\n");
        return -URPC_ERR_EINVAL;
    }

    g_urpc_ctrl_msg_cb = ctrl_cb;

    return URPC_SUCCESS;
}

int urpc_ctrl_msg_process(urpc_ctrl_msg_type_t msg_type, urpc_ctrl_msg_t *ctrl_msg)
{
    if (g_urpc_ctrl_msg_cb == NULL) {
        return URPC_SUCCESS;
    }

    return g_urpc_ctrl_msg_cb(msg_type, ctrl_msg);
}

bool is_server_support_quick_reply(void)
{
    if ((g_urpc_ctx.feature & URPC_FEATURE_HWUB_OFFLOAD) != 0) {
        return true;
    }
    return false;
}

bool is_feature_enable(uint32_t feature)
{
    return (g_urpc_ctx.feature & feature) != 0;
}

urpc_role_t urpc_role_get(void)
{
    return g_urpc_ctx.role;
}

uint64_t urpc_keepalive_attr_get(void)
{
    return g_urpc_ctx.keepalive_cfg.user_ctx;
}

uint16_t urpc_device_class_get(void)
{
    return g_urpc_ctx.device_class;
}

uint16_t urpc_sub_class_get(void)
{
    return g_urpc_ctx.sub_class;
}

void urpc_skip_post_rx_set(bool is_skip)
{
    g_urpc_ctx.skip_post_rx = is_skip;
}

int urpc_channel_task_cancel(uint32_t urpc_chid, int task_id)
{
    if (urpc_check_not_ready()) {
        URPC_LIB_LOG_ERR("urpc is not ready\n");
        return -URPC_ERR_EPERM;
    }

    return task_manager_task_cancel(task_id);
}

int urpc_mem_import(uint32_t server_chid, xchg_mem_info_t *mem_info)
{
    if (server_chid == URPC_INVALID_ID_U32 || mem_info == NULL) {
        URPC_LIB_LOG_ERR("server chid[%u] or xchg_mem invalid\n", server_chid);
        return -URPC_ERR_EINVAL;
    }

    mem_hmap_key_t mem_key = {
        .server_chid = server_chid,
        .token_id = mem_info->seg_token_id,
        .token_value = mem_info->token.token,
    };
    uint32_t list_size = provider_get_list_size();
    int ret = URPC_FAIL;
    provider_t *provider = NULL;
    urpc_list_t *provider_list = get_provider_list();
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        if (provider->idx >= list_size) {
            URPC_LIB_LOG_ERR("provider idx exceeds limitation\n");
            goto ERR;
        }

        ret = provider->ops->import_mem(provider, mem_info, server_chid);
        if (ret != URPC_SUCCESS) {
            if (ret == -URPC_ERR_EEXIST) {
                continue;
            }
            urpc_eid_t eid = {0};
            provider->ops->get_eid(provider, &eid);
            URPC_LIB_LOG_ERR("failed to import tseg on eid: "EID_FMT"\n", EID_ARGS(eid));
            goto ERR;
        }
    }

    URPC_LIB_LOG_INFO("import segment memory successful\n");
    return URPC_SUCCESS;

ERR:
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        provider->ops->unimport_mem(provider, &mem_key);
    }
    URPC_LIB_LOG_INFO("import segment memory failed\n");
    return ret;
}

int urpc_mem_unimport(uint32_t server_chid, uint32_t token_id, uint32_t token_value)
{
    if (server_chid == URPC_INVALID_ID_U32) {
        URPC_LIB_LOG_ERR("server chid invalid\n");
        return -URPC_ERR_EINVAL;
    }

    mem_hmap_key_t mem_key = {
        .server_chid = server_chid,
        .token_id = token_id,
        .token_value = token_value,
    };

    int ret = URPC_SUCCESS;
    provider_t *provider = NULL;
    urpc_list_t *provider_list = get_provider_list();
    URPC_LIST_FOR_EACH(provider, node, provider_list) {
        if (provider->ops->unimport_mem(provider, &mem_key) != URPC_SUCCESS) {
            urpc_eid_t eid = {0};
            provider->ops->get_eid(provider, &eid);
            URPC_LIB_LOG_ERR("failed to unimport memory segment on eid: "EID_FMT"\n", EID_ARGS(eid));
            ret = URPC_FAIL;
        };
    }

    return ret;
}