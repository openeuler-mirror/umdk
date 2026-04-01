/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize func for umq api
 * Create: 2025-7-17
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>

#include "perf.h"
#include "umq_vlog.h"
#include "umq_inner.h"
#include "urpc_thread.h"
#include "urpc_manage.h"
#include "umq_qbuf_pool.h"
#include "urpc_timer.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_errno.h"
#include "urpc_util.h"
#include "util_lock.h"

#ifdef UMQ_STATIC_LIB
#include "umq_ub_api.h"
#endif

#define MAX_SO_NAME_LEN     (32)
#define MAX_FUNCNAME_LEN    (32)

typedef struct umq_framework {
    umq_trans_mode_t mode;
    bool enable;

    char dlopen_so_name[MAX_SO_NAME_LEN];
    void *dlhandler;

    char ops_get_funcname[MAX_FUNCNAME_LEN];
    umq_ops_get_t ops_get_func;
    umq_ops_t *tp_ops;
    uint8_t *ctx;

    char pro_ops_get_funcname[MAX_FUNCNAME_LEN];
    umq_pro_ops_get_t pro_ops_get_func;
    umq_pro_ops_t *pro_tp_ops;

    char dfx_ops_get_funcname[MAX_FUNCNAME_LEN];
    umq_dfx_ops_get_t dfx_ops_get_func;
    umq_dfx_ops_t *dfx_tp_ops;
} umq_framework_t;

static bool g_umq_inited = false;
static struct {
    umq_log_config_t cfg;
    bool is_set;
} g_umq_log_config;
static umq_init_cfg_t *g_umq_config;
static util_external_mutex_lock *g_umq_config_mutex_lock = NULL;

static umq_framework_t g_umq_fws[UMQ_TRANS_MODE_MAX] = {
    [UMQ_TRANS_MODE_UB] = {
        .mode = UMQ_TRANS_MODE_UB,
        .enable = false,

        .dlopen_so_name = "libumq_ub.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ub_ops_get",
#ifdef UMQ_STATIC_LIB
        .ops_get_func = umq_ub_ops_get,
#else
        .ops_get_func = NULL,
#endif
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ub_ops_get",
#ifdef UMQ_STATIC_LIB
        .pro_ops_get_func = umq_pro_ub_ops_get,
#else
        .pro_ops_get_func = NULL,
#endif
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ub_dfx_ops_get",
#ifdef UMQ_STATIC_LIB
        .dfx_ops_get_func = umq_ub_dfx_ops_get,
#else
        .dfx_ops_get_func = NULL,
#endif
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_IB] = {
        .mode = UMQ_TRANS_MODE_IB,
        .enable = false,

        .dlopen_so_name = "libumq_ib.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ib_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ib_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ib_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_UCP] = {
        .mode = UMQ_TRANS_MODE_UCP,
        .enable = false,

        .dlopen_so_name = "libumq_ucp.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ucp_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ucp_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ucp_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_IPC] = {
        .mode = UMQ_TRANS_MODE_IPC,
        .enable = false,

        .dlopen_so_name = "libumq_ipc.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ipc_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ipc_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ipc_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_UBMM] = {
        .mode = UMQ_TRANS_MODE_UBMM,
        .enable = false,

        .dlopen_so_name = "libumq_ubmm.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ubmm_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ubmm_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ubmm_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_UB_PLUS] = {
        .mode = UMQ_TRANS_MODE_UB_PLUS,
        .enable = false,

        .dlopen_so_name = "libumq_ub.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ub_plus_ops_get",
#ifdef UMQ_STATIC_LIB
        .ops_get_func = umq_ub_plus_ops_get,
#else
        .ops_get_func = NULL,
#endif
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ub_plus_ops_get",
#ifdef UMQ_STATIC_LIB
        .pro_ops_get_func = umq_pro_ub_plus_ops_get,
#else
        .pro_ops_get_func = NULL,
#endif
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ub_plus_dfx_ops_get",
#ifdef UMQ_STATIC_LIB
        .dfx_ops_get_func = umq_ub_plus_dfx_ops_get,
#else
        .dfx_ops_get_func = NULL,
#endif
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_IB_PLUS] = {
        .mode = UMQ_TRANS_MODE_IB_PLUS,
        .enable = false,

        .dlopen_so_name = "libumq_ib.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ib_plus_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ib_plus_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,

        .dfx_ops_get_funcname = "umq_ib_plus_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
    [UMQ_TRANS_MODE_UBMM_PLUS] = {
        .mode = UMQ_TRANS_MODE_UBMM_PLUS,
        .enable = false,

        .dlopen_so_name = "libumq_ubmm.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ubmm_plus_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ubmm_plus_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,
        .dfx_ops_get_funcname = "umq_ubmm_plus_dfx_ops_get",
        .dfx_ops_get_func = NULL,
        .dfx_tp_ops = NULL,
    },
};

static int umq_fw_log_config_set(umq_log_config_t *config)
{
    uint8_t fw_i = 0;
    int ret = UMQ_SUCCESS;
    for (; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        if (!umq_fw->enable) {
            continue;
        }
        if ((umq_fw == NULL) || (umq_fw->tp_ops == NULL) || (umq_fw->tp_ops->umq_tp_log_config_set == NULL)) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq_fw invalid\n");
            goto RESET_LOG;
        }
        ret = umq_fw->tp_ops->umq_tp_log_config_set(config);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "log config set failed, status: %d\n", ret);
            goto RESET_LOG;
        }
    }
    return UMQ_SUCCESS;

RESET_LOG:
    for (uint8_t j = 0; j < fw_i; j++) {
        umq_framework_t *umq_fw = &g_umq_fws[j];
        if (!umq_fw->enable) {
            continue;
        }
        ret = umq_fw->tp_ops->umq_tp_log_config_reset();
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "log config reset failed, j = %u, status: %d\n", j, ret);
        }
    }
    return -UMQ_ERR_EINVAL;
}

int umq_log_config_set(umq_log_config_t *config)
{
    if (config == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid configure\n");
        return -UMQ_ERR_EINVAL;
    }

    if ((config->log_flag & UMQ_LOG_FLAG_LEVEL) &&
        (config->level < UMQ_LOG_LEVEL_EMERG || config->level >= UMQ_LOG_LEVEL_MAX)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid log level %d\n", config->level);
        return -UMQ_ERR_EINVAL;
    }

    umq_vlog_config_t *log_config = umq_get_log_config();
    if (config->log_flag & UMQ_LOG_FLAG_FUNC) {
        if (config->func == NULL) {
            log_config->ctx.vlog_output_func = default_vlog_output;
            UMQ_VLOG_INFO(VLOG_UMQ, "set log configuration success, log output function: default\n");
        } else {
            log_config->ctx.vlog_output_func = config->func;
            UMQ_VLOG_INFO(VLOG_UMQ, "set log configuration success, log output function: user defined\n");
        }
    }

    if (config->log_flag & UMQ_LOG_FLAG_LEVEL) {
        log_config->ctx.level = (util_vlog_level_t)config->level;
        UMQ_VLOG_INFO(VLOG_UMQ, "set log configuration success, log level: %d\n", config->level);
    }
    if (umq_fw_log_config_set(config) != UMQ_SUCCESS) {
        return -UMQ_ERR_EINVAL;
    }
    if ((config->log_flag & UMQ_LOG_FLAG_RATE_LIMITED)) {
        log_config->ctx.rate_limited.interval_ms = config->rate_limited.interval_ms;
        log_config->ctx.rate_limited.num = config->rate_limited.num;
        UMQ_VLOG_INFO(VLOG_UMQ, "set log configuration success, limited interval(ms): %u, limited num: %u\n",
                      config->rate_limited.interval_ms, config->rate_limited.num);
    }

    g_umq_log_config.cfg = *config;
    g_umq_log_config.is_set = true;

    return UMQ_SUCCESS;
}

int umq_log_config_get(umq_log_config_t *config)
{
    if (config == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_vlog_config_t *log_config = umq_get_log_config();

    config->log_flag = log_config->log_flag;
    config->level = (umq_log_level_t)log_config->ctx.level;
    config->func = log_config->ctx.vlog_output_func;
    config->rate_limited.interval_ms = log_config->ctx.rate_limited.interval_ms;
    config->rate_limited.num = log_config->ctx.rate_limited.num;
    if (config->func == default_vlog_output) {
        config->func = NULL;
    }

    return UMQ_SUCCESS;
}

static void framework_uninit(void)
{
    for (uint8_t fw_i = 0; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        umq_fw->dfx_tp_ops = NULL;
        umq_fw->dfx_ops_get_func = NULL;
        umq_fw->pro_tp_ops = NULL;
        umq_fw->pro_ops_get_func = NULL;

        if ((umq_fw->ctx != NULL) && (umq_fw->tp_ops != NULL) && (umq_fw->tp_ops->umq_tp_uninit != NULL)) {
            umq_fw->tp_ops->umq_tp_uninit(umq_fw->ctx);

            if (umq_fw->tp_ops->umq_tp_log_config_reset != NULL) {
                (void)umq_fw->tp_ops->umq_tp_log_config_reset();
            }
        }
        umq_fw->ctx = NULL;
        umq_fw->tp_ops = NULL;
        umq_fw->ops_get_func = NULL;

        if (umq_fw->dlhandler != NULL) {
            dlclose(umq_fw->dlhandler);
        }
        umq_fw->dlhandler = NULL;
        umq_fw->enable = false;
    }
}

static int umq_pre_thread_start_callback(void *args)
{
    return UMQ_SUCCESS;
}

static void umq_post_thread_end_callback(void *args)
{
    return;
}

static int umq_pre_dp_start(void)
{
    if (urpc_timing_wheel_init() != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq timing wheel init failed\n");
        return UMQ_FAIL;
    }
    urpc_manage_callback_register(umq_pre_thread_start_callback, umq_post_thread_end_callback,
        URPC_MANAGE_JOB_TYPE_LISTEN);
    if (urpc_manage_init() != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq listen thread init failed\n");
        goto TIMER_UNINIT;
    }
    return UMQ_SUCCESS;
TIMER_UNINIT:
    urpc_timing_wheel_uninit();

    return UMQ_FAIL;
}

static void umq_post_dp_end(void)
{
    urpc_manage_uninit();
    urpc_timing_wheel_uninit();
}

static int umq_thread_init(umq_init_cfg_t *cfg)
{
    if ((cfg->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) == 0) {
        // disable flow control
        return UMQ_SUCCESS;
    }
    if (urpc_thread_ctx_init() != UMQ_SUCCESS) {
        return UMQ_FAIL;
    }

    if (umq_pre_dp_start() != UMQ_SUCCESS) {
        goto THREAD_CTX_UNINIT;
    }

    return UMQ_SUCCESS;

THREAD_CTX_UNINIT:
    urpc_thread_ctx_uninit();

    return UMQ_FAIL;
}

static void umq_thread_uninit(umq_init_cfg_t *cfg)
{
    if ((cfg->feature & UMQ_FEATURE_ENABLE_FLOW_CONTROL) == 0) {
        return;
    }
    umq_post_dp_end();
    urpc_thread_ctx_uninit();
}

void umq_uninit(void)
{
    if (!g_umq_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq has not been inited\n");
        return;
    }

    umq_perf_uninit();
    framework_uninit();

    if (g_umq_config != NULL) {
        umq_thread_uninit(g_umq_config);
        free(g_umq_config);
        g_umq_config = NULL;
    }
    g_umq_log_config.is_set = false;
    g_umq_inited = false;
    (void)util_mutex_lock_destroy(g_umq_config_mutex_lock);
    g_umq_config_mutex_lock = NULL;
    util_external_mutex_lock_ops_register(NULL);
    util_external_rwlock_ops_register(NULL);
}

#ifndef UMQ_STATIC_LIB
static int load_symbol(void *handle, void **func, const char *symbol)
{
    *func = dlsym(handle, symbol);
    if (*func == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "dlsym failed, err: %s\n", dlerror());
        return UMQ_FAIL;
    }
    return UMQ_SUCCESS;
}
#endif

static int umq_framework_init(umq_framework_t *umq_fw, umq_init_cfg_t *cfg)
{
    int ret = UMQ_SUCCESS;
#ifndef UMQ_STATIC_LIB
    umq_fw->dlhandler = dlopen(umq_fw->dlopen_so_name, RTLD_LAZY | RTLD_GLOBAL);
    if (umq_fw->dlhandler == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "open so failed, err: %s\n", dlerror());
        return UMQ_FAIL;
    }

    ret = load_symbol(umq_fw->dlhandler, (void **)&umq_fw->ops_get_func, umq_fw->ops_get_funcname);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "load_symbol ops failed, status: %d\n", ret);
        goto CLONE_SO;
    }
#endif

    umq_fw->tp_ops = umq_fw->ops_get_func();
    if ((umq_fw->tp_ops == NULL) || (umq_fw->tp_ops->umq_tp_init == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get ops func failed\n");
        goto UNLOAD_OPS_GET_FUNC;
    }

    // Load dynamic symbols - must succeed
    if (umq_fw->tp_ops->umq_tp_load_symbol == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq_tp_load_symbol is NULL\n");
        ret = -UMQ_ERR_EINVAL;
        goto PUT_TP_OPS;
    }
    ret = umq_fw->tp_ops->umq_tp_load_symbol();
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "load symbol failed, status: %d\n", ret);
        goto PUT_TP_OPS;
    }

    // register log func if needed
    if (g_umq_log_config.is_set && umq_fw->tp_ops->umq_tp_log_config_set != NULL) {
        ret = umq_fw->tp_ops->umq_tp_log_config_set(&g_umq_log_config.cfg);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "log config set failed, status: %d\n", ret);
            goto PUT_TP_OPS;
        }
    }
    umq_fw->ctx = umq_fw->tp_ops->umq_tp_init(cfg);
    if (umq_fw->ctx == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tp init failed\n");
        goto RESET_LOG;
    }

#ifndef UMQ_STATIC_LIB
    ret = load_symbol(umq_fw->dlhandler, (void **)&umq_fw->pro_ops_get_func, umq_fw->pro_ops_get_funcname);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "load_symbol pro_ops failed, status: %d\n", ret);
        goto UNINIT_UMQ_TP;
    }
#endif

    umq_fw->pro_tp_ops = umq_fw->pro_ops_get_func();
    if (umq_fw->pro_tp_ops == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get pro_ops func failed\n");
        goto UNLOAD_PRO_OPS_GET_FUNC;
    }

#ifndef UMQ_STATIC_LIB
    if (load_symbol(umq_fw->dlhandler,
        (void **)&umq_fw->dfx_ops_get_func, umq_fw->dfx_ops_get_funcname) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "load_symbol dfx_ops failed\n");
        goto PUT_PRO_TP_OPS;
    }
#endif

    umq_fw->dfx_tp_ops = umq_fw->dfx_ops_get_func();
    if (umq_fw->dfx_tp_ops == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get dfx_ops func failed\n");
        goto UNLOAD_DFX_OPS_GET_FUNC;
    }

    return UMQ_SUCCESS;

UNLOAD_DFX_OPS_GET_FUNC:
#ifndef UMQ_STATIC_LIB
    umq_fw->dfx_ops_get_func = NULL;

PUT_PRO_TP_OPS:
#endif
    umq_fw->pro_tp_ops = NULL;

UNLOAD_PRO_OPS_GET_FUNC:
#ifndef UMQ_STATIC_LIB
    umq_fw->pro_ops_get_func = NULL;

UNINIT_UMQ_TP:
#endif
    if (umq_fw->tp_ops->umq_tp_uninit != NULL) {
        umq_fw->tp_ops->umq_tp_uninit(umq_fw->ctx);
        umq_fw->ctx = NULL;
    }

RESET_LOG:
    if (umq_fw->tp_ops->umq_tp_log_config_reset != NULL) {
        (void)umq_fw->tp_ops->umq_tp_log_config_reset();
    }

PUT_TP_OPS:
    umq_fw->tp_ops = NULL;

UNLOAD_OPS_GET_FUNC:
#ifndef UMQ_STATIC_LIB
    umq_fw->ops_get_func = NULL;

CLONE_SO:
#endif
    if (umq_fw->dlhandler != NULL) {
        dlclose(umq_fw->dlhandler);
    }
    umq_fw->enable = false;
    return UMQ_FAIL;
}

static void umq_init_cfg_dummy_dev_filter(umq_init_cfg_t *cfg)
{
    uint8_t i, j;
    umq_trans_info_t *src, *dst;
    for (i = 0, j = 0; i < cfg->trans_info_num && j < cfg->trans_info_num;) {
        src = &cfg->trans_info[i];
        dst = &cfg->trans_info[j];

        if (src->dev_info.assign_mode == UMQ_DEV_ASSIGN_MODE_DUMMY) {
            i++;
            continue;
        }

        memcpy(dst, src, sizeof(umq_trans_info_t));
        i++;
        j++;
    }

    cfg->trans_info_num = j;
}

int umq_init(umq_init_cfg_t *cfg)
{
    int ret = UMQ_SUCCESS;
    if (g_umq_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    if (cfg == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "cfg is null\n");
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->trans_info_num > MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans_info_num[%u] is invalid\n", cfg->trans_info_num);
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR(VLOG_UMQ, "headroom size %u exceeds the maximum value\n", cfg->headroom_size);
        return -UMQ_ERR_EINVAL;
    }

    if ((cfg->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0) {
        ret = urpc_rand_seed_init();
        if (ret != 0) {
            UMQ_VLOG_ERR(VLOG_UMQ, "rand seed init failed, status: %u\n", ret);
            return ret;
        }
    }

    if (umq_buf_size_pow_small_set(cfg->block_cfg.small_block_size) != UMQ_SUCCESS) {
        return -UMQ_ERR_EINVAL;
    }

    for (uint8_t trans_info_i = 0; trans_info_i < cfg->trans_info_num; trans_info_i++) {
        umq_trans_info_t *info = &cfg->trans_info[trans_info_i];
#ifdef UMQ_STATIC_LIB
        if (info->trans_mode != UMQ_TRANS_MODE_UB && info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
            return -UMQ_ERR_EINVAL;
        }
#endif
        if (info->trans_mode >= UMQ_TRANS_MODE_MAX || info->trans_mode < 0) {
            continue;
        }

        g_umq_fws[info->trans_mode].enable = true;
    }

    g_umq_config_mutex_lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (g_umq_config_mutex_lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq config mutex create failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    ret = umq_thread_init(cfg);
    if (ret != UMQ_SUCCESS) {
        goto LOCK_DESTROY;
    }

    for (uint8_t fw_i = 0; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        if (!umq_fw->enable) {
            continue;
        }
        ret = umq_framework_init(umq_fw, cfg);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u umq framework init failed, status: %d\n", fw_i, ret);
            goto FW_UNINIT;
        }
    }

    g_umq_config = (umq_init_cfg_t *)malloc(sizeof(umq_init_cfg_t));
    if (g_umq_config == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "malloc umq config failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FW_UNINIT;
    }
    (void)memcpy(g_umq_config, cfg, sizeof(umq_init_cfg_t));

    umq_init_cfg_dummy_dev_filter(g_umq_config);

    g_umq_inited = true;
    return UMQ_SUCCESS;

FW_UNINIT:
    framework_uninit();
    umq_thread_uninit(cfg);
LOCK_DESTROY:
    (void)util_mutex_lock_destroy(g_umq_config_mutex_lock);
    g_umq_config_mutex_lock = NULL;
    return ret;
}

uint64_t umq_create(umq_create_option_t *option)
{
    if (option == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create option is null\n");
        return UMQ_INVALID_HANDLE;
    }

#ifdef UMQ_STATIC_LIB
    if (option->trans_mode != UMQ_TRANS_MODE_UB && option->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return UMQ_INVALID_HANDLE;
    }
#endif

    if ((option->trans_mode >= UMQ_TRANS_MODE_MAX) || (option->trans_mode < 0) || (option->name[0] == '\0')) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans_mode[%d] not support or name is null\n", option->trans_mode);
        return UMQ_INVALID_HANDLE;
    }

    umq_framework_t *umq_fw = &g_umq_fws[option->trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans_mode[%d] is not enabled on initialize\n", option->trans_mode);
        return UMQ_INVALID_HANDLE;
    }

    umq_t *umq = calloc(1, sizeof(umq_t));
    if (umq == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "alloc umq failed\n");
        return UMQ_INVALID_HANDLE;
    }
    umq->mode = option->trans_mode;
    umq->tp_ops = umq_fw->tp_ops;
    umq->pro_tp_ops = umq_fw->pro_tp_ops;
    if (umq->tp_ops->umq_tp_create == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "tp create function is null\n");
        goto ERR;
    }
    umq->umqh_tp = umq->tp_ops->umq_tp_create((uint64_t)(uintptr_t)umq, umq_fw->ctx, option);
    if (umq->umqh_tp == 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create transport resource failed\n");
        goto ERR;
    }
    umq->dfx_tp_ops = umq_fw->dfx_tp_ops;

    return (uint64_t)(uintptr_t)umq;
ERR:
    free(umq);
    return UMQ_INVALID_HANDLE;
}

int umq_destroy(uint64_t umqh)
{
    int ret;
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_destroy == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    ret = umq->tp_ops->umq_tp_destroy(umq->umqh_tp);
    if (ret != UMQ_SUCCESS) {
        return ret;
    }

    free(umq);
    return ret;
}

uint32_t umq_bind_info_get(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((bind_info == NULL) || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_bind_info_get == NULL)) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "bind_info or umqh invalid, errno: %d\n", errno);
        return 0;
    }

    return umq->tp_ops->umq_tp_bind_info_get(umq->umqh_tp, bind_info, bind_info_size);
}

int umq_bind(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((bind_info == NULL) || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_bind == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "bind_info or umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_bind(umq->umqh_tp, bind_info, bind_info_size);
}

int umq_unbind(uint64_t umqh)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_unbind == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_unbind(umq->umqh_tp);
}

umq_buf_t *umq_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh, umq_alloc_option_t *option)
{
    if (!g_umq_inited || request_qbuf_num == 0 || request_size > UMQ_MAX_BUF_REQUEST_SIZE) {
        UMQ_VLOG_ERR(VLOG_UMQ, "param invalid or umq not initialized\n");
        return NULL;
    }
    uint32_t headroom_size = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
        option->headroom_size : umq_qbuf_headroom_get();
    if (headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR(VLOG_UMQ, "headroom size %u exceeds the maximum value\n", headroom_size);
        return NULL;
    }
    umq_buf_mode_t mode = umq_qbuf_mode_get();
    uint32_t factor = (mode == UMQ_BUF_SPLIT) ? 0 : sizeof(umq_buf_t);
    if (umqh == UMQ_INVALID_HANDLE) {
        umq_buf_list_t head;
        QBUF_LIST_INIT(&head);
        uint32_t buf_size = request_size + headroom_size + factor;

        if (buf_size < umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID)) {
            if (umq_qbuf_alloc(request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
                return NULL;
            }
        } else {
            huge_qbuf_pool_size_type_t type = umq_huge_qbuf_get_type_by_size(buf_size);
            if (umq_huge_qbuf_alloc(type, request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
                return NULL;
            }
        }

        return QBUF_LIST_FIRST(&head);
    }

    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if ((umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_buf_alloc == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or qbuf invalid\n");
        return NULL;
    }

    return umq->tp_ops->umq_tp_buf_alloc(request_size, request_qbuf_num, umq->umqh_tp, option);
}

void umq_buf_free(umq_buf_t *qbuf)
{
    if (!g_umq_inited || qbuf == NULL) {
        return;
    }

    umq_buf_list_t head;
    QBUF_LIST_FIRST(&head) = qbuf;
    if (qbuf->umqh == UMQ_INVALID_HANDLE) {
        if (QBUF_LIST_NEXT(qbuf) == NULL) {
            if (qbuf->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
                umq_huge_qbuf_free(&head);
            } else {
                umq_qbuf_free(&head);
            }

            return;
        }

        /* Here, the free list will be traversed, and an attempt will be made to scan each qbuf object.
        * If there exist n consecutive qbuf objects that belong to the same memory pool, they will be
        * released in batch. */
        umq_buf_t *cur_node = NULL;
        umq_buf_t *next_node = NULL;
        umq_buf_t *last_node = NULL;
        umq_buf_t *free_node = qbuf; // head of the list to be released
        umq_buf_list_t free_head;
        QBUF_LIST_FIRST(&free_head) = free_node;
        bool is_huge = qbuf->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID; // Specify the list to be released currently
                                                                        // belongs to large or general pool.
        QBUF_LIST_FIRST(&head) = QBUF_LIST_NEXT(qbuf);

        QBUF_LIST_FOR_EACH_SAFE(cur_node, &head, next_node)
        {
            if ((is_huge && (cur_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID)) ||
                (!is_huge && (cur_node->mempool_id == 0))) {
                // current qbuf is in the same pool, scan the next one directly
                last_node = cur_node;
                continue;
            }

            QBUF_LIST_NEXT(last_node) = NULL;
            QBUF_LIST_FIRST(&free_head) = free_node;
            free_node = cur_node;
            is_huge = cur_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID;
            if (free_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
                umq_huge_qbuf_free(&free_head);
            } else {
                umq_qbuf_free(&free_head);
            }
        }

        QBUF_LIST_FIRST(&free_head) = free_node;
        if (free_node->mempool_id != UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
            umq_huge_qbuf_free(&free_head);
        } else {
            umq_qbuf_free(&free_head);
        }
        return;
    }

    umq_t *umq = (umq_t *)(uintptr_t)qbuf->umqh;
    if ((umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_buf_free == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or qbuf invalid\n");
        return;
    }

    umq->tp_ops->umq_tp_buf_free(qbuf, umq->umqh_tp);
}

umq_buf_t *umq_buf_break_and_free(umq_buf_t *qbuf)
{
    if (!g_umq_inited || qbuf == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq not initialized or qbuf is NULL\n");
        return NULL;
    }
    // break qbuf list for many batchs connected, only release the first batch.
    umq_buf_t *next_batch_qbuf = qbuf->qbuf_next; /* if request_size = 0, return qbuf->qbuf_next */
    umq_buf_t *tmp_buf = qbuf;
    uint32_t rest_data_size = tmp_buf->total_data_size;
    if (rest_data_size == 0) {
        qbuf->qbuf_next = NULL;
        goto FREE_BUF;
    }
    while (tmp_buf && rest_data_size > 0) {
        if (rest_data_size <= tmp_buf->data_size) {
            next_batch_qbuf = tmp_buf->qbuf_next;
            tmp_buf->qbuf_next = NULL;
            break;
        }
        rest_data_size -= tmp_buf->data_size;
        tmp_buf = tmp_buf->qbuf_next;
    }
FREE_BUF:
    umq_buf_free(qbuf);
    return next_batch_qbuf;
}

int umq_buf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_umq_inited || qbuf == NULL) {
        return -UMQ_ERR_EINVAL;
    }

    if (headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR(VLOG_UMQ, "headroom size %u exceeds the maximum value\n", headroom_size);
        return -UMQ_ERR_EINVAL;
    }

    if (qbuf->umqh == UMQ_INVALID_HANDLE) {
        if (qbuf->mempool_id == UMQ_QBUF_DEFAULT_MEMPOOL_ID) {
            return umq_qbuf_headroom_reset(qbuf, headroom_size);
        } else {
            return umq_huge_qbuf_headroom_reset(qbuf, headroom_size);
        }
    }

    umq_t *umq = (umq_t *)(uintptr_t)qbuf->umqh;
    if ((umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_buf_headroom_reset == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or tp invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_buf_headroom_reset(qbuf, headroom_size);
}

int umq_buf_reset(umq_buf_t *qbuf)
{
    if (!g_umq_inited || qbuf == NULL) {
        return -UMQ_ERR_EINVAL;
    }

    umq_buf_t *head = qbuf;
    umq_buf_t *tmp_buf = head;
    uint32_t total_data_size = 0;
    uint32_t align_size = 0;
    while (head != NULL) {
        align_size = head->buf_size - sizeof(umq_buf_t);
        uint16_t headroom_size = head->headroom_size;
        while (tmp_buf) {
            tmp_buf->data_size = tmp_buf->first_fragment ? align_size - headroom_size : align_size;
            total_data_size += tmp_buf->data_size;
            tmp_buf = tmp_buf->qbuf_next;
            if (tmp_buf == NULL || tmp_buf->first_fragment) {
                break;
            }
        }
        head->total_data_size = total_data_size;
        head = tmp_buf;
        total_data_size = 0;
    }
    return UMQ_SUCCESS;
}

umq_buf_t *umq_data_to_head(void *data)
{
    if (!g_umq_inited || data == NULL) {
        return NULL;
    }

    return umq_qbuf_data_to_head(data);
}

int umq_enqueue(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_enqueue == NULL) || qbuf == NULL || qbuf->buf_data == NULL || bad_qbuf == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or qbuf invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq->tp_ops->umq_tp_enqueue(umq->umqh_tp, qbuf, bad_qbuf);
    umq_perf_record_write(UMQ_PERF_RECORD_ENQUEUE, start_timestamp);
    return ret;
}

static inline void umq_perf_record_write_dequeue(uint64_t start, bool is_empty)
{
    if (is_empty) {
        umq_perf_record_write(UMQ_PERF_RECORD_DEQUEUE_EMPTY, start);
        return;
    }
    umq_perf_record_write(UMQ_PERF_RECORD_DEQUEUE, start);
}

umq_buf_t *umq_dequeue(uint64_t umqh)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_dequeue == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return NULL;
    }

    umq_buf_t *umq_buf = umq->tp_ops->umq_tp_dequeue(umq->umqh_tp);
    umq_perf_record_write_dequeue(start_timestamp, umq_buf == NULL);
    return umq_buf;
}

void umq_notify(uint64_t umqh)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_notify == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return;
    }

    umq->tp_ops->umq_tp_notify(umq->umqh_tp);
    umq_perf_record_write(UMQ_PERF_RECORD_NOTIFY, start_timestamp);
    return;
}

int umq_rearm_interrupt(uint64_t umqh, bool solicated, umq_interrupt_option_t *option)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_rearm_interrupt == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    int ret = umq->tp_ops->umq_tp_rearm_interrupt(umq->umqh_tp, solicated, option);
    umq_perf_record_write_interrupt_with_direction(UMQ_PERF_RECORD_REARM_TX, start_timestamp, option->direction);
    return ret;
}

int32_t umq_wait_interrupt(uint64_t wait_umqh, int time_out, umq_interrupt_option_t *option)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)wait_umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_wait_interrupt == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    int32_t ret = umq->tp_ops->umq_tp_wait_interrupt(umq->umqh_tp, time_out, option);
    umq_perf_record_write_interrupt_with_direction(UMQ_PERF_RECORD_WAIT_TX, start_timestamp, option->direction);
    return ret;
}

void umq_ack_interrupt(uint64_t umqh, uint32_t nevents, umq_interrupt_option_t *option)
{
    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_ack_interrupt == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh or option invalid\n");
        return;
    }

    umq->tp_ops->umq_tp_ack_interrupt(umq->umqh_tp, nevents, option);
    umq_perf_record_write_interrupt_with_direction(UMQ_PERF_RECORD_ACK_TX, start_timestamp, option->direction);
}

int umq_buf_split(umq_buf_t *head, umq_buf_t *node)
{
    if (!g_umq_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq not initialized\n");
        return -UMQ_ERR_EINVAL;
    }
    if (head == NULL || node == NULL || head == node) {
        UMQ_VLOG_ERR(VLOG_UMQ, "head or node invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_buf_t *tmp = head;
    while (tmp->qbuf_next != NULL && tmp->qbuf_next != node) {
        tmp = tmp->qbuf_next;
    }

    if (tmp->qbuf_next == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "target node not found in the buf list\n");
        return -UMQ_ERR_EINVAL;
    }

    tmp->qbuf_next = NULL;
    return UMQ_SUCCESS;
}

int umq_state_set(uint64_t umqh, umq_state_t state)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_state_set == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_state_set(umq->umqh_tp, state);
}

umq_state_t umq_state_get(uint64_t umqh)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_state_get == NULL)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umqh invalid\n");
        return QUEUE_STATE_MAX;
    }

    return umq->tp_ops->umq_tp_state_get(umq->umqh_tp);
}

int umq_async_event_fd_get(umq_trans_info_t *trans_info)
{
#ifdef UMQ_STATIC_LIB
    if (trans_info->trans_mode != UMQ_TRANS_MODE_UB && trans_info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX || trans_info->trans_mode < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info invalid\n");
        return UMQ_INVALID_FD;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "framework instance disabled\n");
        return UMQ_INVALID_FD;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_async_event_fd_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "get event fd failed\n");
        return UMQ_INVALID_FD;
    }
    return umq_fw->tp_ops->umq_tp_async_event_fd_get(trans_info);
}

int umq_get_async_event(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
#ifdef UMQ_STATIC_LIB
    if (trans_info->trans_mode != UMQ_TRANS_MODE_UB && trans_info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (event == NULL || trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX ||
        trans_info->trans_mode < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "framework instance disabled\n");
        return -UMQ_ERR_EINVAL;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_async_event_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ops invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq_fw->tp_ops->umq_tp_async_event_get(trans_info, event);
}

void umq_ack_async_event(umq_async_event_t *event)
{
#ifdef UMQ_STATIC_LIB
    if (event->trans_info.trans_mode != UMQ_TRANS_MODE_UB &&
        event->trans_info.trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return;
    }
#endif

    if (event == NULL || event->trans_info.trans_mode >= UMQ_TRANS_MODE_MAX || event->trans_info.trans_mode < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "event invalid\n");
        return;
    }

    umq_framework_t *umq_fw = &g_umq_fws[event->trans_info.trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "framework instance disabled\n");
        return;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_aync_event_ack == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ops invalid\n");
        return;
    }
    return umq_fw->tp_ops->umq_tp_aync_event_ack(event);
}

int umq_dev_add(umq_trans_info_t *trans_info)
{
    int ret = UMQ_SUCCESS;
    if (!g_umq_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq has not been inited\n");
        return -UMQ_ERR_EINVAL;
    }

#ifdef UMQ_STATIC_LIB
    if (trans_info->trans_mode != UMQ_TRANS_MODE_UB &&
        trans_info->trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];
    (void)util_mutex_lock(g_umq_config_mutex_lock);
    if (g_umq_config->trans_info_num >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info num[%u] exceeds maximum[%u] limit\n",
            g_umq_config->trans_info_num, MAX_UMQ_TRANS_INFO_NUM);
        ret = -UMQ_ERR_EINVAL;
        goto UNLOCK;
    }
    g_umq_config->trans_info[g_umq_config->trans_info_num++] = *trans_info;

    // new trans mode umq framework need init and add dev
    if (!umq_fw->enable) {
        umq_fw->enable = true;
        ret = umq_framework_init(umq_fw, g_umq_config);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_ERR(VLOG_UMQ, "umq framework init failed, status: %d\n", ret);
            goto DECREASE_TRANS_INFO_NUM;
        }
        (void)util_mutex_unlock(g_umq_config_mutex_lock);
        return UMQ_SUCCESS;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_dev_add == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode [%u] tp ops invalid\n", trans_info->trans_mode);
        ret = -UMQ_ERR_EINVAL;
        goto DECREASE_TRANS_INFO_NUM;
    }

    // add new dev
    ret = umq_fw->tp_ops->umq_tp_dev_add(trans_info, g_umq_config);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "add dev failed, status: %d\n", ret);
        goto DECREASE_TRANS_INFO_NUM;
    }
    (void)util_mutex_unlock(g_umq_config_mutex_lock);
    return ret;

DECREASE_TRANS_INFO_NUM:
    g_umq_config->trans_info_num--;

UNLOCK:
    (void)util_mutex_unlock(g_umq_config_mutex_lock);

return ret;
}

int umq_get_route_list(const umq_route_key_t *route_key, umq_trans_mode_t umq_trans_mode, umq_route_list_t *route_list)
{
    if (route_key == NULL || route_list == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

#ifdef UMQ_STATIC_LIB
    if (umq_trans_mode != UMQ_TRANS_MODE_UB && umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (umq_trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[umq_trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not init\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_get_topo == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    return umq_fw->tp_ops->umq_tp_get_topo(route_key, route_list);
}

int umq_user_ctl(uint64_t umqh, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out)
{
    return UMQ_SUCCESS;
}

int umq_mempool_state_get(uint64_t umqh, uint32_t mempool_id, umq_mempool_state_t *mempool_state)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->tp_ops == NULL ||
        umq->tp_ops->umq_tp_mempool_state_get == NULL || mempool_state == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_mempool_state_get(umq->umqh_tp, mempool_id, mempool_state);
}

int umq_mempool_state_refresh(uint64_t umqh, uint32_t mempool_id)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->tp_ops == NULL ||
        umq->tp_ops->umq_tp_mempool_state_refresh == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_mempool_state_refresh(umq->umqh_tp, mempool_id);
}

int umq_dev_info_get(char *dev_name, umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info)
{
    if (dev_name == NULL || strnlen(dev_name, UMQ_DEV_NAME_SIZE) >= UMQ_DEV_NAME_SIZE || umq_dev_info == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

#ifdef UMQ_STATIC_LIB
    if (umq_trans_mode != UMQ_TRANS_MODE_UB && umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return -UMQ_ERR_EINVAL;
    }
#endif

    if (umq_trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[umq_trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not init\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_dev_info_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    return umq_fw->tp_ops->umq_tp_dev_info_get(dev_name, umq_trans_mode, umq_dev_info);
}

umq_dev_info_t *umq_dev_info_list_get(umq_trans_mode_t umq_trans_mode, int *dev_num)
{
    if (dev_num == NULL) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter, errno: %d\n", errno);
        return NULL;
    }

#ifdef UMQ_STATIC_LIB
    if (umq_trans_mode != UMQ_TRANS_MODE_UB && umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        errno = UMQ_ERR_EINVAL;
        return NULL;
    }
#endif

    if (umq_trans_mode >= UMQ_TRANS_MODE_MAX) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "trans info mode[%u] is invalid, errno: %d\n", umq_trans_mode, errno);
        return NULL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[umq_trans_mode];
    if (!umq_fw->enable) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not init, errno: %d\n", umq_trans_mode, errno);
        return NULL;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_dev_info_list_get == NULL) {
        errno = UMQ_ERR_EINVAL;
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support, errno: %d\n", umq_trans_mode, errno);
        return NULL;
    }

    return umq_fw->tp_ops->umq_tp_dev_info_list_get(umq_trans_mode, dev_num);
}

void umq_dev_info_list_free(umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info)
{
#ifdef UMQ_STATIC_LIB
    if (umq_trans_mode != UMQ_TRANS_MODE_UB && umq_trans_mode != UMQ_TRANS_MODE_UB_PLUS) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq static library only support UB transport mode\n");
        return;
    }
#endif

    if (umq_trans_mode >= UMQ_TRANS_MODE_MAX || umq_dev_info == NULL) {
        return;
    }

    umq_framework_t *umq_fw = &g_umq_fws[umq_trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not init\n", umq_trans_mode);
        return;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_dev_info_list_free == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "trans mode %u ops not support\n", umq_trans_mode);
        return;
    }

    umq_fw->tp_ops->umq_tp_dev_info_list_free(umq_trans_mode, umq_dev_info);
}

int umq_cfg_get(uint64_t umqh, umq_cfg_get_t *cfg)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->tp_ops == NULL
        || umq->tp_ops->umq_tp_cfg_get == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq->tp_ops->umq_tp_cfg_get(umq->umqh_tp, cfg);
}

int umq_external_mutex_lock_ops_register(umq_external_mutex_lock_ops_t *ops)
{
    if (ops == NULL || ops->create == NULL || ops->destroy == NULL || ops->lock == NULL || ops->trylock == NULL ||
        ops->unlock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    util_external_mutex_lock_ops_t util_ops;
    util_ops.create = (util_external_mutex_lock *(*)(util_externel_mutex_attr_t attr))ops->create;
    util_ops.destroy = (int (*)(util_external_mutex_lock *m))ops->destroy;
    util_ops.lock = (int (*)(util_external_mutex_lock *m))ops->lock;
    util_ops.unlock = (int (*)(util_external_mutex_lock *m))ops->unlock;
    util_ops.trylock = (int (*)(util_external_mutex_lock *m))ops->trylock;
    util_external_mutex_lock_ops_register(&util_ops);
    return UMQ_SUCCESS;
}

int umq_external_rwlock_ops_register(umq_external_rwlock_ops_t *ops)
{
    if (ops == NULL || ops->create == NULL || ops->destroy == NULL || ops->write_lock == NULL ||
        ops->read_lock == NULL || ops->unlock == NULL || ops->try_read_lock == NULL || ops->try_write_lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }
    util_external_rwlock_ops_t util_ops;
    util_ops.create = (util_external_rwlock *(*)(void))ops->create;
    util_ops.destroy = (int (*)(util_external_rwlock *m))ops->destroy;
    util_ops.read_lock = (int (*)(util_external_rwlock *m))ops->read_lock;
    util_ops.write_lock = (int (*)(util_external_rwlock *m))ops->write_lock;
    util_ops.unlock = (int (*)(util_external_rwlock *m))ops->unlock;
    util_ops.try_read_lock = (int (*)(util_external_rwlock *m))ops->try_read_lock;
    util_ops.try_write_lock = (int (*)(util_external_rwlock *m))ops->try_write_lock;
    util_external_rwlock_ops_register(&util_ops);
    return UMQ_SUCCESS;
}