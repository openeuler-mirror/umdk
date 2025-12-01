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

#include "dfx.h"
#include "perf.h"
#include "umq_vlog.h"
#include "umq_inner.h"
#include "umq_qbuf_pool.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_errno.h"
#include "urpc_util.h"

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
} umq_framework_t;

static bool g_umq_inited = false;

static umq_init_cfg_t *g_umq_config;
static pthread_mutex_t g_umq_config_mutex_lock = PTHREAD_MUTEX_INITIALIZER;

static umq_framework_t g_umq_fws[UMQ_TRANS_MODE_MAX] = {
    [UMQ_TRANS_MODE_UB] = {
        .mode = UMQ_TRANS_MODE_UB,
        .enable = false,

        .dlopen_so_name = "libumq_ub.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ub_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ub_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,
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
    },
    [UMQ_TRANS_MODE_UB_PLUS] = {
        .mode = UMQ_TRANS_MODE_UB_PLUS,
        .enable = false,

        .dlopen_so_name = "libumq_ub.so",
        .dlhandler = NULL,

        .ops_get_funcname = "umq_ub_plus_ops_get",
        .ops_get_func = NULL,
        .tp_ops = NULL,
        .ctx = NULL,

        .pro_ops_get_funcname = "umq_pro_ub_plus_ops_get",
        .pro_ops_get_func = NULL,
        .pro_tp_ops = NULL,
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
    },
};

static int umq_fw_log_config_set(umq_log_config_t *config)
{
    uint8_t fw_i = 0;
    for (; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        if (!umq_fw->enable) {
            continue;
        }
        if ((umq_fw == NULL) || (umq_fw->tp_ops == NULL) || (umq_fw->tp_ops->umq_tp_log_config_set == NULL)) {
            UMQ_VLOG_ERR("umq_fw invalid\n");
            goto RESET_LOG;
        }
        if (umq_fw->tp_ops->umq_tp_log_config_set(config) != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("log config set failed\n");
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
        if (umq_fw->tp_ops->umq_tp_log_config_reset() != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("log config reset failed, j = %u\n", j);
        }
    }
    return -UMQ_ERR_EINVAL;
}

int umq_log_config_set(umq_log_config_t *config)
{
    if (config == NULL) {
        UMQ_VLOG_ERR("invalid configure\n");
        return -UMQ_ERR_EINVAL;
    }

    if ((config->log_flag & UMQ_LOG_FLAG_LEVEL) &&
        (config->level < UMQ_LOG_LEVEL_EMERG || config->level >= UMQ_LOG_LEVEL_MAX)) {
        UMQ_VLOG_ERR("invalid log level %d\n", config->level);
        return -UMQ_ERR_EINVAL;
    }

    umq_vlog_config_t *log_config = umq_get_log_config();
    (void)pthread_mutex_lock(&log_config->log_lock);
    if (config->log_flag & UMQ_LOG_FLAG_FUNC) {
        if (config->func == NULL) {
            log_config->ctx.vlog_output_func = default_vlog_output;
            UMQ_VLOG_INFO("set log configuration successful, log output function: default\n");
        } else {
            log_config->ctx.vlog_output_func = config->func;
            UMQ_VLOG_INFO("set log configuration successful, log output function: user defined\n");
        }
    }

    if (config->log_flag & UMQ_LOG_FLAG_LEVEL) {
        log_config->ctx.level = (util_vlog_level_t)config->level;
        UMQ_VLOG_INFO("set log configuration successful, log level: %d\n", config->level);
    }
    if (umq_fw_log_config_set(config) != UMQ_SUCCESS) {
        (void)pthread_mutex_unlock(&log_config->log_lock);
        return -UMQ_ERR_EINVAL;
    }
    if ((config->log_flag & UMQ_LOG_FLAG_RATE_LIMITED)) {
        log_config->ctx.rate_limited.interval_ms = config->rate_limited.interval_ms;
        log_config->ctx.rate_limited.num = config->rate_limited.num;
        UMQ_VLOG_INFO("set log configuration successful, limited interval(ms): %u, limited num: %u\n",
                      config->rate_limited.interval_ms, config->rate_limited.num);
    }
    (void)pthread_mutex_unlock(&log_config->log_lock);

    return UMQ_SUCCESS;
}

int umq_log_config_get(umq_log_config_t *config)
{
    if (config == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_vlog_config_t *log_config = umq_get_log_config();
    (void)pthread_mutex_lock(&log_config->log_lock);
    config->log_flag = log_config->log_flag;
    config->level = (umq_log_level_t)log_config->ctx.level;
    config->func = log_config->ctx.vlog_output_func;
    config->rate_limited.interval_ms = log_config->ctx.rate_limited.interval_ms;
    config->rate_limited.num = log_config->ctx.rate_limited.num;
    if (config->func == default_vlog_output) {
        config->func = NULL;
    }
    (void)pthread_mutex_unlock(&log_config->log_lock);

    return UMQ_SUCCESS;
}

static void framework_uninit(void)
{
    for (uint8_t fw_i = 0; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        umq_fw->pro_tp_ops = NULL;
        umq_fw->pro_ops_get_func = NULL;

        if ((umq_fw->ctx != NULL) && (umq_fw->tp_ops != NULL) && (umq_fw->tp_ops->umq_tp_uninit != NULL)) {
            umq_fw->tp_ops->umq_tp_uninit(umq_fw->ctx);
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

void umq_uninit(void)
{
    if (!g_umq_inited) {
        UMQ_VLOG_ERR("umq has not been inited\n");
        return;
    }

    umq_dfx_uninit();
    framework_uninit();

    if (g_umq_config != NULL) {
        free(g_umq_config);
        g_umq_config = NULL;
    }
    g_umq_inited = false;
}

static int load_symbol(void *handle, void **func, const char *symbol)
{
    *func = dlsym(handle, symbol);
    if (*func == NULL) {
        UMQ_VLOG_ERR("dlsym failed\n");
        return UMQ_FAIL;
    }
    return UMQ_SUCCESS;
}

static int umq_framework_init(umq_framework_t *umq_fw, umq_init_cfg_t *cfg)
{
    umq_fw->dlhandler = dlopen(umq_fw->dlopen_so_name, RTLD_LAZY | RTLD_GLOBAL);
    if (umq_fw->dlhandler == NULL) {
        UMQ_VLOG_ERR("open so failed, err: %s\n", dlerror());
        return UMQ_FAIL;
    }

    if (load_symbol(umq_fw->dlhandler,
        (void **)&umq_fw->ops_get_func, umq_fw->ops_get_funcname) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("load_symbol ops failed\n");
        goto CLONE_SO;
    }

    umq_fw->tp_ops = umq_fw->ops_get_func();
    if ((umq_fw->tp_ops == NULL) || (umq_fw->tp_ops->umq_tp_init == NULL)) {
        UMQ_VLOG_ERR("get ops func failed\n");
        goto UNLOAD_OPS_GET_FUNC;
    }

    umq_fw->ctx = umq_fw->tp_ops->umq_tp_init(cfg);
    if (umq_fw->ctx == NULL) {
        UMQ_VLOG_ERR("tp init failed\n");
        goto PUT_TP_OPS;
    }

    if (load_symbol(umq_fw->dlhandler,
        (void **)&umq_fw->pro_ops_get_func, umq_fw->pro_ops_get_funcname) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("load_symbol pro_ops failed\n");
        goto UNINIT_UMQ_TP;
    }

    umq_fw->pro_tp_ops = umq_fw->pro_ops_get_func();
    if (umq_fw->pro_tp_ops == NULL) {
        UMQ_VLOG_ERR("get pro_ops func failed\n");
        goto UNLOAD_PRO_OPS_GET_FUNC;
    }

    return UMQ_SUCCESS;

UNLOAD_PRO_OPS_GET_FUNC:
    umq_fw->pro_ops_get_func = NULL;

UNINIT_UMQ_TP:
    if (umq_fw->tp_ops->umq_tp_uninit != NULL) {
        umq_fw->tp_ops->umq_tp_uninit(umq_fw->ctx);
        umq_fw->ctx = NULL;
    }

PUT_TP_OPS:
    umq_fw->tp_ops = NULL;

UNLOAD_OPS_GET_FUNC:
    umq_fw->ops_get_func = NULL;

CLONE_SO:
    if (umq_fw->dlhandler != NULL) {
        dlclose(umq_fw->dlhandler);
    }
    umq_fw->enable = false;
    return UMQ_FAIL;
}

int umq_init(umq_init_cfg_t *cfg)
{
    if (g_umq_inited) {
        UMQ_VLOG_ERR("umq has already been inited\n");
        return -UMQ_ERR_EEXIST;
    }

    if (cfg == NULL) {
        UMQ_VLOG_ERR("cfg is null\n");
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->trans_info_num > MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR("trans_info_num[%u] is invalid\n", cfg->trans_info_num);
        return -UMQ_ERR_EINVAL;
    }

    if (cfg->headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR("headroom size %u exceeds the maximum value\n", cfg->headroom_size);
        return -UMQ_ERR_EINVAL;
    }

    if ((cfg->feature & UMQ_FEATURE_ENABLE_TOKEN_POLICY) != 0 && urpc_rand_seed_init() != 0) {
        UMQ_VLOG_ERR("rand seed init failed\n");
        return -UMQ_ERR_EINVAL;
    }
    
    if (umq_buf_size_pow_small_set(cfg->block_cfg.small_block_size) != UMQ_SUCCESS) {
        return -UMQ_ERR_EINVAL;
    }

    for (uint8_t trans_info_i = 0; trans_info_i < cfg->trans_info_num; trans_info_i++) {
        umq_trans_info_t *info = &cfg->trans_info[trans_info_i];
        if (info->trans_mode >= UMQ_TRANS_MODE_MAX || info->trans_mode < 0) {
            continue;
        }

        g_umq_fws[info->trans_mode].enable = true;
    }

    for (uint8_t fw_i = 0; fw_i < UMQ_TRANS_MODE_MAX; fw_i++) {
        umq_framework_t *umq_fw = &g_umq_fws[fw_i];
        if (!umq_fw->enable) {
            continue;
        }

        if (umq_framework_init(umq_fw, cfg) != UMQ_SUCCESS) {
            UMQ_VLOG_ERR("trans mode %u umq framework init failed\n", fw_i);
            goto FW_UNINIT;
        }
    }

    if (umq_dfx_init(cfg) != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq dfx init failed\n");
        goto FW_UNINIT;
    }

    g_umq_config = (umq_init_cfg_t *)malloc(sizeof(umq_init_cfg_t));
    if (g_umq_config == NULL) {
        UMQ_VLOG_ERR("malloc umq config failed\n");
        goto DFX_UNINIT;
    }
    (void)memcpy(g_umq_config, cfg, sizeof(umq_init_cfg_t));

    g_umq_inited = true;
    return UMQ_SUCCESS;

DFX_UNINIT:
    umq_dfx_uninit();

FW_UNINIT:
    framework_uninit();
    return UMQ_FAIL;
}

uint64_t umq_create(umq_create_option_t *option)
{
    if (option == NULL) {
        UMQ_VLOG_ERR("create option is null\n");
        return UMQ_INVALID_HANDLE;
    }

    if ((option->trans_mode >= UMQ_TRANS_MODE_MAX) || (option->trans_mode < 0) || (option->name[0] == '\0')) {
        UMQ_VLOG_ERR("trans_mode[%d] not support or name is null\n", option->trans_mode);
        return UMQ_INVALID_HANDLE;
    }

    umq_framework_t *umq_fw = &g_umq_fws[option->trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR("trans_mode[%d] is not enabled on initialize\n", option->trans_mode);
        return UMQ_INVALID_HANDLE;
    }

    umq_t *umq = calloc(1, sizeof(umq_t));
    if (umq == NULL) {
        UMQ_VLOG_ERR("alloc umq failed\n");
        return UMQ_INVALID_HANDLE;
    }
    umq->mode = option->trans_mode;
    umq->tp_ops = umq_fw->tp_ops;
    umq->pro_tp_ops = umq_fw->pro_tp_ops;
    if (umq->tp_ops->umq_tp_create == NULL) {
        UMQ_VLOG_ERR("tp create function is null\n");
        goto ERR;
    }
    umq->umqh_tp = umq->tp_ops->umq_tp_create((uint64_t)(uintptr_t)umq, umq_fw->ctx, option);
    if (umq->umqh_tp == 0) {
        UMQ_VLOG_ERR("create transport resource failed\n");
        goto ERR;
    }

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
        UMQ_VLOG_ERR("umqh invalid\n");
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
        UMQ_VLOG_ERR("bind_info or umqh invalid\n");
        return 0;
    }

    return umq->tp_ops->umq_tp_bind_info_get(umq->umqh_tp, bind_info, bind_info_size);
}

int umq_bind(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((bind_info == NULL) || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_bind == NULL)) {
        UMQ_VLOG_ERR("bind_info or umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_bind(umq->umqh_tp, bind_info, bind_info_size);
}

int umq_unbind(uint64_t umqh)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_unbind == NULL)) {
        UMQ_VLOG_ERR("umqh invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_unbind(umq->umqh_tp);
}

umq_buf_t *umq_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh, umq_alloc_option_t *option)
{
    if (!g_umq_inited || request_qbuf_num == 0 || request_qbuf_num > UMQ_BATCH_SIZE
        || request_size > UMQ_MAX_BUF_REQUEST_SIZE) {
        UMQ_VLOG_ERR("parma invalid or umq initialized\n");
        return NULL;
    }
    uint32_t headroom_size = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0) ?
        option->headroom_size : umq_qbuf_headroom_get();
    if (headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR("headroom size %u exceeds the maximum value\n", headroom_size);
        return NULL;
    }
    umq_buf_mode_t mode = umq_qbuf_mode_get();
    uint32_t factor = (mode == UMQ_BUF_SPLIT) ? 0 : sizeof(umq_buf_t);
    if (umqh == UMQ_INVALID_HANDLE) {
        umq_buf_list_t head;
        QBUF_LIST_INIT(&head);
        if (request_size + headroom_size + factor < umq_buf_size_middle()) {
            if (umq_qbuf_alloc(request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
                return NULL;
            }
        } else {
            enum HUGE_QBUF_POOL_SIZE_TYPE type = (request_size + headroom_size + factor >= umq_buf_size_big())
                                                     ? HUGE_QBUF_POOL_SIZE_TYPE_BIG
                                                     : HUGE_QBUF_POOL_SIZE_TYPE_MID;
            if (umq_huge_qbuf_alloc(type, request_size, request_qbuf_num, option, &head) != UMQ_SUCCESS) {
                return NULL;
            }
        }

        return QBUF_LIST_FIRST(&head);
    }

    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if ((umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_buf_alloc == NULL)) {
        UMQ_VLOG_ERR("umqh or qbuf invalid\n");
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
        UMQ_VLOG_ERR("umqh or qbuf invalid\n");
        return;
    }

    umq->tp_ops->umq_tp_buf_free(qbuf, umq->umqh_tp);
}

umq_buf_t *umq_buf_break_and_free(umq_buf_t *qbuf)
{
    // break qbuf list for many batchs connected, only release the first batch.
    umq_buf_t *next_batch_qbuf = NULL;
    umq_buf_t *tmp_buf = qbuf;
    uint32_t rest_data_size = tmp_buf->total_data_size;
    while (tmp_buf && rest_data_size > 0) {
        if (rest_data_size <= tmp_buf->data_size) {
            next_batch_qbuf = tmp_buf->qbuf_next;
            tmp_buf->qbuf_next = NULL;
            break;
        }
        rest_data_size -= tmp_buf->data_size;
        tmp_buf = tmp_buf->qbuf_next;
    }
    umq_buf_free(qbuf);
    return next_batch_qbuf;
}

int umq_buf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size)
{
    if (!g_umq_inited || qbuf == NULL) {
        return -UMQ_ERR_EINVAL;
    }

    if (headroom_size > UMQ_HEADROOM_SIZE_LIMIT) {
        UMQ_VLOG_ERR("headroom size %u exceeds the maximum value\n", headroom_size);
        return -UMQ_ERR_EINVAL;
    }

    if (qbuf->umqh == UMQ_INVALID_HANDLE) {
        return umq_qbuf_headroom_reset(qbuf, headroom_size);
    }

    umq_t *umq = (umq_t *)(uintptr_t)qbuf->umqh;
    if ((umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_buf_headroom_reset == NULL)) {
        UMQ_VLOG_ERR("umqh or tp invalid\n");
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
    uint32_t total_data_size = 0;
    while (head != NULL) {
        head->data_size = head->buf_size;
        total_data_size += head->data_size;

        head = head->qbuf_next;
    }
    qbuf->total_data_size = total_data_size;

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
        UMQ_VLOG_ERR("umqh or qbuf invalid\n");
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
        UMQ_VLOG_ERR("umqh invalid\n");
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
        UMQ_VLOG_ERR("umqh invalid\n");
        return;
    }

    umq->tp_ops->umq_tp_notify(umq->umqh_tp);
    umq_perf_record_write(UMQ_PERF_RECORD_NOTIFY, start_timestamp);
    return;
}

int umq_rearm_interrupt(uint64_t umqh, bool solicated, umq_interrupt_option_t *option)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_rearm_interrupt == NULL)) {
        UMQ_VLOG_ERR("umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_rearm_interrupt(umq->umqh_tp, solicated, option);
}

int32_t umq_wait_interrupt(uint64_t wait_umqh, int time_out, umq_interrupt_option_t *option)
{
    umq_t *umq = (umq_t *)(uintptr_t)wait_umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_wait_interrupt == NULL)) {
        UMQ_VLOG_ERR("umqh or option invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_wait_interrupt(umq->umqh_tp, time_out, option);
}

void umq_ack_interrupt(uint64_t umqh, uint32_t nevents, umq_interrupt_option_t *option)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if (option == NULL || (umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_ack_interrupt == NULL)) {
        UMQ_VLOG_ERR("umqh or option invalid\n");
        return;
    }

    return umq->tp_ops->umq_tp_ack_interrupt(umq->umqh_tp, nevents, option);
}

int umq_buf_split(umq_buf_t *head, umq_buf_t *node)
{
    if (head == NULL || node == NULL || head == node) {
        UMQ_VLOG_ERR("head or node invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_buf_t *tmp = head;
    while (tmp->qbuf_next != NULL && tmp->qbuf_next != node) {
        tmp = tmp->qbuf_next;
    }

    if (tmp->qbuf_next == NULL) {
        UMQ_VLOG_ERR("target node not found in the buf list\n");
        return -UMQ_ERR_EINVAL;
    }

    tmp->qbuf_next = NULL;
    return UMQ_SUCCESS;
}

umq_state_t umq_state_get(uint64_t umqh)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;

    if ((umq == NULL) || (umq->umqh_tp == UMQ_INVALID_HANDLE) || (umq->tp_ops == NULL) ||
        (umq->tp_ops->umq_tp_state_get == NULL)) {
        UMQ_VLOG_ERR("umqh invalid\n");
        return QUEUE_STATE_MAX;
    }

    return umq->tp_ops->umq_tp_state_get(umq->umqh_tp);
}

int umq_async_event_fd_get(umq_trans_info_t *trans_info)
{
    if (trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX || trans_info->trans_mode < 0) {
        UMQ_VLOG_ERR("trans info invalid\n");
        return UMQ_INVALID_FD;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR("framework instance disabled\n");
        return UMQ_INVALID_FD;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_async_event_fd_get == NULL) {
        UMQ_VLOG_ERR("get event fd failed\n");
        return UMQ_INVALID_FD;
    }
    return umq_fw->tp_ops->umq_tp_async_event_fd_get(trans_info);
}

int umq_get_async_event(umq_trans_info_t *trans_info, umq_async_event_t *event)
{
    if (trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX || trans_info->trans_mode < 0) {
        UMQ_VLOG_ERR("trans info invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR("framework instance disabled\n");
        return -UMQ_ERR_EINVAL;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_async_event_get == NULL) {
        UMQ_VLOG_ERR("ops invalid\n");
        return -UMQ_ERR_EINVAL;
    }
    return umq_fw->tp_ops->umq_tp_async_event_get(trans_info, event);
}

void umq_ack_async_event(umq_async_event_t *event)
{
    if (event == NULL || event->trans_info.trans_mode >= UMQ_TRANS_MODE_MAX || event->trans_info.trans_mode < 0) {
        UMQ_VLOG_ERR("event invalid\n");
        return;
    }

    umq_framework_t *umq_fw = &g_umq_fws[event->trans_info.trans_mode];

    if (!umq_fw->enable) {
        UMQ_VLOG_ERR("framework instance disabled\n");
        return;
    }
    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_aync_event_ack == NULL) {
        UMQ_VLOG_ERR("ops invalid\n");
        return;
    }
    return umq_fw->tp_ops->umq_tp_aync_event_ack(event);
}

int umq_dev_add(umq_trans_info_t *trans_info)
{
    if (!g_umq_inited) {
        UMQ_VLOG_ERR("umq has not been inited\n");
        return -UMQ_ERR_EINVAL;
    }

    if (trans_info == NULL || trans_info->trans_mode >= UMQ_TRANS_MODE_MAX) {
        UMQ_VLOG_ERR("trans info invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[trans_info->trans_mode];
    int ret = UMQ_SUCCESS;
    pthread_mutex_lock(&g_umq_config_mutex_lock);
    if (g_umq_config->trans_info_num >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR("trans info num[%u] exceeds maximum[%u] limit\n",
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
            UMQ_VLOG_ERR("umq framework init failed\n");
            goto DECREASE_TRANS_INFO_NUM;
        }
        pthread_mutex_unlock(&g_umq_config_mutex_lock);
        return UMQ_SUCCESS;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_dev_add == NULL) {
        UMQ_VLOG_ERR("trans mode [%u] tp ops invalid\n", trans_info->trans_mode);
        ret = -UMQ_ERR_EINVAL;
        goto DECREASE_TRANS_INFO_NUM;
    }

    // add new dev
    ret = umq_fw->tp_ops->umq_tp_dev_add(trans_info, g_umq_config);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("add dev failed\n");
        goto DECREASE_TRANS_INFO_NUM;
    }
    pthread_mutex_unlock(&g_umq_config_mutex_lock);
    return ret;

DECREASE_TRANS_INFO_NUM:
    g_umq_config->trans_info_num--;

UNLOCK:
    pthread_mutex_unlock(&g_umq_config_mutex_lock);

return ret;
}

int umq_get_route_list(const umq_route_t *route, umq_trans_mode_t umq_trans_mode, umq_route_list_t *route_list)
{
    if (route == NULL || route_list == NULL) {
        UMQ_VLOG_ERR("invalid parameter\n");
        return -UMQ_ERR_EINVAL;
    }

    if (umq_trans_mode >= MAX_UMQ_TRANS_INFO_NUM) {
        UMQ_VLOG_ERR("trans info num[%u] exceeds maximum[%u] limit\n", umq_trans_mode, MAX_UMQ_TRANS_INFO_NUM);
        return -UMQ_ERR_EINVAL;
    }

    umq_framework_t *umq_fw = &g_umq_fws[umq_trans_mode];
    if (!umq_fw->enable) {
        UMQ_VLOG_ERR("trans mode %u ops not init\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }

    if (umq_fw->tp_ops == NULL || umq_fw->tp_ops->umq_tp_get_topo == NULL) {
        UMQ_VLOG_ERR("trans mode %u ops not support\n", umq_trans_mode);
        return -UMQ_ERR_EINVAL;
    }
    
    return umq_fw->tp_ops->umq_tp_get_topo(route, route_list);
}

int umq_user_ctl(uint64_t umqh, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out)
{
    umq_t *umq = (umq_t *)(uintptr_t)umqh;
    if (umq == NULL || umq->umqh_tp == UMQ_INVALID_HANDLE || umq->tp_ops->umq_tp_user_ctl == NULL || in == NULL
        || out == NULL) {
        UMQ_VLOG_ERR("parameter invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return umq->tp_ops->umq_tp_user_ctl(umq->umqh_tp, in, out);
}
