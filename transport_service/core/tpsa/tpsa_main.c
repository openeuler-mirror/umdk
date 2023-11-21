/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa so main file
 * Author: Zheng Hongqin
 * Create: 2023-08-18
 * Note:
 * History:
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <pthread.h>
#include "uvs_types.h"
#include "uvs_types_str.h"
#include "uvs_tp_exception.h"
#include "tpsa_log.h"
#include "tpsa_config.h"
#include "tpsa_worker.h"
#include "tpsa_net.h"
#include "tpsa_service.h"

tpsa_worker_t *g_uvs_worker = NULL;

int uvs_so_init(uvs_init_attr_t *attr)
{
    /* tpsa log init */
    tpsa_log_init();
    tpsa_log_set_level((unsigned)TPSA_VLOG_LEVEL_INFO);

    /* must call net init before config init */
    if (tpsa_net_init() != 0) {
        goto tpsa_log_uninit;
    }

    tpsa_worker_t *worker = tpsa_worker_init(attr);
    if (worker == NULL) {
        goto tpsa_net_uninit;
    }
    g_uvs_worker = worker;
    TPSA_LOG_INFO("tpsa so init successfully!\n");
    return 0;

tpsa_net_uninit:
    tpsa_net_uninit();
tpsa_log_uninit:
    tpsa_log_uninit();

    TPSA_LOG_ERR("tpsa so init failed!\n");
    return -1;
}

void uvs_so_uninit(void)
{
    tpsa_worker_uninit(g_uvs_worker);
    tpsa_net_uninit();
    tpsa_log_uninit();
    TPSA_LOG_INFO("tpsa so uninit successfully!\n");
    return;
}

tpsa_worker_t *uvs_get_worker(void)
{
    return g_uvs_worker;
}

int uvs_add_global_info(uvs_global_info_t *info)
{
    if (info == NULL) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    uvs_global_mask_t mask = info->mask;
    uvs_worker->global_cfg_ctx.mask.value |= info->mask.value;
    if (mask.bs.mtu != 0) {
        uvs_worker->global_cfg_ctx.mtu = info->mtu;
        TPSA_LOG_INFO("set mtu to %s\n", uvs_mtu_to_str(uvs_worker->global_cfg_ctx.mtu));
    }
    if (mask.bs.slice != 0) {
        uvs_worker->global_cfg_ctx.slice = info->slice;
        TPSA_LOG_INFO("set slice to %u\n", uvs_worker->global_cfg_ctx.slice);
    }
    if (mask.bs.suspend_period != 0) {
        uvs_worker->global_cfg_ctx.suspend_cnt = info->suspend_cnt;
        TPSA_LOG_INFO("set suspend_period to %u\n", uvs_worker->global_cfg_ctx.suspend_cnt);
    }
    if (mask.bs.suspend_cnt != 0) {
        uvs_worker->global_cfg_ctx.suspend_period = info->suspend_period;
        TPSA_LOG_INFO("set suspend_cnt to %u\n", uvs_worker->global_cfg_ctx.suspend_period);
    }
    if (mask.bs.sus2err_period != 0) {
        uvs_worker->global_cfg_ctx.sus2err_period = info->sus2err_period;
        uvs_set_sus2err_period(info->sus2err_period);
        TPSA_LOG_INFO("set sus2err_period to %u\n", uvs_worker->global_cfg_ctx.sus2err_period);
    }

    int ret = uvs_ioctl_cmd_set_global_cfg(&uvs_worker->ioctl_ctx, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to add global configurations.\n");
        return -1;
    }

    TPSA_LOG_INFO("Add global configurations successfully!\n");
    return 0;
}

uvs_global_info_t *uvs_list_global_info(void)
{
    uvs_global_info_t *info = (uvs_global_info_t *)calloc(1, sizeof(uvs_global_info_t));
    if (info == NULL) {
        TPSA_LOG_ERR("failed to alloc global cfg.\n");
        return NULL;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    info->mtu = uvs_worker->global_cfg_ctx.mtu;
    info->slice = uvs_worker->global_cfg_ctx.slice;
    info->suspend_cnt = uvs_worker->global_cfg_ctx.suspend_cnt;
    info->suspend_period = uvs_worker->global_cfg_ctx.suspend_period;
    info->sus2err_period = uvs_worker->global_cfg_ctx.sus2err_period;

    return info;
}