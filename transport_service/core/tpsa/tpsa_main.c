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
    tpsa_worker_t *worker;
    /* tpsa log init */
    tpsa_log_init();
    tpsa_log_set_level((unsigned)TPSA_VLOG_LEVEL_INFO);

    /* must call net init before config init */
    if (tpsa_net_init() != 0) {
        goto tpsa_log_uninit;
    }

    worker = tpsa_worker_init(attr);
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