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
#include "tpsa_service.h"

tpsa_worker_t *g_uvs_worker = NULL;

int uvs_so_init(uvs_init_attr_t *attr)
{
    tpsa_worker_t *worker;

    if (attr == NULL) {
        return -1;
    }

    /* tpsa log init */
    tpsa_log_init();
    tpsa_log_set_level((unsigned)TPSA_VLOG_LEVEL_INFO);
    tpsa_getenv_log_level();

    if (tpsa_check_cpu_core(attr->cpu_core) != 0) {
        attr->cpu_core = -1;
    }
    worker = tpsa_worker_init(attr);
    if (worker == NULL) {
        goto tpsa_log_uninit;
    }
    g_uvs_worker = worker;
    TPSA_LOG_INFO("tpsa so init successfully!\n");
    return 0;

tpsa_log_uninit:
    tpsa_log_uninit();

    return -1;
}

void uvs_so_uninit(void)
{
    tpsa_worker_uninit(g_uvs_worker);
    g_uvs_worker = NULL;
    tpsa_log_uninit();
    return;
}

int uvs_socket_init(uvs_socket_init_attr_t *attr)
{
    tpsa_worker_t *worker = g_uvs_worker;
    if (worker == NULL || attr == NULL) {
        TPSA_LOG_ERR("tpsa socket init failed, worker or attr is NULL!\n");
        return -1;
    }

    worker->tpsa_attr = *attr;
    worker->sock_ctx.epollfd = worker->epollfd;
    if (tpsa_sock_server_init(&worker->sock_ctx, attr) != 0) {
        return -1;
    }

    if (tpsa_worker_socket_init(worker) != 0) {
        tpsa_sock_server_uninit(&worker->sock_ctx);
        return -1;
    }
    TPSA_LOG_INFO("Succeed to listen in worker thread, fd: %d, IP: " EID_FMT ", port: 0x%x.\n",
        worker->sock_ctx.listen_fd, EID_ARGS(attr->server_ip), (uint32_t)attr->server_port);
    return 0;
}

void uvs_socket_uninit(void)
{
    tpsa_worker_t *worker = g_uvs_worker;
    if (worker == NULL) {
        return;
    }
    tpsa_sock_server_uninit(&worker->sock_ctx);
}

int uvs_restore_table(void)
{
    tpsa_ioctl_cfg_t *restore_vtp_tbl_cfg = NULL;
    uint32_t vtp_cnt = 0;

    if (tpsa_get_vtp_table_from_ubcore(g_uvs_worker->ioctl_ctx.ubcore_fd, &restore_vtp_tbl_cfg, &vtp_cnt) != 0) {
        TPSA_LOG_ERR("Fail to get vtp table from ubcore");
        return -1;
    }

    if (tpsa_restore_vtp_table(g_uvs_worker, restore_vtp_tbl_cfg, vtp_cnt) != 0) {
        free(restore_vtp_tbl_cfg);
        return -1;
    }

    free(restore_vtp_tbl_cfg);
    return 0;
}

void uvs_table_input_finish(void)
{
    g_uvs_worker->global_cfg_ctx.tbl_input_done = true;
    g_uvs_worker->global_cfg_ctx.mask.bs.tbl_input_done = 1;
    TPSA_LOG_INFO("succeed to set sip and vport add done");
}

tpsa_worker_t *uvs_get_worker(void)
{
    return g_uvs_worker;
}