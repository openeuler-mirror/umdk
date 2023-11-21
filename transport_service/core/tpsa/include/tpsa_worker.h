/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker header file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#ifndef TPSA_WORKER_H
#define TPSA_WORKER_H

#include "uvs_types.h"
#include "tpsa_table.h"
#include "tpsa_sock.h"
#include "tpsa_nl.h"
#include "tpsa_net.h"
#include "tpsa_tbl_manage.h"
#include "tpsa_ioctl.h"
#include "uvs_tp_manage.h"
#include "tpsa_types.h"
#include "uvs_lm.h"
#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_worker {
    tpsa_global_cfg_t global_cfg_ctx;
    tpsa_table_t table_ctx;
    tpsa_sock_ctx_t sock_ctx;
    tpsa_nl_ctx_t nl_ctx;
    tpsa_ioctl_ctx_t ioctl_ctx;
    bool stop;
    pthread_t thread;
    int epollfd;
} tpsa_worker_t;

tpsa_worker_t *tpsa_worker_init(uvs_init_attr_t *attr);
void tpsa_worker_uninit(tpsa_worker_t *worker);

/**
 * get ctx.
 * Return: 0 on success, other value on error.
 */
tpsa_worker_t *uvs_get_worker(void);   /* obselete, not to be exposed in the future */

#ifdef __cplusplus
}
#endif

#endif