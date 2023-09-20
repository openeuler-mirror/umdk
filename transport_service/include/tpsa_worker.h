/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker header file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#ifndef TPSA_NETLINK_H
#define TPSA_NETLINK_H

#include "tpsa_sock.h"
#include "tpsa_nl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_worker {
    tpsa_sock_ctx_t sock_ctx;
    tpsa_nl_ctx_t nl_ctx;
    bool stop;
    pthread_t thread;
    int epollfd;
} tpsa_worker_t;

tpsa_worker_t *tpsa_worker_init(void);
void tpsa_worker_unint(tpsa_worker_t *worker);

#ifdef __cplusplus
}
#endif

#endif