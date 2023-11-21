/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa daemon header file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#ifndef TPSA_DAEMON_H
#define TPSA_DAEMON_H

#include "tpsa_worker.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_daemon_context {
    bool keeper_runnig;
    tpsa_worker_t *worker;
} tpsa_daemon_ctx_t;

tpsa_daemon_ctx_t *get_tpsa_daemon_ctx(void);

#ifdef __cplusplus
}

#endif

#endif /* TPSA_DAEMON_H */
