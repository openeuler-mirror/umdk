/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process sip table ops header file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#ifndef GLOBAL_CFG_H
#define GLOBAL_CFG_H

#include <netinet/in.h>
#include "tpsa_service.h"
#include "tpsa_worker.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_global_cfg_show_rsp {
    uvs_mtu_t mtu_show;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
    bool tp_fast_destroy;
} tpsa_global_cfg_show_rsp_t;

typedef struct tpsa_global_cfg_set_req {
    uvs_global_cfg_mask_t mask;
    uvs_mtu_t mtu_set;
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    uint32_t sus2err_period;
    bool tp_fast_destroy;
} tpsa_global_cfg_set_req_t;

typedef struct tpsa_global_cfg_set_rsp {
    int32_t res;
} tpsa_global_cfg_set_rsp_t;

tpsa_response_t *process_global_cfg_show(tpsa_request_t *req, ssize_t read_len);
tpsa_response_t *process_global_cfg_set(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* GLOBAL_CFG_H */
