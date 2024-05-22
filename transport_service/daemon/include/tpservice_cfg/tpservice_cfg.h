/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa socket service header file
 * Author: Ji Lei
 * Create: 2023-06-15
 * Note:
 * History: 2023-06-15 Ji lei Initial version
 */
#ifndef TPSERVICE_CFG_H
#define TPSERVICE_CFG_H

#include "uvs_types.h"
#include "tpsa_service.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_service_show_rsp {
    uvs_net_addr_t service_ip;
    uint16_t service_port;
} tpsa_service_show_rsp_t;

tpsa_response_t *process_tpservice_show(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* TPSERVICE_CFG_H */
