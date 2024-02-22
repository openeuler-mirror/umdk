/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa socket service endpoint header file
 * Author: Ji Lei
 * Create: 2023-06-15
 * Note:
 * History: 2023-06-15 Ji lei Initial version
 */
#include <stdlib.h>

#include "tpsa_config.h"
#include "tpsa_log.h"
#include "tpsa_service.h"
#include "tpservice_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

tpsa_response_t *process_tpservice_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(struct tpsa_service_show_rsp));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_service_show_rsp_t *show_rsp = (tpsa_service_show_rsp_t *)(rsp->rsp);
    tpsa_config_t cfg = uvs_get_config();
    show_rsp->service_ip = cfg.tpsa_server_ip;
    show_rsp->service_port = cfg.tpsa_server_port;

    rsp->cmd_type = TPSA_SERVICE_SHOW;
    rsp->rsp_len = (uint32_t)sizeof(tpsa_service_show_rsp_t);

    return rsp;
}

#ifdef __cplusplus
}
#endif

