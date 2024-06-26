/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process global cfg table ops file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#include <stdlib.h>

#include "tpsa_log.h"
#include "tpsa_daemon.h"
#include "uvs_api.h"
#include "global_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_DEFAULT_UDP_PORT_START 10000
#define UVS_DEFAULT_UDP_PORT_END 60000
#define UVS_DEFAULT_UDP_RANGE 8

tpsa_response_t *process_global_cfg_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    uvs_global_info_t *global_cfg = NULL;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %u, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    global_cfg = uvs_list_global_info();
    if (global_cfg == NULL) {
        TPSA_LOG_ERR("failed to get global_cfg from uvs\n");
        return NULL;
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_global_cfg_show_rsp_t));
    if (rsp == NULL) {
        free(global_cfg);
        return NULL;
    }

    tpsa_global_cfg_show_rsp_t *show_rsp = (tpsa_global_cfg_show_rsp_t *)rsp->rsp;

    show_rsp->mtu_show = global_cfg->mtu;
    show_rsp->slice = global_cfg->slice;
    show_rsp->suspend_period = global_cfg->suspend_period;
    show_rsp->suspend_cnt = global_cfg->suspend_cnt;
    show_rsp->sus2err_period = global_cfg->sus2err_period;
    show_rsp->sus2err_cnt = global_cfg->sus2err_cnt;
    show_rsp->tp_fast_destroy = tpsa_get_tp_fast_destroy();
    show_rsp->tbl_input_done = global_cfg->tbl_input_done;

    rsp->cmd_type = GLOBAL_CFG_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_global_cfg_show_rsp_t);

    free(global_cfg);
    return rsp;
}

void set_req_to_global_info(tpsa_global_cfg_set_req_t *set_req, uvs_global_info_t *global_cfg)
{
    /* global_cfg->mask and local global mask is different */
    global_cfg->mask.bs.mtu = set_req->mask.bs.mtu;
    global_cfg->mask.bs.slice = set_req->mask.bs.slice;
    global_cfg->mask.bs.suspend_period = set_req->mask.bs.suspend_period;
    global_cfg->mask.bs.suspend_cnt = set_req->mask.bs.suspend_cnt;
    global_cfg->mask.bs.sus2err_period = set_req->mask.bs.sus2err_period;
    global_cfg->mask.bs.sus2err_cnt = set_req->mask.bs.sus2err_cnt;
    global_cfg->mask.bs.tbl_input_done = set_req->mask.bs.tbl_input_done;
    global_cfg->mask.bs.udp_port_start = 1;
    global_cfg->mask.bs.udp_port_end = 1;
    global_cfg->mask.bs.udp_range = 1;

    global_cfg->mtu = set_req->mtu_set;
    global_cfg->slice = set_req->slice;
    global_cfg->suspend_period = set_req->suspend_period;
    global_cfg->suspend_cnt = set_req->suspend_cnt;
    global_cfg->sus2err_period = set_req->sus2err_period;
    global_cfg->sus2err_cnt = set_req->sus2err_cnt;
    tpsa_set_tp_fast_destroy(set_req->tp_fast_destroy);
    global_cfg->tbl_input_done = set_req->tbl_input_done;
    /* current uvs cmd doesn't have these params, use default value instead */
    global_cfg->udp_port_start = UVS_DEFAULT_UDP_PORT_START;
    global_cfg->udp_port_end = UVS_DEFAULT_UDP_PORT_END;
    global_cfg->udp_range = UVS_DEFAULT_UDP_RANGE;
}

tpsa_response_t *process_global_cfg_set(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_global_cfg_set_req_t *set_req = NULL;
    uvs_global_info_t *global_cfg = NULL;
    int ret;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %u, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    set_req = (tpsa_global_cfg_set_req_t *)req->req;
    global_cfg = (uvs_global_info_t *)calloc(1, sizeof(uvs_global_info_t));
    if (global_cfg == NULL) {
        return NULL;
    }
    set_req_to_global_info(set_req, global_cfg);

    ret = uvs_add_global_info(global_cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add global cfg\n");
        free(global_cfg);
        return NULL;
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_global_cfg_set_rsp_t));
    if (rsp == NULL) {
        free(global_cfg);
        return NULL;
    }
    tpsa_global_cfg_set_rsp_t *set_rsp = (tpsa_global_cfg_set_rsp_t *)rsp->rsp;
    set_rsp->res = 0;
    rsp->cmd_type = GLOBAL_CFG_SET;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_global_cfg_set_rsp_t);

    free(global_cfg);
    return rsp;
}

#ifdef __cplusplus
}
#endif

