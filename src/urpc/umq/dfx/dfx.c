/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq dfx
 * Create: 2025-10-29
 */

#include "umq_api.h"
#include "umq_types.h"
#include "umq_errno.h"
#include "umq_vlog.h"
#include "perf.h"
#include "dfx.h"

int umq_dfx_init(umq_init_cfg_t *cfg)
{
    if (((cfg->feature & UMQ_FEATURE_ENABLE_PERF) != 0) && umq_perf_init() != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("umq dfx perf init failed\n");
        return UMQ_FAIL;
    }
    return UMQ_SUCCESS;
}

void umq_dfx_uninit(void)
{
    umq_perf_uninit();
}

static void umq_dfx_process_perf_cmd(umq_dfx_cmd_t *cmd, umq_dfx_result_t *result_ctl)
{
    umq_perf_cmd_id_t cmd_id = cmd->perf_cmd_id;
    switch (cmd_id) {
        case UMQ_PERF_CMD_START:
            result_ctl->err_code = umq_perf_start(cmd->perf_in_param.thresh_array, cmd->perf_in_param.thresh_num);
            result_ctl->perf_cmd_id = UMQ_PERF_CMD_START;
            break;
        case UMQ_PERF_CMD_STOP:
            result_ctl->err_code = umq_perf_stop();
            result_ctl->perf_cmd_id = UMQ_PERF_CMD_STOP;
            break;
        case UMQ_PERF_CMD_CLEAR:
            result_ctl->err_code = umq_perf_clear();
            result_ctl->perf_cmd_id = UMQ_PERF_CMD_CLEAR;
            break;
        case UMQ_PERF_CMD_GET_RESULT:
            result_ctl->err_code = umq_perf_info_get(&result_ctl->perf_out_param);
            result_ctl->perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;
            break;
        case UMQ_PERF_CMD_MAX:
        default:
            result_ctl->err_code = UMQ_FAIL;
            result_ctl->perf_cmd_id = UMQ_PERF_CMD_MAX;
            break;
    }
}

void umq_dfx_cmd_process(umq_dfx_cmd_t *cmd, umq_dfx_result_t *result_ctl)
{
    if ((cmd == NULL) || (result_ctl == NULL)) {
        UMQ_VLOG_ERR("umq dfx cmd process invalid param\n");
        return;
    }

    umq_dfx_module_id_t module_id = cmd->module_id;
    switch (module_id) {
        case UMQ_DFX_MODULE_PERF:
            umq_dfx_process_perf_cmd(cmd, result_ctl);
            result_ctl->module_id = UMQ_DFX_MODULE_PERF;
            break;
        case UMQ_DFX_MODULE_STATS:
        default:
            result_ctl->err_code = UMQ_FAIL;
            break;
    }
}