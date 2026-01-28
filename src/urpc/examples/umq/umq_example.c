/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq example
 * Create: 2025-7-24
 * Note:
 * History: 2025-7-24
 */

#include "umq_example_common.h"
#include "umq_example_base.h"
#include "umq_example_pro.h"
#include "connection_setup_tool.h"

int main(int argc, char *argv[])
{
    struct urpc_example_config cfg = {0};
    int ret = parse_arguments(argc, argv, &cfg);
    if (ret != 0) {
        LOG_PRINT_ERR("parse_arguments failed, ret: %d\n", ret);
        goto EXIT;
    }

    if (cfg.case_type == CASE_TYPE_CONNEXTION) {
        return connection_setup_tool(&cfg);
    }

    if ((cfg.feature & UMQ_FEATURE_API_PRO) != 0) {
        // 运行PRO类型的example
        ret = run_umq_example_pro(&cfg);
    } else {
        // 运行BASE类型的example
        ret = run_umq_example(&cfg);
    }

EXIT:
    if (cfg.dev_name != NULL) {
        free(cfg.dev_name);
    }

    if (cfg.server_ip != NULL) {
        free(cfg.server_ip);
    }

    return ret;
}
