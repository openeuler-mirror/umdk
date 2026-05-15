/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: tpsa topo internal helpers
 */

#ifndef TPSA_TOPO_HELPER_H
#define TPSA_TOPO_HELPER_H

#include "uvs_api.h"

int uvs_update_main_ue_eid_table_by_topo(const struct urma_topo_node *topo,
    uint32_t topo_num);

#endif
