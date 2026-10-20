/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-10-22
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.Getter;

@Getter
public enum NodeType {
    NPU("npu"),
    L1_SW("l1_sw"),
    L2_SW("l2_sw");

    private final String value;

    NodeType(String value) {
        this.value = value;
    }
}
