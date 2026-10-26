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
public enum SuperNodeType {
    ATLAS950_GALAXY_RACK32("atlas950_galaxy_rack32"),
    ATLAS950_GALAXY_RACK32_SUPERNODE_128("atlas950_galaxy_rack32_supernode_128");

    private final String value;

    SuperNodeType(String value) {
        this.value = value;
    }
}
