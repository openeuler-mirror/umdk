/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: chip node
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.model;

import lombok.Data;

import java.util.HashSet;
import java.util.Set;

@Data
public class ChipNode {
    private ChipRef chipRef;

    private Set<String> inPorts = new HashSet<>();

    private Set<String> excludeChips = new HashSet<>();

    public ChipNode(ChipRef chipRef) {
        this.chipRef = chipRef;
    }

    public ChipNode(ChipRef chipRef, Set<String> excludeChips) {
        this.chipRef = chipRef;
        this.excludeChips.addAll(excludeChips);
    }
}
