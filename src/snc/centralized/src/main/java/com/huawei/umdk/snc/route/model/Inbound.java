/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route description
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.LinkedHashSet;
import java.util.Set;

@Data
@NoArgsConstructor
public class Inbound {
    private int inPortId;

    private String parentNodeId;

    private int cost;

    private LinkedHashSet<Integer> outIfSet = new LinkedHashSet<>();

    public Inbound(int inPortId, String parentNodeId, int cost, Set<Integer> outIfSet) {
        this.parentNodeId = parentNodeId;
        this.cost = cost;
        this.inPortId = inPortId;
        this.outIfSet.addAll(outIfSet);
    }
}
