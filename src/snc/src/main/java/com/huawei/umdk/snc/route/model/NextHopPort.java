/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route description
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.route.topo.template.model.PolicyPath;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(of = {"outPortId"})
public class NextHopPort implements Cloneable {
    private static final long INVALID_NEXT_HOP_VALUE = -1;

    private int cost;

    private int outPortId;

    private String outPortName;

    private PolicyPath.PolicyEnType pathType;

    public NextHopPort(int cost, int outPortId, PolicyPath.PolicyEnType pathType) {
        this.cost = cost;
        this.outPortId = outPortId;
        this.pathType = pathType;
    }

    @Override
    public NextHopPort clone() {
        try {
            return (NextHopPort) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError("clone failed", e);
        }
    }
}
