/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Data
@AllArgsConstructor
@EqualsAndHashCode(of = {"addr", "maskLen", "mask"})
public class Prefix {
    private long addr;

    private int maskLen;

    private long mask;

    @Override
    public String toString() {
        return String.format("addr:%s|maskLen:%s|mask:%s", addr, maskLen, mask);
    }
}
