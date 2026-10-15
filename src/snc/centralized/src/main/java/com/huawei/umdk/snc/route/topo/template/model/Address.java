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

@Data
@AllArgsConstructor
public class Address {
    private long addr;

    private int maskLen;

    private long mask;

    private AddrType addrType;

    public Prefix asPrefix() {
        return new Prefix(addr, maskLen, mask);
    }
}
