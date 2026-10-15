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
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PolicyPrefix {
    private long addr;

    private int maskLen;

    private long mask;

    @NonNull
    private Bitmap visiblePortBitmap = new Bitmap();

    public boolean visible(int portId) {
        return visiblePortBitmap.get(portId);
    }

    public Prefix asPrefix() {
        return new Prefix(addr, maskLen, mask);
    }
}
