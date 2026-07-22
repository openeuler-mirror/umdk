/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.NoArgsConstructor;

import java.util.BitSet;

@NoArgsConstructor
public class Bitmap extends BitSet {
    public Bitmap(Integer w) {
        super(w);
    }

    public Bitmap(Integer w, boolean en) {
        super(w);
        if (en) {
            set(0, w);
        }
    }
}
