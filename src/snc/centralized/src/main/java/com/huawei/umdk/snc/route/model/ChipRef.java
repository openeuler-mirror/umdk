/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: chip description
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.model;

import lombok.Data;

@Data
public class ChipRef {
    private String device;
    private int chipIndex;

    public ChipRef(String device, int chipIndex) {
        this.device = device;
        this.chipIndex = chipIndex;
    }

    public String routeKey() {
        return device + "#" + chipIndex;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ChipRef)) {
            return false;
        }
        ChipRef other = (ChipRef) obj;
        return chipIndex == other.chipIndex && device.equals(other.device);
    }

    @Override
    public int hashCode() {
        return device.hashCode() * 31 + chipIndex;
    }

    @Override
    public String toString() {
        return routeKey();
    }
}
