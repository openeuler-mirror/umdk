/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import java.util.Map;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString(exclude = "mgmtInfo")
public abstract class DeviceEntity {
    private String deviceName;
    private MgmtInfo mgmtInfo;
    private String rack;

    protected DeviceEntity(String deviceName, MgmtInfo mgmtInfo, String rack) {
        this.deviceName = deviceName;
        this.mgmtInfo = mgmtInfo;
        this.rack = rack;
    }

    public abstract DeviceType getDeviceType();

    public abstract Map<Integer, ? extends ForwardingChip> getForwardingChips();
}
