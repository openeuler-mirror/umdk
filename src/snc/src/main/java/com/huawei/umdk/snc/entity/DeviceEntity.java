/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
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
@ToString
public abstract class DeviceEntity {
    private String deviceName;
    @Setter(AccessLevel.NONE)
    private DeviceType deviceType;
    private MgmtInfo mgmtInfo;
    private String rack;
    private Map<Integer, ForwardingChip> forwardingChips;

    protected DeviceEntity(String deviceName, DeviceType deviceType) {
        this.deviceName = deviceName;
        this.deviceType = deviceType;
    }

    protected DeviceEntity(String deviceName, DeviceType deviceType,
                           MgmtInfo mgmtInfo, String rack,
                           Map<Integer, ForwardingChip> forwardingChips) {
        this.deviceName = deviceName;
        this.deviceType = deviceType;
        this.mgmtInfo = mgmtInfo;
        this.rack = rack;
        this.forwardingChips = forwardingChips;
    }
}
