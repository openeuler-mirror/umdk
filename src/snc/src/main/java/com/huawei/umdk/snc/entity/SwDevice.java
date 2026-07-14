/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import java.util.Collections;
import java.util.Map;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwDevice extends DeviceEntity {
    @Getter(AccessLevel.NONE)
    private Map<Integer, SwForwardingChip> forwardingChips;
    private SwitchLevel switchLevel;
    private Integer index;

    public SwDevice(String deviceName, MgmtInfo mgmtInfo, String rack,
                    Map<Integer, SwForwardingChip> forwardingChips,
                    SwitchLevel switchLevel, Integer index) {
        super(deviceName, DeviceType.SW, mgmtInfo, rack);
        this.forwardingChips = forwardingChips;
        this.switchLevel = switchLevel;
        this.index = index;
    }

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.SW;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    public Map<Integer, SwForwardingChip> getSwForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }
}
