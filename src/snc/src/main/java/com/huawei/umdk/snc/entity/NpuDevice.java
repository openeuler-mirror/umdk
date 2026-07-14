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
public class NpuDevice extends DeviceEntity {
    @Getter(AccessLevel.NONE)
    private Map<Integer, NpuForwardingChip> forwardingChips;
    private String osName;
    private String osIp;
    private Integer boardId;
    private Integer moduleId;
    private Integer boardIndex;

    public NpuDevice(String deviceName, MgmtInfo mgmtInfo, String rack,
                     Map<Integer, NpuForwardingChip> forwardingChips,
                     String osName, String osIp, Integer boardId,
                     Integer moduleId, Integer boardIndex) {
        super(deviceName, DeviceType.NPU, mgmtInfo, rack);
        this.forwardingChips = forwardingChips;
        this.osName = osName;
        this.osIp = osIp;
        this.boardId = boardId;
        this.moduleId = moduleId;
        this.boardIndex = boardIndex;
    }

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.NPU;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    public Map<Integer, NpuForwardingChip> getNpuForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }

    public NpuPortEntity findNpuPort(String portName) {
        if (forwardingChips != null) {
            for (NpuForwardingChip chip : forwardingChips.values()) {
                if (chip.getNpuPorts() != null) {
                    NpuPortEntity port = chip.getNpuPorts().get(portName);
                    if (port != null) {
                        return port;
                    }
                }
            }
        }
        return null;
    }
}
