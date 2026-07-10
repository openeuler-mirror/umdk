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
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuDevice extends DeviceEntity {
    private String osName;
    private String osIp;
    private Integer boardId;
    private Integer moduleId;
    private Integer boardIndex;

    public NpuDevice(String deviceName, MgmtInfo mgmtInfo, String rack,
                     Map<Integer, ForwardingChip> forwardingChips,
                     String osName, String osIp, Integer boardId,
                     Integer moduleId, Integer boardIndex) {
        super(deviceName, DeviceType.NPU, mgmtInfo, rack, forwardingChips);
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

    public NpuPortEntity findNpuPort(String portName) {
        if (getForwardingChips() != null) {
            for (ForwardingChip chip : getForwardingChips().values()) {
                if (chip.getPorts() != null) {
                    java.util.Map.Entry<String, PortEntity> found =
                        chip.getPorts().entrySet().stream()
                            .filter(e -> e.getKey().equals(portName))
                            .findFirst().orElse(null);
                    if (found != null && found.getValue() instanceof NpuPortEntity) {
                        return (NpuPortEntity) found.getValue();
                    }
                }
            }
        }
        return null;
    }
}
