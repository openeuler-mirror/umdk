/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import com.alibaba.fastjson2.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString(exclude = {"npuDevices", "swDevices"})
public class SuperNode {
    private String name;
    private String version;
    private Map<String, NpuDevice> npuDevices;
    private Map<String, SwDevice> swDevices;

    /**
     * 合并 NPU 与 SW 设备为统一视图（只读派生属性，不参与 JSON 序列化）。
     */
    @JSONField(serialize = false)
    public Map<String, DeviceEntity> getAllDevices() {
        Map<String, DeviceEntity> all = new HashMap<>();
        if (npuDevices != null) {
            all.putAll(npuDevices);
        }
        if (swDevices != null) {
            all.putAll(swDevices);
        }
        return all.isEmpty() ? Collections.emptyMap() : Collections.unmodifiableMap(all);
    }

    public ForwardingChip getChipByIndex(String deviceName, int chipIndex) {
        if (deviceName == null) {
            return null;
        }
        DeviceEntity device = getAllDevices().get(deviceName);
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        return device.getForwardingChips().get(chipIndex);
    }

    public ForwardingChip getChipByPortName(String deviceName, String portName) {
        if (deviceName == null || portName == null) {
            return null;
        }
        DeviceEntity device = getAllDevices().get(deviceName);
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip == null || chip.getPorts() == null) {
                continue;
            }
            if (chip.getPorts().containsKey(portName)) {
                return chip;
            }
        }
        return null;
    }
}
