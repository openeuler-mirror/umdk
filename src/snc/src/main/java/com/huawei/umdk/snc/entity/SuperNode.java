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
import java.util.HashMap;
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
@EqualsAndHashCode
@ToString
public class SuperNode {
    private String name;
    private String version;
    private Map<String, NpuDevice> npuDevices;
    private Map<String, SwDevice> swDevices;

    public Map<String, NpuDevice> getNpuDevices() {
        return npuDevices == null ? null : Collections.unmodifiableMap(npuDevices);
    }

    public Map<String, SwDevice> getSwDevices() {
        return swDevices == null ? null : Collections.unmodifiableMap(swDevices);
    }

    public Map<String, NpuDevice> getMutableNpuDevices() {
        return npuDevices;
    }

    public Map<String, SwDevice> getMutableSwDevices() {
        return swDevices;
    }

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

    public Map<String, DeviceEntity> getMutableAllDevices() {
        Map<String, DeviceEntity> all = new HashMap<>();
        if (npuDevices != null) {
            all.putAll(npuDevices);
        }
        if (swDevices != null) {
            all.putAll(swDevices);
        }
        return all.isEmpty() ? new HashMap<>() : all;
    }
}
