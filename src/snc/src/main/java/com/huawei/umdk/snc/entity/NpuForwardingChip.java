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
public class NpuForwardingChip extends ForwardingChip {
    @Getter(AccessLevel.NONE)
    private Map<String, NpuPortEntity> ports;
    private Map<String, LogicPortEntity> logicPorts;

    public NpuForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    public NpuForwardingChip(Integer chipIndex, Map<String, NpuPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    public Map<String, NpuPortEntity> getNpuPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    public Map<String, LogicPortEntity> getLogicPorts() {
        return logicPorts == null ? null : Collections.unmodifiableMap(logicPorts);
    }
}
