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
public class SwForwardingChip extends ForwardingChip {
    @Getter(AccessLevel.NONE)
    private Map<String, SwPortEntity> ports;

    public SwForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    public SwForwardingChip(Integer chipIndex, Map<String, SwPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    public Map<String, SwPortEntity> getSwPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
