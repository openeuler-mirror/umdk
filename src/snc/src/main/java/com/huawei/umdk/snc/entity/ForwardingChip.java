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

import java.util.Collections;
import java.util.Map;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class ForwardingChip {
    private Integer chipIndex;
    private Map<String, PortEntity> ports;

    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private RoutingTable routingTable;

    protected ForwardingChip(Integer chipIndex, Map<String, PortEntity> ports) {
        this.chipIndex = chipIndex;
        this.ports = ports;
    }

    public Map<String, PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
