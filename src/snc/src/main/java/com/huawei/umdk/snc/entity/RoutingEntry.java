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

import com.huawei.umdk.snc.route.model.RouteEntry;
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
public class RoutingEntry {
    private RoutePrefix prefix;
    private Map<String, OutPortInfo> outPortInfos;

    public Map<String, OutPortInfo> getOutPortInfos() {
        return outPortInfos == null ? null : Collections.unmodifiableMap(outPortInfos);
    }

    public static RoutingEntry copy(RoutingEntry srcRoutingEntry) {
        if (srcRoutingEntry == null) {
            return null;
        }

        RoutePrefix srcPrefix = srcRoutingEntry.getPrefix();
        RoutePrefix dstPrefix = (srcPrefix == null) ? null
            : new RoutePrefix(srcPrefix.getDstAddress(), srcPrefix.getMaskLength());

        Map<String, OutPortInfo> dstOutPortMap = new HashMap<>();
        Map<String, OutPortInfo> srcOutPortMap = srcRoutingEntry.getOutPortInfos();
        if (srcOutPortMap != null) {
            for (Map.Entry<String, OutPortInfo> portEntry : srcOutPortMap.entrySet()) {
                OutPortInfo srcPort = portEntry.getValue();
                OutPortInfo dstPort = (srcPort == null) ? null : new OutPortInfo(
                    srcPort.getPortName(), srcPort.getNextHop(), srcPort.getPreference(),
                    srcPort.getTag(), srcPort.getProtocol(), srcPort.isActive());
                dstOutPortMap.put(portEntry.getKey(), dstPort);
            }
        }

        RoutingEntry destEntry = new RoutingEntry();
        destEntry.setPrefix(dstPrefix);
        destEntry.setOutPortInfos(dstOutPortMap);
        return destEntry;
    }
}
