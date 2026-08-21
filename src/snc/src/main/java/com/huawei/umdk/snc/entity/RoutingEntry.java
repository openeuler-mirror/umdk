/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-08-18 add reachable flag
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

    /**
     * 路由可达性：表示 outPortInfos 中是否存在 convergedFlag==0 的有效出端口。
     */
    private boolean reachable = true;

    public Map<String, OutPortInfo> getOutPortInfos() {
        return outPortInfos == null ? null : Collections.unmodifiableMap(outPortInfos);
    }

    /**
     * 获取可变的出端口 Map，供收敛逻辑直接修改 OutPortInfo 的 convergedFlag。
     */
    public Map<String, OutPortInfo> getMutableOutPortInfos() {
        return outPortInfos;
    }

    /**
     * 依据 outPortInfos 中各出端口的 convergedFlag 重新计算 reachable。
     * 只要存在一个 convergedFlag==0 的出端口，则 reachable=true；否则 false。
     */
    public void refreshReachable() {
        boolean newReachable = false;
        if (outPortInfos != null) {
            for (OutPortInfo port : outPortInfos.values()) {
                if (port != null && port.getConvergedFlag() == 0) {
                    newReachable = true;
                    break;
                }
            }
        }
        this.reachable = newReachable;
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
                    srcPort.getTag(), srcPort.getProtocol(), srcPort.getConvergedFlag());
                dstOutPortMap.put(portEntry.getKey(), dstPort);
            }
        }

        RoutingEntry destEntry = new RoutingEntry();
        destEntry.setPrefix(dstPrefix);
        destEntry.setOutPortInfos(dstOutPortMap);
        destEntry.setReachable(srcRoutingEntry.isReachable());
        return destEntry;
    }
}
