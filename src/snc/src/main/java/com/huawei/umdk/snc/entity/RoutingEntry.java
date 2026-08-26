/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-08-18 add reachable flag
 */
package com.huawei.umdk.snc.entity;

import java.util.LinkedHashMap;
import java.util.Map;

import com.huawei.umdk.snc.route.model.RouteEntry;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingEntry {
    private RoutePrefix prefix;
    private Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();

    /**
     * 路由可达性：表示 outPortInfos 中是否存在 convergedFlag==0 的有效出端口。
     */
    private boolean reachable = true;

    /**
     * 全参构造函数：对入参 outPortInfos 做防御性拷贝，保证内部始终为 LinkedHashMap 维持插入顺序。
     * 使用方传入的 Map 类型不影响内部有序性。
     */
    public RoutingEntry(RoutePrefix prefix, Map<String, OutPortInfo> outPortInfos, boolean reachable) {
        this.prefix = prefix;
        this.reachable = reachable;
        this.outPortInfos = new LinkedHashMap<>();
        if (outPortInfos != null) {
            this.outPortInfos.putAll(outPortInfos);
        }
    }

    /**
     * 覆盖 Lombok 生成的 setter：保证内部 outPortInfos 始终是 LinkedHashMap，维持插入顺序。
     * 使用方传入的 Map 类型不影响内部有序性。
     */
    public void setOutPortInfos(Map<String, OutPortInfo> outPortInfos) {
        this.outPortInfos = new LinkedHashMap<>();
        if (outPortInfos != null) {
            this.outPortInfos.putAll(outPortInfos);
        }
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

        Map<String, OutPortInfo> dstOutPortMap = new LinkedHashMap<>();
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
