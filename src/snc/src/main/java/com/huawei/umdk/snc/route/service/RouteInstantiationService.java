/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route instantiation service
 * Author: jiang wen jiang
 * Create: 2026-07-28
 * Note:
 */

package com.huawei.umdk.snc.route.service;

import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.NextHopPort;
import com.huawei.umdk.snc.route.model.RouteEntry;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;

import java.util.HashMap;
import java.util.Map;

public class RouteInstantiationService {
    private static final Logger log = new Logger(RouteInstantiationService.class);

    private static final long ALL_MASK = 0xffffffffL;

    private static final long FOUR_MASK = 0x7ffL;

    private static final long DEFAULT_VALUE = 0xdfL;

    private static final long ONE_SECTION_POSITION = 24;

    private static final long TWO_SECTION_POSITION = 16;

    private static final long THREE_SECTION_POSITION = 12;

    private static final long FOUR_SECTION_POSITION = 7;

    private static final long FIVE_SECTION_POSITION = 5;

    private static final long CHASSIS_COUNT = 4;

    private static final long SLOT_COUNT = 8;

    private static final long DEVICE_COUNT = 4;

    private static final int PREFIX_ADDRESS_LEN = 27;

    private static final int DOT_DECIMAL_ONE_PART = 8;

    private static final int DOT_DECIMAL_TWO_PART = 16;

    private static final int DOT_DECIMAL_THREE_PART = 24;

    private static final int DOT_DECIMAL_MASK = 0xFF;

    /**
     * instantiationRouteMap 中 key 的分隔符：形如 "deviceName#chipIndex"。
     */
    public static final String KEY_SEPARATOR = "#";

    /**
     * 构建 instantiationRouteMap 的 key："deviceName#chipIndex"。
     */
    public static String buildRouteTableKey(String deviceName, int chipIndex) {
        return deviceName + KEY_SEPARATOR + chipIndex;
    }

    private static Prefix fillHighBitAddress(Prefix prefix, Integer chassisIndex) {
        Prefix newPrefix = new Prefix(prefix.getAddr(), prefix.getMaskLen(), prefix.getMask());
        if (prefix.getMask() == ALL_MASK) {
            //不需补充高位地址，直接返回
            return newPrefix;
        } else if (prefix.getMask() == FOUR_MASK) {
            long temp = (DEFAULT_VALUE << ONE_SECTION_POSITION) | (DEFAULT_VALUE << TWO_SECTION_POSITION) |
                (chassisIndex << THREE_SECTION_POSITION) | prefix.getAddr();
            newPrefix.setAddr(temp);
        }
        return newPrefix;
    }

    private static void instantiateRouteForChassis(int chassisIndex, RouteTable routeTable, RouteTable newRouteTable) {
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            Prefix prefix = entry.getKey();
            RouteEntry routeEntry = entry.getValue();
            if (prefix.getAddr() == 0) {
                for (int chassis = 0; chassis < CHASSIS_COUNT; chassis++) {
                    if (chassis == chassisIndex) {
                        continue;
                    }
                    for (int slot = 0; slot < SLOT_COUNT; slot++) {
                        for (int ubpu = 0; ubpu < DEVICE_COUNT; ubpu++) {
                            long addr = (DEFAULT_VALUE << ONE_SECTION_POSITION) |
                                (DEFAULT_VALUE << TWO_SECTION_POSITION) | ((long) chassis << THREE_SECTION_POSITION) |
                                ((long) slot << FOUR_SECTION_POSITION) | ((long) ubpu << FIVE_SECTION_POSITION);
                            Prefix newPrefix = new Prefix(addr, PREFIX_ADDRESS_LEN, prefix.getMask());
                            RouteEntry newRouteEntry = new RouteEntry(newPrefix);
                            newRouteEntry.copyNhpSet(routeEntry);
                            newRouteTable.getRouteEntries().put(newPrefix, newRouteEntry);
                        }
                    }
                }
            } else {
                Prefix newPrefix = fillHighBitAddress(prefix, chassisIndex);
                RouteEntry newRouteEntry = new RouteEntry(newPrefix);
                newRouteEntry.copyNhpSet(routeEntry);
                newRouteTable.getRouteEntries().put(newPrefix, newRouteEntry);
            }
        }
    }

    private static void instantiateRouteForL2Sw(SncTopology interRackTopology, SncNode node,
                                                RouteTable routeTable, RouteTable newRouteTable) {
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            Prefix prefix = entry.getKey();
            RouteEntry routeEntry = entry.getValue();
            for (int chassisIndex = 0; chassisIndex < CHASSIS_COUNT; chassisIndex++) {
                Prefix newPrefix = fillHighBitAddress(prefix, chassisIndex);
                RouteEntry newRouteEntry = new RouteEntry(newPrefix);
                newRouteEntry.copyNhpSet(routeEntry);
                newRouteTable.getRouteEntries().put(newPrefix, newRouteEntry);
                if (chassisIndex == 0) {
                    continue;
                }
                // 1 2 3框更新每个nhp的出接口索引和名称
                // 从框间拓扑里去除l2 sw，用于查找端口描述信息
                for (NextHopPort nextHopPort : newRouteEntry.getNhpSet()) {
                    SncPort port = node.getPortMap().get(nextHopPort.getOutPortId());
                    String peerL1SwLabel = port.getPeerNodeId();
                    int peerL1SwIndex = Label.getL1SwIndex(peerL1SwLabel);
                    int peerL1PortId = port.getPeerPortId();

                    int newPeerL1Index = peerL1SwIndex + chassisIndex * 4;
                    String newPeerL1Label = Label.getL1SwLabel(newPeerL1Index);
                    SncNode interL2SwNode = interRackTopology.getNodeMap().get(node.getLabel().toString());
                    for (SncPort tempPort : interL2SwNode.getPortMap().values()) {
                        if (tempPort.getPeerNodeId().equals(newPeerL1Label) &&
                            tempPort.getPeerPortId() == peerL1PortId) {
                            nextHopPort.setOutPortId(tempPort.getId());
                            nextHopPort.setOutPortName(tempPort.getPortName());
                        }
                    }
                }
            }
        }
    }

    private static Map<String, RouteTable> instantiateNodeRoute(SncTopology interRackTopology, SncNode node,
                                                          RouteTable routeTable) {
        Map<String, RouteTable> routeTableMap = new HashMap<>();
        String nodeType = node.type();
        if ("npu".equals(nodeType) || "l1_sw".equals(nodeType)) {
            // 每框实例化一份
            for (int chassisIndex = 0; chassisIndex < CHASSIS_COUNT; chassisIndex++) {
                RouteTable newRouteTable = new RouteTable();
                instantiateRouteForChassis(chassisIndex, routeTable, newRouteTable);
                String nodeLabel = node.getLabel().addChassis(chassisIndex + 1);
                routeTableMap.put(nodeLabel, newRouteTable);
            }
        } else if ("l2_sw".equals(nodeType)) {
            RouteTable newRouteTable = new RouteTable();
            instantiateRouteForL2Sw(interRackTopology, node, routeTable, newRouteTable);
            routeTableMap.put(node.getLabel().toString(), newRouteTable);
        } else {
            throw new IllegalArgumentException("Unknown node type: " + nodeType);
        }

        return routeTableMap;
    }

    public static void instantiateXpodRoute(Map<String, SncTopology> topologyMap,
        Map<String, Map<String, RouteTable>> routeTemplateMap, Map<String, RouteTable> routes) {
        // 框内模板的路由进行实例化
        String xpodType = "128_npu_rack";
        Map<String, RouteTable> routeMap = routeTemplateMap.get(xpodType);
        SncTopology topology = topologyMap.get(xpodType);
        SncTopology interRackTopology = topologyMap.get("128_npu_inter_rack");
        for (Map.Entry<String, RouteTable> entry : routeMap.entrySet()) {
            SncNode node = topology.getNodeMap().get(entry.getKey());
            if (node == null) {
                throw new IllegalArgumentException(String.format("node %s not found", entry.getKey()));
            }
            Map<String, RouteTable> routeTableMap = instantiateNodeRoute(
                interRackTopology, node, entry.getValue());
            routes.putAll(routeTableMap);
        }

        // l2 sw的路由合并下
        xpodType = "128_npu_inter_rack";
        Map<String, RouteTable> interRouteMap = routeTemplateMap.get(xpodType);
        for (Map.Entry<String, RouteTable> entry : interRouteMap.entrySet()) {
            String nodeKey = entry.getKey();
            if (routes.containsKey(nodeKey)) {
                RouteTable oldRouteTable = routes.get(nodeKey);
                RouteTable newRouteTable = entry.getValue();
                oldRouteTable.addRouteTable(newRouteTable);
            }
        }
        log.info("instantiate xpod route success");
    }

    public void makeNpuRoutes(NpuDevice npuDevice, Map<String, RouteTable> routes,
                               Map<String, Map<String, RoutingEntry>> instantiationRouteMap) {
        int chassis = extractRackNumber(npuDevice.getRack());
        Map<Integer, NpuForwardingChip> chips = npuDevice.getNpuForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("npu device %s has no forwarding chips",
                npuDevice.getDeviceName()));
        }

        for (NpuForwardingChip chip : chips.values()) {
            String label = String.format("type:npu|chassis:%d|slot:%d|ubpu:%d|die:%d",
                chassis, npuDevice.getBoardId(), npuDevice.getBoardIndex(), chip.getChipIndex());
            RouteTable routeTable = routes.get(label);
            if (routeTable == null) {
                log.error("route not found for label %s", label);
                continue;
            }
            String key = buildRouteTableKey(npuDevice.getDeviceName(), chip.getChipIndex());
            instantiationRouteMap.put(key, convertToRoutingEntries(routeTable));
        }
    }

    public void makeSwRoutes(SwDevice swDevice, Map<String, RouteTable> routes,
                              Map<String, Map<String, RoutingEntry>> instantiationRouteMap) {
        if (swDevice.getSwitchLevel() == SwitchLevel.L1) {
            makeL1SwRoutes(swDevice, routes, instantiationRouteMap);
        } else if (swDevice.getSwitchLevel() == SwitchLevel.L2) {
            makeL2SwRoutes(swDevice, routes, instantiationRouteMap);
        }
    }

    private void makeL1SwRoutes(SwDevice swDevice, Map<String, RouteTable> routes,
                                Map<String, Map<String, RoutingEntry>> instantiationRouteMap) {
        Map<Integer, SwForwardingChip> chips = swDevice.getSwForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("sw device %s has no forwarding chips",
                swDevice.getDeviceName()));
        }

        int chassis = extractRackNumber(swDevice.getRack());
        String label = String.format("type:l1_sw|chassis:%d|index:%d", chassis, swDevice.getIndex());
        RouteTable routeTable = routes.get(label);
        if (routeTable == null) {
            log.error("route not found for label %s", label);
            return;
        }

        String key = buildRouteTableKey(swDevice.getDeviceName(),
            chips.values().iterator().next().getChipIndex());
        instantiationRouteMap.put(key, convertToRoutingEntries(routeTable));
    }

    private void makeL2SwRoutes(SwDevice swDevice, Map<String, RouteTable> routes,
                                Map<String, Map<String, RoutingEntry>> instantiationRouteMap) {
        Map<Integer, SwForwardingChip> chips = swDevice.getSwForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("l2 sw device %s has no forwarding chips",
                swDevice.getDeviceName()));
        }

        for (SwForwardingChip chip : chips.values()) {
            String label = String.format("type:l2_sw|index:%d|chip:%d",
                swDevice.getIndex(), chip.getChipIndex());
            RouteTable routeTable = routes.get(label);
            if (routeTable == null) {
                log.error("route not found for label %s", label);
                continue;
            }
            String key = buildRouteTableKey(swDevice.getDeviceName(), chip.getChipIndex());
            instantiationRouteMap.put(key, convertToRoutingEntries(routeTable));
        }
    }

    private Map<String, RoutingEntry> convertToRoutingEntries(RouteTable routeTable) {
        Map<String, RoutingEntry> result = new HashMap<>();
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            Prefix prefix = entry.getKey();
            RouteEntry routeEntry = entry.getValue();

            String dstAddress = longToIp(prefix.getAddr());
            RoutePrefix routePrefix = new RoutePrefix(dstAddress, prefix.getMaskLen());

            Map<String, OutPortInfo> outPortInfoMap = new HashMap<>();
            for (NextHopPort nhp : routeEntry.getNhpSet()) {
                OutPortInfo outPortInfo = new OutPortInfo();
                outPortInfo.setPortName(nhp.getOutPortName());
                // 默认 convergedFlag=0 表示未收敛，可达
                outPortInfoMap.put(nhp.getOutPortName(), outPortInfo);
            }

            RoutingEntry routingEntry = new RoutingEntry(routePrefix, outPortInfoMap, true);
            routingEntry.refreshReachable();
            result.put(dstAddress, routingEntry);
        }
        return result;
    }

    private static int extractRackNumber(String rack) {
        if (rack == null) {
            throw new IllegalArgumentException("rack is null");
        }
        String numPart = rack.replaceAll("\\D", "");
        if (numPart.isEmpty()) {
            throw new IllegalArgumentException("invalid rack format: " + rack);
        }
        return Integer.parseInt(numPart);
    }

    private static String longToIp(long addr) {
        return ((addr >> DOT_DECIMAL_THREE_PART) & DOT_DECIMAL_MASK) + "." +
            ((addr >> DOT_DECIMAL_TWO_PART) & DOT_DECIMAL_MASK) + "." +
            ((addr >> DOT_DECIMAL_ONE_PART) & DOT_DECIMAL_MASK) + "." +
            (addr & DOT_DECIMAL_MASK);
    }

    public static Map<String, Map<String, RoutingEntry>> deepCopyRoutingEntry(
        Map<String, Map<String, RoutingEntry>> source) {
        Map<String, Map<String, RoutingEntry>> dest = new HashMap<>();
        for (Map.Entry<String, Map<String, RoutingEntry>> deviceEntry : source.entrySet()) {
            String deviceKey = deviceEntry.getKey();
            Map<String, RoutingEntry> srcRouteMap = deviceEntry.getValue();
            if (srcRouteMap == null) {
                dest.put(deviceKey, null);
                continue;
            }

            Map<String, RoutingEntry> dstRouteMap = new HashMap<>();
            for (Map.Entry<String, RoutingEntry> routeEntry : srcRouteMap.entrySet()) {
                RoutingEntry dstEntry = RoutingEntry.copy(routeEntry.getValue());
                dstRouteMap.put(routeEntry.getKey(), dstEntry);
            }
            dest.put(deviceKey, dstRouteMap);
        }
        return dest;
    }
}
