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
import com.huawei.umdk.snc.route.topo.template.model.NodeType;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.model.SuperNodeType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    private static final int PREFIX_ADDRESS_LEN = 28;

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

    private static void instantiateRouteForNpu(int chassisIndex, RouteTable routeTable, RouteTable newRouteTable) {
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            Prefix prefix = entry.getKey();
            RouteEntry routeEntry = entry.getValue();
            if (prefix.getAddr() == 0) {
                for (int chassis = 0; chassis < CHASSIS_COUNT; chassis++) {
                    if (chassis == chassisIndex) {
                        continue;
                    }
                    // 补充其他框 npu 的聚合地址
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

    private static void instantiateRouteForL1Sw(int chassisIndex, RouteTable routeTable, List<Prefix> l2RoutePrefix,
                                                RouteTable newRouteTable) {
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            Prefix prefix = entry.getKey();
            RouteEntry routeEntry = entry.getValue();
            if (prefix.getAddr() == 0) {
                for (int chassis = 0; chassis < CHASSIS_COUNT; chassis++) {
                    if (chassis == chassisIndex) {
                        continue;
                    }
                    // 对于l1 sw，还需要补充其他框 l1 sw 和 npu 的明细地址
                    // l2RoutePrefix 为l1 sw对端的l2 sw的路由前缀列表
                    for (Prefix tempPrefix : l2RoutePrefix) {
                        Prefix newPrefix = fillHighBitAddress(tempPrefix, chassis);
                        RouteEntry newRouteEntry = new RouteEntry(newPrefix);
                        newRouteEntry.copyNhpSet(routeEntry);
                        newRouteTable.getRouteEntries().put(newPrefix, newRouteEntry);
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

    private static List<Prefix> getL2SwPrefixes(String l1SwLabel, SncTopology rackTopology,
                                         Map<String, RouteTable> routeTemplateMap) {
        SncNode l1SwNode = rackTopology.getNodeMap().get(l1SwLabel);
        if (l1SwNode == null) {
            throw new IllegalArgumentException(String.format("l1 sw node %s not found in rack topology", l1SwLabel));
        }

        // 先收集对端l2 sw的label，Set直接去重
        Set<String> l2SwLabels = new LinkedHashSet<>();
        for (SncPort port : l1SwNode.getPortMap().values()) {
            SncNode peerNode = rackTopology.getNodeMap().get(port.getPeerNodeId());
            if (peerNode == null || !NodeType.L2_SW.getValue().equals(peerNode.type())) {
                continue;
            }
            l2SwLabels.add(peerNode.getLabel().toString());
        }

        // 再处理每个l2 sw，记录路由prefix；不同l2 sw的路由prefix可能相同，需去重
        Set<Prefix> prefixes = new LinkedHashSet<>();
        for (String l2SwLabel : l2SwLabels) {
            RouteTable l2SwRouteTable = routeTemplateMap.get(l2SwLabel);
            if (l2SwRouteTable == null) {
                log.error("route table not found for l2 sw %s", l2SwLabel);
                continue;
            }
            prefixes.addAll(l2SwRouteTable.getRouteEntries().keySet());
        }
        return new ArrayList<>(prefixes);
    }

    private static Map<String, RouteTable> instantiateNodeRoute(Map<String, SncTopology> topologyMap, SncNode node,
                                                                Map<String, RouteTable> routeTemplateMap) {
        Map<String, RouteTable> routeTableMap = new HashMap<>();
        RouteTable routeTable = routeTemplateMap.get(node.getLabel().toString());
        if (routeTable == null) {
            throw new IllegalArgumentException(String.format("route table %s not found in rack topology",
                node.getLabel().toString()));
        }
        SncTopology rackTopology = topologyMap.get(SuperNodeType.ATLAS950_GALAXY_RACK32.getValue());
        SncTopology interRackTopology = topologyMap.get(SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());
        String nodeType = node.type();
        if (NodeType.NPU.getValue().equals(nodeType)) {
            // 每框实例化一份
            for (int chassisIndex = 0; chassisIndex < CHASSIS_COUNT; chassisIndex++) {
                RouteTable newRouteTable = new RouteTable();
                instantiateRouteForNpu(chassisIndex, routeTable, newRouteTable);
                String nodeLabel = node.getLabel().addChassis(chassisIndex + 1);
                routeTableMap.put(nodeLabel, newRouteTable);
            }
        } else if (NodeType.L1_SW.getValue().equals(nodeType)) {
            // 根据框内模板，找到l1 sw连接的l2 sw，收集其路由前缀，用于发布地址的转换
            List<Prefix> l2RoutePrefix = getL2SwPrefixes(node.getLabel().toString(), rackTopology, routeTemplateMap);
            // 每框实例化一份
            for (int chassisIndex = 0; chassisIndex < CHASSIS_COUNT; chassisIndex++) {
                RouteTable newRouteTable = new RouteTable();
                instantiateRouteForL1Sw(chassisIndex, routeTable, l2RoutePrefix, newRouteTable);
                String nodeLabel = node.getLabel().addChassis(chassisIndex + 1);
                routeTableMap.put(nodeLabel, newRouteTable);
            }
        } else if (NodeType.L2_SW.getValue().equals(nodeType)) {
            RouteTable newRouteTable = new RouteTable();
            instantiateRouteForL2Sw(interRackTopology, node, routeTable, newRouteTable);
            routeTableMap.put(node.getLabel().toString(), newRouteTable);
        } else {
            throw new IllegalArgumentException("Unknown node type: " + nodeType);
        }

        return routeTableMap;
    }

    // 对框内模板的路由进行实例化
    public static void instantiateXpodRoute(Map<String, SncTopology> topologyMap,
        Map<String, Map<String, RouteTable>> routeTemplateMap, Map<String, Map<String, RouteTable>> superNodeRoutes) {
        String xpodType = SuperNodeType.ATLAS950_GALAXY_RACK32.getValue();
        Map<String, RouteTable> routeMap = routeTemplateMap.get(xpodType);
        SncTopology topology = topologyMap.get(xpodType);
        Map<String, RouteTable> routes = new HashMap<>();

        // l1 sw 实例化会用到框内模板计算的l2 sw的路由，所以l1 sw实例化在l2 sw之前
        // l1 sw 的发布路由，转化成其他框的l1 sw 和 npu的路由，基于l2 sw的路由进行转换，每一框复制一份，补齐高位
        for (Map.Entry<String, SncNode> entry : topology.getNodeMap().entrySet()) {
            SncNode node = entry.getValue();
            if (NodeType.L1_SW.getValue().equals(node.type())) {
                Map<String, RouteTable> routeTableMap = instantiateNodeRoute(topologyMap, node, routeMap);
                routes.putAll(routeTableMap);
            }
        }

        // npu和l2 sw进行路由实例化
        for (Map.Entry<String, SncNode> entry : topology.getNodeMap().entrySet()) {
            SncNode node = entry.getValue();
            if (NodeType.L1_SW.getValue().equals(node.type())) {
                continue;
            }

            Map<String, RouteTable> routeTableMap = instantiateNodeRoute(topologyMap, node, routeMap);
            routes.putAll(routeTableMap);
        }

        superNodeRoutes.put(xpodType, routes);
        log.info("instantiate xpod route success");
    }

    public void makeNpuRoutes(NpuDevice npuDevice, Map<String, RouteTable> routes,
                               Map<String, Map<String, RoutingEntry>> instantiationRouteMap) {
        int chassis = extractRackNumber(npuDevice.getRack());
        Map<Integer, NpuForwardingChip> chips = npuDevice.getForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("npu device %s has no forwarding chips",
                npuDevice.getDeviceName()));
        }

        for (NpuForwardingChip chip : chips.values()) {
            String label = String.format("type:%s|chassis:%d|slot:%d|ubpu:%d|die:%d", NodeType.NPU.getValue(),
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
        Map<Integer, SwForwardingChip> chips = swDevice.getForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("sw device %s has no forwarding chips",
                swDevice.getDeviceName()));
        }

        int chassis = extractRackNumber(swDevice.getRack());
        String label = String.format("type:%s|chassis:%d|index:%d", NodeType.L1_SW.getValue(), chassis,
            swDevice.getIndex());
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
        Map<Integer, SwForwardingChip> chips = swDevice.getForwardingChips();
        if (chips == null || chips.isEmpty()) {
            throw new IllegalArgumentException(String.format("l2 sw device %s has no forwarding chips",
                swDevice.getDeviceName()));
        }

        for (SwForwardingChip chip : chips.values()) {
            String label = String.format("type:%s|index:%d|chip:%d", NodeType.L2_SW.getValue(),
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

            Map<String, OutPortInfo> outPortInfoMap = new LinkedHashMap<>();
            for (NextHopPort nhp : routeEntry.getNhpSet()) {
                OutPortInfo outPortInfo = new OutPortInfo();
                outPortInfo.setPortName(nhp.getOutPortName());
                // 默认 convergedFlag=0 表示未收敛，可达
                outPortInfoMap.put(nhp.getOutPortName(), outPortInfo);
            }

            RoutingEntry routingEntry = new RoutingEntry(routePrefix, outPortInfoMap, true);
            routingEntry.refreshReachable();
            String key = String.format("%s/%d", dstAddress, prefix.getMaskLen());
            result.put(key, routingEntry);
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
