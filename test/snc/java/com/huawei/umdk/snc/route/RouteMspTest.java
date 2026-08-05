/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route;

import com.huawei.umdk.snc.C3SncService;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.NextHopPort;
import com.huawei.umdk.snc.route.model.RouteEntry;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.Address;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class RouteMspTest {
    private static final Logger log = new Logger(RouteMspTest.class);

    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

    private boolean compareAddressAndPrefix(Address address, Prefix prefix) {
        return address.getAddr() == prefix.getAddr() &&
            address.getMask() == prefix.getMask() &&
            address.getMaskLen() == prefix.getMaskLen();
    }

    private String addrToLabelDescription(SncTopology topology, Prefix prefix) {
        StringBuilder result = new StringBuilder();
        String separator = " || ";
        for (SncNode node : topology.getNodeMap().values()) {
            for (Address address : node.getAddrList()) {
                if (compareAddressAndPrefix(address, prefix)) {
                    result.append(node.getLabel()).append(' ')
                        .append(address.getAddrType()).append(separator);
                }
            }

            for (SncPort port : node.getPortMap().values()) {
                for (Address address : port.getAddrList()) {
                    if (compareAddressAndPrefix(address, prefix)) {
                        result.append(port.getLabel()).append(' ')
                            .append(address.getAddrType()).append(separator);
                    }
                }
            }
        }

        if (result.isEmpty()) {
            result.append("unknown addr maybe inter-chassis address");
        } else {
            int length = result.length();
            result.delete(length - separator.length(), length);
        }

        return result.toString();
    }

    private void assertRouteCost(RouteTable routeTable, long addr, int expectedCost) {
        String addrHex = "0x" + Long.toHexString(addr);
        RouteEntry routeEntry = routeTable.getRouteEntries().keySet().stream()
            .filter(prefix -> prefix.getAddr() == addr)
            .map(routeTable.getRouteEntries()::get)
            .findFirst()
            .orElseThrow(() -> new AssertionError("route entry not found for addr " + addrHex));
        int minCost = routeEntry.getNhpSet().stream().mapToInt(NextHopPort::getCost).min()
            .orElseThrow(() -> new AssertionError("nhp set is empty for addr " + addrHex));
        Assertions.assertEquals(expectedCost, minCost, "route cost for addr " + addrHex + " mismatch");
    }

    private void printFormatNodeRouteInfo(SncTopology topology, RouteTable routeTable) {
        Map<Prefix, RouteEntry> routeEntries = routeTable.getRouteEntries();
        for (Map.Entry<Prefix, RouteEntry> entry : routeEntries.entrySet()) {
            List<String> outIfList = new ArrayList<>();
            for (NextHopPort nhp : entry.getValue().getNhpSet()) {
                outIfList.add(nhp.getOutPortId() + ":" + nhp.getCost());
            }
            Collections.sort(outIfList);
            String destAddrDetail = "addr description " + addrToLabelDescription(topology, entry.getKey());
            String addr = "addr " + String.format("0x%x", entry.getKey().getAddr()) + " : maskLen " + entry.getKey().getMaskLen()
                + " : mask " + Long.toHexString(entry.getKey().getMask());
            String outPortId = "outPortId" + outIfList;
            log.info("%-40s %-40s %-80s", addr, outPortId, destAddrDetail);
        }
    }

    @BeforeAll
    public static void init() {
        C3SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        List<String> templateFiles = new ArrayList<>();
        templateFiles.add("128_npu_rack.json");
        templateFiles.add("128_npu_inter_rack.json");

        for (String template : templateFiles) {
            SncTopology topology = TopoTemplateService.parseTemplateFile(template);
            topologyMap.put(topology.getLabel().getNames().get("type"), topology);
        }
    }

    @Test
    void calculateNpuRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:npu|slot:1|ubpu:1|die:2");
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
        // 目的为31个npu：每个npu 8个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        // 目的为4个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(31 * (8 + 1) + 4 + 4 * 2 + 1, routeTable.getRouteEntries().size());
        // cost校验：npu直连l1_sw cost=1；npu经l1_sw到l2_sw cost=2
        long l2SwNodeCna = topologyMap.get(templateType).getNodeMap().get("type:l2_sw|index:1|chip:1").
            getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, l2SwNodeCna, 2);
        long l1SwNodeCna = topologyMap.get(templateType).getNodeMap().get("type:l1_sw|index:1").
            getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, l1SwNodeCna, 1);
        long npuPortCna = topologyMap.get(templateType).getNodeMap().get("type:npu|slot:3|ubpu:2|die:2").
            getPortMap().get(0).getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, npuPortCna, 2);
    }

    @Test
    void calculateL1SwRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l1_sw|index:1");
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
        // 目的为32个npu：每个npu 2个 port cna和1个 pg cna
        // 目的为1个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(32 * (2 + 1) + 2 + 1, routeTable.getRouteEntries().size());
        // cost校验：l1_sw直连l2_sw cost=1
        long l2SwNodeCna = topologyMap.get(templateType).getNodeMap().get("type:l2_sw|index:1|chip:1").
            getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, l2SwNodeCna, 1);
        // 到npu的路由是2跳
        long npuPortCna = topologyMap.get(templateType).getNodeMap().get("type:npu|slot:2|ubpu:1|die:2").
            getPortMap().get(0).getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, npuPortCna, 1);
    }

    @Test
    void calculateL2SwRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l2_sw|index:1|chip:1");
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
        // 目的为32个npu：每个npu 2个 port cna和1个 pg cna
        Assertions.assertEquals(32 * (2 + 1), routeTable.getRouteEntries().size());
        // 到npu的路由是2跳
        long npuPortCna = topologyMap.get(templateType).getNodeMap().get("type:npu|slot:2|ubpu:1|die:2").
            getPortMap().get(0).getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, npuPortCna, 2);
    }

    @Test
    void calculateL2SwRouteInterRackTest() {
        String templateType = "128_npu_inter_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l2_sw|index:1|chip:1");
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(4, routeTable.getRouteEntries().size());
        // cost校验：l2_sw直连4个l1_sw，cost都为1
        long l1SwNodeCna = topologyMap.get(templateType).getNodeMap().get("type:l1_sw|index:1").
            getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, l1SwNodeCna, 1);
    }
}
