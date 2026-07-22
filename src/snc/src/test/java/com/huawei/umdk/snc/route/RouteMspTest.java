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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
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

    private void printFormatNodeRouteInfo(SncTopology topology, RouteTable routeTable) {
        Map<Prefix, RouteEntry> routeEntries = routeTable.getRouteEntries();
        for (Map.Entry<Prefix, RouteEntry> entry : routeEntries.entrySet()) {
            List<Integer> outIfList = new ArrayList<>();
            for (NextHopPort nhp : entry.getValue().getNhpSet()) {
                outIfList.add(nhp.getOutPortId());
            }
            Collections.sort(outIfList);
            String destAddrDetail = "addr description " + addrToLabelDescription(topology, entry.getKey());
            String addr = "addr " + String.format("0x%x", entry.getKey().getAddr()) + " : maskLen " + entry.getKey().getMaskLen()
                + " : mask " + Long.toHexString(entry.getKey().getMask());
            String outPortId = "outPortId" + outIfList;
            System.out.printf("%-40s %-40s %-80s\n", addr, outPortId, destAddrDetail);
        }
    }

    @BeforeAll
    public static void init() {
        try {
            List<String> templateFiles = new ArrayList<>();
            templateFiles.add("src/main/resources/128_npu_rack.json");
            templateFiles.add("src/main/resources/128_npu_inter_rack.json");
            for (String template : templateFiles) {
                String jsonStr = Files.readString(Paths.get(template), StandardCharsets.UTF_8);
                SncTopology topology = TopoTemplateService.parseTemplateJson(jsonStr);
                topologyMap.put(topology.getLabel().getNames().get("type"), topology);
            }
        } catch (IOException e) {
            Assertions.fail(e);
        }
    }

    @Test
    void calculateNpuRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:npu|slot:1|ubpu:1|die:2");
        // 目的为31个npu：每个npu 8个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        // 目的为4个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(31 * (8 + 1) + 4 + 4 * 2 + 1, routeTable.getRouteEntries().size());
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
    }

    @Test
    void calculateL1SwRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l1_sw|index:1");
        // 目的为32个npu：每个npu 2个 port cna和1个 pg cna
        // 目的为1个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(32 * (2 + 1) + 1 * 2 + 1, routeTable.getRouteEntries().size());
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
    }

    @Test
    void calculateL2SwRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l2_sw|index:1|chip:1");
        // 目的为32个npu：每个npu 2个 port cna和1个 pg cna
        Assertions.assertEquals(32 * (2 + 1), routeTable.getRouteEntries().size());
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
    }

    @Test
    void calculateL2SwRouteInterRackTest() {
        String templateType = "128_npu_inter_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:l2_sw|index:1|chip:1");
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(4 * 1, routeTable.getRouteEntries().size());
        printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
    }
}
