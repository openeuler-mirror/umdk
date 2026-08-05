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
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;


public class RouteMspTest {
    private static final Logger log = new Logger(RouteMspTest.class);

    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

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

    @BeforeAll
    public static void init() {
        C3SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        topologyMap.putAll(TestUtils.parseTopoTemplate());
    }

    @Test
    void calculateNpuRouteTest() {
        String templateType = "128_npu_rack";
        Map<String, Map<String, RouteTable>> routeMaps = C3SncService.routeMSP();
        Map<String, RouteTable> routeMap = routeMaps.get(templateType);
        RouteTable routeTable = routeMap.get("type:npu|slot:1|ubpu:1|die:2");
        TestUtils.printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
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
        TestUtils.printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
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
        TestUtils.printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
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
        TestUtils.printFormatNodeRouteInfo(topologyMap.get(templateType), routeTable);
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(4, routeTable.getRouteEntries().size());
        // cost校验：l2_sw直连4个l1_sw，cost都为1
        long l1SwNodeCna = topologyMap.get(templateType).getNodeMap().get("type:l1_sw|index:1").
            getAddrList().getFirst().getAddr();
        assertRouteCost(routeTable, l1SwNodeCna, 1);
    }
}
