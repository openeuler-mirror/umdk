/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-29
 * Note:
 */

package com.huawei.umdk.snc.route;

import com.huawei.umdk.snc.C3SncService;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class RouteInstantiationTest {
    private static final Logger log = new Logger(RouteMspTest.class);

    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

    private static final SuperNode superNode = new SuperNode();

    private static String getNpuDeviceName(String superNodeName, int rack, int board, int device) {
        return String.format("%s#rack%d#board%d#npu%d", superNodeName, rack, board, device);
    }

    private static String getL1SwName(String superNodeName, int rack, int index) {
        return String.format("%s#rack%d#l1sw%d", superNodeName, rack, index);
    }

    private static String getL2SwName(String superNodeName, int index) {
        return String.format("%s#l2sw%d", superNodeName, index);
    }

    private static void constructSuperNode() {
        superNode.setName("SuperNode1");

        Map<String, NpuDevice> npuDevices = new HashMap<>();
        for (int rack = 1; rack <= 4; rack++) {
            for (int board = 1; board <= 8; board++) {
                for (int npuIndex = 1; npuIndex <= 4; npuIndex++) {
                    String deviceName = getNpuDeviceName(superNode.getName(), rack,
                        board, npuIndex);
                    Map<Integer, NpuForwardingChip> chips = new HashMap<>();
                    chips.put(1, new NpuForwardingChip(1));
                    chips.put(2, new NpuForwardingChip(2));
                    NpuDevice npuDevice = new NpuDevice(deviceName, null, String.valueOf(rack),
                        chips, "os0", null,
                        board, 0, npuIndex);
                    npuDevices.put(deviceName, npuDevice);
                }
            }
        }

        Map<String, SwDevice> swDevices = new HashMap<>();
        for (int rack = 1; rack <= 4; rack++) {
            for (int index = 1; index <= 4; index++) {
                String deviceName = getL1SwName(superNode.getName(), rack, index);
                Map<Integer, SwForwardingChip> chips = new HashMap<>();
                chips.put(1, new SwForwardingChip(1));
                SwDevice swDevice = new SwDevice(deviceName, null, String.valueOf(rack),
                    chips, SwitchLevel.L1, index);
                swDevices.put(deviceName, swDevice);
            }
        }

        for (int index = 1; index <= 4; index++) {
            String deviceName = getL2SwName(superNode.getName(), index);
            Map<Integer, SwForwardingChip> chips = new HashMap<>();
            chips.put(1, new SwForwardingChip(1));
            chips.put(2, new SwForwardingChip(2));
            SwDevice swDevice = new SwDevice(deviceName, null, null,
                chips, SwitchLevel.L2, index);
            swDevices.put(deviceName, swDevice);
        }

        superNode.setNpuDevices(npuDevices);
        superNode.setSwDevices(swDevices);
    }

    @BeforeAll
    public static void init() {
        C3SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        topologyMap.putAll(TestUtils.parseTopoTemplate());

        constructSuperNode();
    }

    private void printRoutingEntry(Map<String, RoutingEntry> routeMap) {
        for (Map.Entry<String, RoutingEntry> entry : routeMap.entrySet()) {
            RoutingEntry routingEntry = entry.getValue();
            log.info("%s/%d", routingEntry.getPrefix().getDstAddress(),
                routingEntry.getPrefix().getMaskLength());
            for (OutPortInfo outPortInfo : routingEntry.getOutPortInfos().values()) {
                log.info("    %s active=%s", outPortInfo.getPortName(), outPortInfo.isActive());
            }
        }
    }

    @Test
    void calculateNpuRouteTest() {
        String templateType = "128_npu_rack";
        C3SncService service = new C3SncService();
        service.makeRoutes(superNode);
        NpuDevice npuDevice = superNode.getNpuDevices().get(getNpuDeviceName(superNode.getName(), 2, 3, 4));
        Map<String, RoutingEntry> routeMap = service.getNodeRoute(npuDevice.getDeviceName(), 2);
        printRoutingEntry(routeMap);
        // 目的为31个npu：每个npu 8个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        // 目的为4个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(31 * (8 + 1) + 4 + 4 * 2 + 3 * 32, routeMap.size());
    }

    @Test
    void calculateL1SwRouteTest() {
        String templateType = "128_npu_rack";
        C3SncService service = new C3SncService();
        service.makeRoutes(superNode);
        SwDevice swDevice = superNode.getSwDevices().get(getL1SwName(superNode.getName(), 3, 2));
        Map<String, RoutingEntry> routeMap = service.getNodeRoute(swDevice.getDeviceName(), 1);
        printRoutingEntry(routeMap);
        // 目的为32个npu：每个npu 2个 port cna和1个 pg cna
        // 目的为1个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：3框，每框32个
        Assertions.assertEquals(32 * (2 + 1) + 2 + 3 * 32, routeMap.size());
    }

    @Test
    void calculateL2SwRouteTest() {
        String templateType = "128_npu_rack";
        C3SncService service = new C3SncService();
        service.makeRoutes(superNode);
        SwDevice swDevice = superNode.getSwDevices().get(getL2SwName(superNode.getName(), 3));
        Map<String, RoutingEntry> routeMap = service.getNodeRoute(swDevice.getDeviceName(), 2);
        printRoutingEntry(routeMap);
        // 目的128个npu：每个npu 2个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(128 * (2 + 1) + 4, routeMap.size());
    }
}
