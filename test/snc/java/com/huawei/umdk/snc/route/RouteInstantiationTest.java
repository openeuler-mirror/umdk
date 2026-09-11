/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-29
 * Note:
 */

package com.huawei.umdk.snc.route;

import com.huawei.umdk.snc.SncService;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
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

        SncTopology rackTopology = topologyMap.get("128_npu_rack");
        SncTopology interRackTopology = topologyMap.get("128_npu_inter_rack");

        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();

        // 1. 创建NPU设备：4个rack × 8个board × 4个NPU = 128个NPU
        for (int rack = 1; rack <= 4; rack++) {
            for (int board = 1; board <= 8; board++) {
                for (int npuIndex = 1; npuIndex <= 4; npuIndex++) {
                    String deviceName = getNpuDeviceName(superNode.getName(), rack, board, npuIndex);
                    Map<Integer, NpuForwardingChip> chips = new HashMap<>();
                    NpuForwardingChip iodie2 = new NpuForwardingChip(2);
                    iodie2.setPorts(new LinkedHashMap<>());
                    chips.put(2, iodie2);
                    NpuDevice npuDevice = new NpuDevice(deviceName, null, String.valueOf(rack),
                        chips, "os0", null, board, 0, npuIndex);
                    npuDevices.put(deviceName, npuDevice);
                }
            }
        }

        // 2. 创建L1 switch设备：4个rack × 4个L1 sw = 16个L1 sw
        for (int rack = 1; rack <= 4; rack++) {
            for (int index = 1; index <= 4; index++) {
                String deviceName = getL1SwName(superNode.getName(), rack, index);
                Map<Integer, SwForwardingChip> chips = new HashMap<>();
                SwForwardingChip chip1 = new SwForwardingChip(1);
                chip1.setPorts(new LinkedHashMap<>());
                chips.put(1, chip1);
                SwDevice swDevice = new SwDevice(deviceName, null, String.valueOf(rack),
                    chips, SwitchLevel.L1, index);
                swDevices.put(deviceName, swDevice);
            }
        }

        // 3. 创建L2 switch设备：4个L2 sw，每个含chip 1和chip 2
        for (int index = 1; index <= 4; index++) {
            String deviceName = getL2SwName(superNode.getName(), index);
            Map<Integer, SwForwardingChip> chips = new HashMap<>();
            SwForwardingChip chip1 = new SwForwardingChip(1);
            chip1.setPorts(new LinkedHashMap<>());
            SwForwardingChip chip2 = new SwForwardingChip(2);
            chip2.setPorts(new LinkedHashMap<>());
            chips.put(1, chip1);
            chips.put(2, chip2);
            SwDevice swDevice = new SwDevice(deviceName, null, null,
                chips, SwitchLevel.L2, index);
            swDevices.put(deviceName, swDevice);
        }

        // 4. 根据框内模板连接 NPU ↔ L1 sw（每框复制一份）
        for (SncNode npuNode : rackTopology.getNodeMap().values()) {
            if (!"npu".equals(npuNode.type())) {
                continue;
            }
            int slot = Integer.parseInt(npuNode.getLabel().getNames().get("slot"));
            int ubpu = Integer.parseInt(npuNode.getLabel().getNames().get("ubpu"));
            int die = Integer.parseInt(npuNode.getLabel().getNames().get("die"));

            for (int rack = 1; rack <= 4; rack++) {
                String npuDeviceName = getNpuDeviceName(superNode.getName(), rack, slot, ubpu);
                NpuDevice npuDevice = npuDevices.get(npuDeviceName);
                NpuForwardingChip chip = npuDevice.getForwardingChips().get(die);
                Map<String, NpuPortEntity> ports = chip.getPorts();

                for (SncPort sncPort : npuNode.getPortMap().values()) {
                    String peerLabel = sncPort.getPeerNodeId();
                    int peerL1Index = Label.getL1SwIndex(peerLabel);
                    String l1DeviceName = getL1SwName(superNode.getName(), rack, peerL1Index);
                    SwDevice l1Sw = swDevices.get(l1DeviceName);
                    SwForwardingChip l1Chip = l1Sw.getForwardingChips().get(1);
                    Map<String, SwPortEntity> l1Ports = l1Chip.getPorts();

                    SncNode l1Node = rackTopology.getNodeMap().get(peerLabel);
                    SncPort peerSncPort = l1Node.getPortMap().get(sncPort.getPeerPortId());
                    String peerPortName = peerSncPort.getPortName();

                    // NPU侧端口
                    NpuPortEntity npuPort = new NpuPortEntity();
                    npuPort.setPortName(sncPort.getPortName());
                    npuPort.setId(sncPort.getId());
                    npuPort.setChipIndex(die);
                    npuPort.setRemoteDevice(l1DeviceName);
                    npuPort.setRemotePort(peerPortName);
                    ports.put(sncPort.getPortName(), npuPort);

                    // L1 sw侧端口（NPU-facing）
                    if (!l1Ports.containsKey(peerPortName)) {
                        SwPortEntity l1Port = new SwPortEntity();
                        l1Port.setPortName(peerPortName);
                        l1Port.setId(peerSncPort.getId());
                        l1Port.setChipIndex(1);
                        l1Port.setRemoteDevice(npuDeviceName);
                        l1Port.setRemotePort(sncPort.getPortName());
                        l1Ports.put(peerPortName, l1Port);
                    }
                }
            }
        }

        // 5. 根据框间模板连接 L1 sw ↔ L2 sw
        //    模板中L1 sw索引1-4对应rack1，5-8对应rack2，9-12对应rack3，13-16对应rack4
        for (SncNode l1Node : interRackTopology.getNodeMap().values()) {
            if (!"l1_sw".equals(l1Node.type())) {
                continue;
            }
            int globalL1Index = Label.getL1SwIndex(l1Node.getLabel().toString());
            int rack = (globalL1Index - 1) / 4 + 1;
            int localL1Index = (globalL1Index - 1) % 4 + 1;

            String l1DeviceName = getL1SwName(superNode.getName(), rack, localL1Index);
            SwDevice l1Sw = swDevices.get(l1DeviceName);
            SwForwardingChip l1Chip = l1Sw.getForwardingChips().get(1);
            Map<String, SwPortEntity> l1Ports = l1Chip.getPorts();

            for (SncPort sncPort : l1Node.getPortMap().values()) {
                String peerLabel = sncPort.getPeerNodeId();
                if (!peerLabel.contains("l2_sw")) {
                    continue;
                }

                Label peerL2Label = new Label();
                peerL2Label.refreshAllNames(peerLabel);
                int peerL2Index = Integer.parseInt(peerL2Label.getNames().get("index"));
                int peerL2Chip = Integer.parseInt(peerL2Label.getNames().get("chip"));
                String l2DeviceName = getL2SwName(superNode.getName(), peerL2Index);
                SwDevice l2Sw = swDevices.get(l2DeviceName);
                SwForwardingChip l2Chip = l2Sw.getForwardingChips().get(peerL2Chip);
                Map<String, SwPortEntity> l2Ports = l2Chip.getPorts();

                SncNode l2Node = interRackTopology.getNodeMap().get(peerLabel);
                SncPort peerSncPort = l2Node.getPortMap().get(sncPort.getPeerPortId());
                String peerPortName = peerSncPort.getPortName();

                // L1 sw侧端口（L2-facing）
                if (!l1Ports.containsKey(sncPort.getPortName())) {
                    SwPortEntity l1Port = new SwPortEntity();
                    l1Port.setPortName(sncPort.getPortName());
                    l1Port.setId(sncPort.getId());
                    l1Port.setChipIndex(1);
                    l1Port.setRemoteDevice(l2DeviceName);
                    l1Port.setRemotePort(peerPortName);
                    l1Ports.put(sncPort.getPortName(), l1Port);
                }

                // L2 sw侧端口
                if (!l2Ports.containsKey(peerPortName)) {
                    SwPortEntity l2Port = new SwPortEntity();
                    l2Port.setPortName(peerPortName);
                    l2Port.setId(peerSncPort.getId());
                    l2Port.setChipIndex(peerL2Chip);
                    l2Port.setRemoteDevice(l1DeviceName);
                    l2Port.setRemotePort(sncPort.getPortName());
                    l2Ports.put(peerPortName, l2Port);
                }
            }
        }

        superNode.setNpuDevices(npuDevices);
        superNode.setSwDevices(swDevices);
    }

    @BeforeAll
    public static void init() {
        SncService.registerLogCallback(((level, msg) -> {
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
                log.info("    %s converged=%s", outPortInfo.getPortName(), outPortInfo.isConverged());
            }
        }
    }

    @Test
    void makeRoutesTest() {
        SncService service = new SncService();
        service.routeCalculate();
        Map<String, Map<String, RoutingEntry>> result = service.makeRoutes(superNode);
        NpuDevice npuDevice = superNode.getNpuDevices().get(getNpuDeviceName(superNode.getName(), 2, 3, 4));
        // 拼接该npu对应的路由的key
        String key = npuDevice.getDeviceName().concat("#").concat("2");
        Map<String, RoutingEntry> routeMap = result.get(key);
        printRoutingEntry(routeMap);
        // 目的为31个npu：每个npu 8个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        // 目的为4个l2 sw：每个l2 sw 2个 node cna
        // 框间发布地址：1个
        Assertions.assertEquals(31 * (8 + 1) + 4 + 4 * 2 + 3 * 32, routeMap.size());
    }

    @Test
    void calculateNpuRouteTest() {
        SncService service = new SncService();
        service.routeCalculate();
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
        SncService service = new SncService();
        service.routeCalculate();
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
        SncService service = new SncService();
        service.routeCalculate();
        service.makeRoutes(superNode);
        SwDevice swDevice = superNode.getSwDevices().get(getL2SwName(superNode.getName(), 3));
        Map<String, RoutingEntry> routeMap = service.getNodeRoute(swDevice.getDeviceName(), 2);
        printRoutingEntry(routeMap);
        // 目的128个npu：每个npu 2个 port cna和1个 pg cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(128 * (2 + 1) + 4, routeMap.size());
    }
}
