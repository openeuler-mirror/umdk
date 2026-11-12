/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: active drain service test
 * Create: 2026-11-05
 * Note:
 */

package com.huawei.umdk.snc.route;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.huawei.umdk.snc.entity.ConvergedNodeRoute;
import com.huawei.umdk.snc.entity.ConvergedPrefix;
import com.huawei.umdk.snc.entity.ConvergedRouteResult;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DrainEvent;
import com.huawei.umdk.snc.route.topo.template.model.SuperNodeType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.SncService;
import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.route.service.RouteInstantiationService;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;

/**
 * ActiveDrainService 切流单元测试。
 */
public class SuperNode128ActiveDrainServiceTest {
    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

    private static final SuperNode superNode = new SuperNode();

    private SncService sncService;

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

        SncTopology rackTopology = topologyMap.get(SuperNodeType.ATLAS950_GALAXY_RACK32.getValue());
        SncTopology interRackTopology = topologyMap.get(SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());

        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();

        // 1. 创建NPU设备：4个rack × 8个board × 4个NPU = 128个NPU
        for (int rack = 1; rack <= 4; rack++) {
            for (int board = 1; board <= 8; board++) {
                for (int npuIndex = 1; npuIndex <= 4; npuIndex++) {
                    int boardIndex = board * 2 - 1;
                    String deviceName = getNpuDeviceName(superNode.getName(), rack, boardIndex, npuIndex);
                    Map<Integer, NpuForwardingChip> chips = new HashMap<>();
                    NpuForwardingChip iodie2 = new NpuForwardingChip(2);
                    iodie2.setPorts(new LinkedHashMap<>());
                    chips.put(2, iodie2);
                    NpuDevice npuDevice = new NpuDevice(deviceName, null, String.valueOf(rack),
                        chips, "os0", null, boardIndex, 0, npuIndex);
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

    @BeforeEach
    public void init() {
        SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        sncService = new SncService();
        sncService.init(new SNCConfig());

        topologyMap.putAll(TestUtils.parseTopoTemplate());

        constructSuperNode();

        sncService.routeCalculate();
        Map<String, Map<String, RoutingEntry>> nodeRoutes = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());

        // 将实例化路由下发到 superNode 各设备芯片的 RoutingTable
        fillChipRoutingTables(nodeRoutes);
    }

    @AfterEach
    public void uninit() {
        sncService.uninit();
        sncService = null;
        topologyMap.clear();
    }

    /**
     * 将 makeRoutes 生成的实例化路由下发到 superNode 各设备芯片的 RoutingTable。
     */
    private void fillChipRoutingTables(Map<String, Map<String, RoutingEntry>> nodeRoutes) {
        if (superNode.getNpuDevices() != null) {
            for (NpuDevice npuDevice : superNode.getNpuDevices().values()) {
                for (NpuForwardingChip chip : npuDevice.getForwardingChips().values()) {
                    fillChipRoutingTable(nodeRoutes, npuDevice.getDeviceName(), chip);
                }
            }
        }
        if (superNode.getSwDevices() != null) {
            for (SwDevice swDevice : superNode.getSwDevices().values()) {
                for (SwForwardingChip chip : swDevice.getForwardingChips().values()) {
                    fillChipRoutingTable(nodeRoutes, swDevice.getDeviceName(), chip);
                }
            }
        }
    }

    private void fillChipRoutingTable(Map<String, Map<String, RoutingEntry>> nodeRoutes,
        String deviceName, ForwardingChip chip) {
        String key = RouteInstantiationService.buildRouteTableKey(deviceName, chip.getChipIndex());
        Map<String, RoutingEntry> routingEntries = nodeRoutes.get(key);
        if (routingEntries == null || routingEntries.isEmpty()) {
            return;
        }

        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();
        List<Integer> maskLengths = new ArrayList<>();
        for (RoutingEntry routingEntry : routingEntries.values()) {
            RoutePrefix prefix = routingEntry.getPrefix();
            routes.put(prefix, RoutingEntry.copy(routingEntry));
            maskLengths.add(prefix.getMaskLength());
        }
        maskLengths.sort(Collections.reverseOrder());

        RoutingTable routingTable =
            new RoutingTable(deviceName, chip.getChipIndex(), routes, maskLengths);
        chip.setRoutingTable(routingTable);
    }

    // ==================== 设备切流场景 ====================
    @Test
    void l2swDrain() {
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        List<String> connectedL1sws = findDevicesConnectedTo(l2sw1);
        assertFalse(connectedL1sws.isEmpty(), "l2sw1 should have connected l1sw");

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, l2sw1, null));

        assertFalse(result.getRouteMap().isEmpty(), "drain l2sw1 should produce changes");

        // NPU 侧：受影响 L1SW 将不可达前缀通告给同框 NPU，
        // NPU 上本地收敛的路由落表置位，需传播的路由不落表
        assertEquals(128, result.getRouteMap().size());
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            assertTrue(entry.getKey().contains("npu"));
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(96, prefix.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l2swDrainRecovery() {
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        List<String> connectedL1sws = findDevicesConnectedTo(l2sw1);
        assertFalse(connectedL1sws.isEmpty(), "l2sw1 should have connected l1sw");
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_DEVICE, l2sw1, null));

        assertFalse(result.getRouteMap().isEmpty(), "drain l2sw1 should produce changes");

        // NPU 侧：受影响 L1SW 将不可达前缀通告给同框 NPU，
        // NPU 上本地收敛的路由落表置位，需传播的路由不落表
        assertEquals(128, result.getRouteMap().size());
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            assertTrue(entry.getKey().contains("npu"));
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(96, prefix.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1swDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        // rack1-L1SW1 仅与本框 32 个 NPU 和 L2SW1（同索引）互联
        List<String> connectedDevices = findDevicesConnectedTo(l1sw1);
        assertEquals(33, connectedDevices.size(), "l1sw1 should connect to 32 npus and l2sw1");

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, l1sw1, null));

        // 被切设备自身不处理；L2SW1 全部翻转传播不落表 → 交换机均无收敛明细
        assertFalse(result.getRouteMap().containsKey(l1sw1), "drained l1sw1 should not be in changes");
        assertFalse(result.getRouteMap().containsKey(getL2SwName(superNode.getName(), 1)),
            "l2sw1 propagates without commit, should not be in changes");

        // 收敛明细恰为 128 个 NPU：rack1 32 个（起始节点）+ 其他框 96 个（接收节点）
        assertEquals(128, result.getRouteMap().size());
        for (String deviceName : result.getRouteMap().keySet()) {
            assertTrue(deviceName.contains("npu"), "changes should cover npus only");
        }

        // rack1 NPU：其他框96个NPU（1个聚合地址）+ 本框其他31个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (!entry.getKey().contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertTrue(prefix.isAllConverged());
                assertTrue(prefix.getRoutePrefixes().isEmpty());
            }
        }

        // 其他框 96 个 NPU：本框32个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (entry.getKey().contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(32, prefix.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1swDrainRecovery() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        // rack1-L1SW1 仅与本框 32 个 NPU 和 L2SW1（同索引）互联
        List<String> connectedDevices = findDevicesConnectedTo(l1sw1);
        assertEquals(33, connectedDevices.size(), "l1sw1 should connect to 32 npus and l2sw1");

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_DEVICE, l1sw1, null));

        // 收敛明细恰为 128 个 NPU：rack1 32 个（起始节点）+ 其他框 96 个（接收节点）
        assertEquals(128, result.getRouteMap().size());
        for (String deviceName : result.getRouteMap().keySet()) {
            assertTrue(deviceName.contains("npu"), "changes should cover npus only");
        }

        // rack1 NPU：其他框96个NPU（1个聚合地址）+ 本框其他31个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (!entry.getKey().contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertTrue(prefix.isAllConverged());
            }
        }

        // 其他框 96 个 NPU：本框32个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (entry.getKey().contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(32, prefix.getRoutePrefixes().size());
            }
        }
    }

    // ==================== 链路切流：本地收敛（不传播）场景 ====================
    @Test
    void singleL1L2LinkDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        PortEntity l1Port = portsTo(l1sw1, 1, l2sw1).get(0);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1,
            Collections.singleton(l1Port.getPortName())));

        // 本地收敛不传播：结果仅含两端设备，无其他设备被波及
        assertEquals(2, result.getRouteMap().size());
        // 本端 l1sw1：仅被切端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Collections.singleton(l1Port.getPortName()), l1Node.getPortPrefixes().keySet());
        assertTrue(l1Node.getPortPrefixes().get(l1Port.getPortName()).isAllConverged());
        assertTrue(l1Node.getPortPrefixes().get(l1Port.getPortName()).getRoutePrefixes().isEmpty());

        // 对端 l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        String l2Port = l1Port.getRemotePort();
        assertEquals(Collections.singleton(l2Port), l2Node.getPortPrefixes().keySet());
        assertTrue(l2Node.getPortPrefixes().get(l2Port).isAllConverged());
        assertTrue(l2Node.getPortPrefixes().get(l2Port).getRoutePrefixes().isEmpty());
    }

    @Test
    void singleL1L2LinkRecovery() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        PortEntity l1Port = portsTo(l1sw1, 1, l2sw1).get(0);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1,
            Collections.singleton(l1Port.getPortName())));

        // 本地收敛不传播：结果仅含两端设备，无其他设备被波及
        assertEquals(2, result.getRouteMap().size());
        // 本端 l1sw1：仅被切端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Collections.singleton(l1Port.getPortName()), l1Node.getPortPrefixes().keySet());
        assertTrue(l1Node.getPortPrefixes().get(l1Port.getPortName()).isAllConverged());

        // 对端 l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        String l2Port = l1Port.getRemotePort();
        assertEquals(Collections.singleton(l2Port), l2Node.getPortPrefixes().keySet());
        assertTrue(l2Node.getPortPrefixes().get(l2Port).isAllConverged());
    }

    @Test
    void singleL1L2LinkDrainRecoveryWhenLinkDrained() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        PortEntity l1Port = portsTo(l1sw1, 1, l2sw1).get(0);
        PortEntity remotePort = getRemotePort(l1Port);
        assertNotNull(remotePort);

        l1Port.setDrained(true);
        remotePort.setDrained(true);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1,
            Collections.singleton(l1Port.getPortName())));

        // 本地收敛不传播：结果仅含两端设备，无其他设备被波及
        assertEquals(2, result.getRouteMap().size());
        // 本端 l1sw1：仅被切端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Collections.singleton(l1Port.getPortName()), l1Node.getPortPrefixes().keySet());
        assertTrue(l1Node.getPortPrefixes().get(l1Port.getPortName()).isAllConverged());

        // 对端 l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        String l2Port = l1Port.getRemotePort();
        assertEquals(Collections.singleton(l2Port), l2Node.getPortPrefixes().keySet());
        assertTrue(l2Node.getPortPrefixes().get(l2Port).isAllConverged());
    }

    @Test
    void twoL1L2LinkInOneL2ChipDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        List<PortEntity> portList = portsTo(l2sw1, 1, l1sw1);
        PortEntity l2Port1 = portList.get(0);
        PortEntity l2Port2 = portList.get(1);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l2sw1,
                new HashSet<>(Arrays.asList(l2Port1.getPortName(), l2Port2.getPortName()))));

        assertEquals(2, result.getRouteMap().size());
        // l1sw1：仅被切端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Set.of(l2Port1.getRemotePort(), l2Port2.getRemotePort()), l1Node.getPortPrefixes().keySet());
        for (Map.Entry<String, ConvergedPrefix> entry : l1Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }

        // l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        assertEquals(Set.of(l2Port1.getPortName(), l2Port2.getPortName()), l2Node.getPortPrefixes().keySet());
        for (Map.Entry<String, ConvergedPrefix> entry : l2Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
    }

    @Test
    void twoL1L2LinkInOneL2ChipDrainRecovery() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        List<PortEntity> portList = portsTo(l2sw1, 1, l1sw1);
        PortEntity l2Port1 = portList.get(0);
        PortEntity l1Port1 = getRemotePort(l2Port1);
        assertNotNull(l1Port1);
        PortEntity l2Port2 = portList.get(1);
        PortEntity l1Port2 = getRemotePort(l2Port2);
        assertNotNull(l1Port2);

        l1Port1.setDrained(true);
        l2Port1.setDrained(true);
        l1Port2.setDrained(true);
        l2Port2.setDrained(true);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1,
            new HashSet<>(Arrays.asList(l1Port1.getPortName(), l1Port2.getPortName()))));

        assertEquals(2, result.getRouteMap().size());
        // l1sw1：仅被切端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Set.of(l1Port1.getPortName(), l1Port2.getPortName()), l1Node.getPortPrefixes().keySet());
        for (Map.Entry<String, ConvergedPrefix> entry : l1Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }

        // l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        assertEquals(Set.of(l2Port1.getPortName(), l2Port2.getPortName()), l2Node.getPortPrefixes().keySet());
        for (Map.Entry<String, ConvergedPrefix> entry : l2Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
    }

    /* 对端多芯片——L1SW1 朝向 L2SW1 chip1 与 chip2 的链路各取 1 条 drain */
    @Test
    void twoL1L2LinkInTwoL2ChipDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        // L1SW1 上朝向 L2SW1 chip1 / chip2 链路的本端端口（经对端端口反向查询）
        PortEntity l2PortOnChip1 = portsTo(l2sw1, 1, l1sw1).get(0);
        PortEntity l2PortOnChip2 = portsTo(l2sw1, 2, l1sw1).get(0);
        String l1PortToChip1 = l2PortOnChip1.getRemotePort();
        String l1PortToChip2 = l2PortOnChip2.getRemotePort();

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1,
            new HashSet<>(Arrays.asList(l1PortToChip1, l1PortToChip2))));

        // 本地收敛不传播：结果仅含两端设备，无其他设备被波及
        assertEquals(2, result.getRouteMap().size());

        // 本端 l1sw1
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(Set.of(l1PortToChip1, l1PortToChip2), l1Node.getPortPrefixes().keySet(),
            "l1sw1 changes should be on the drained port only");
        for (Map.Entry<String, ConvergedPrefix> entry : l1Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }

        // 对端 l2sw1：仅对端端口有明细，前缀与切流前经该链路的前缀完全一致
        ConvergedNodeRoute l2Node = result.getRouteMap().get(l2sw1);
        assertEquals(Set.of(l2PortOnChip1.getPortName(), l2PortOnChip2.getPortName()), l2Node.getPortPrefixes().keySet(),
            "l2sw1 changes should be on the drained peer port only");
        for (Map.Entry<String, ConvergedPrefix> entry : l2Node.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
    }

    // ==================== 链路切流：跨节点传播场景 ====================
    @Test
    void singleNpuL1LinkDrain() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        PortEntity npuPort = portsTo(npu0, 2, l1sw1).get(0);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            Collections.singleton(npuPort.getPortName())));

        // 本地收敛明细恰为 2 个设备：NPU + L1SW
        assertEquals(2, result.getRouteMap().size());

        // NPU 侧：96 远端发布地址 + 31 同框其他NPU (1聚合地址) + 1个L1，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        assertTrue(npu0Route.getPortPrefixes().get(npuPort.getPortName()).isAllConverged());
        assertTrue(npu0Route.getPortPrefixes().get(npuPort.getPortName()).getRoutePrefixes().isEmpty());

        // L1SW 侧：1 PG地址 + 1聚合地址 + 1个node地址(1个port地址会传播，不返回结果)，本地收敛落表
        ConvergedNodeRoute l1swRoute = result.getRouteMap().get(l1sw1);
        assertTrue(l1swRoute.getPortPrefixes().get(npuPort.getRemotePort()).isAllConverged());
        assertTrue(l1swRoute.getPortPrefixes().get(npuPort.getRemotePort()).getRoutePrefixes().isEmpty());
    }

    @Test
    void singleNpuL1LinkRecovery() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        PortEntity npuPort = portsTo(npu0, 2, l1sw1).get(0);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            Collections.singleton(npuPort.getPortName())));

        // 本地收敛明细恰为 2 个设备：NPU + L1SW
        assertEquals(2, result.getRouteMap().size());

        // NPU 侧：96 远端发布地址 + 31 同框其他NPU (1聚合地址) + 1个L1，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        assertTrue(npu0Route.getPortPrefixes().get(npuPort.getPortName()).isAllConverged());

        // L1SW 侧：1 PG地址 + 1聚合地址 + 1个node地址(1个port地址会传播，不返回结果)，本地收敛落表
        ConvergedNodeRoute l1swRoute = result.getRouteMap().get(l1sw1);
        assertTrue(l1swRoute.getPortPrefixes().get(npuPort.getRemotePort()).isAllConverged());
        assertTrue(l1swRoute.getPortPrefixes().get(npuPort.getRemotePort()).getRoutePrefixes().isEmpty());
    }

    @Test
    void singleNpuL1LinkDrainRecovery() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        PortEntity npuPort = portsTo(npu0, 2, l1sw1).get(0);
        PortEntity remotePort = getRemotePort(npuPort);
        assertNotNull(remotePort);

        npuPort.setDrained(true);
        remotePort.setDrained(true);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            Collections.singleton(npuPort.getPortName())));

        // 本地收敛明细恰为 2 个设备：NPU + L1SW
        assertEquals(2, result.getRouteMap().size());

        // NPU 侧：96 远端发布地址 + 31 同框其他NPU (1聚合地址) + 1个L1，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        assertTrue(npu0Route.getPortPrefixes().get(npuPort.getPortName()).isAllConverged());

        // L1SW 侧：1 PG地址 + 1聚合地址 + 1个node地址(1个port地址会传播，不返回结果)，本地收敛落表
        ConvergedNodeRoute l1swRoute = result.getRouteMap().get(l1sw1);
        assertTrue(l1swRoute.getPortPrefixes().get(npuPort.getRemotePort()).isAllConverged());
    }

    @Test
    void twoNpuL1LinkDrain() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        assertEquals(2, npuPorts.size(), "npu0 should have 2 links to l1sw1");
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity npuPort2 = npuPorts.get(1);

        // 同一事件的 portNames 携带全部 2 条链路的本端端口，对端由拓扑查询
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            new HashSet<>(Arrays.asList(npuPort1.getPortName(), npuPort2.getPortName()))));

        // 本地收敛明细恰为 128 个设备：NPU0 + 同框其他 31 个 NPU + 其他框96个NPU
        assertEquals(128, result.getRouteMap().size(),
            "changes should cover npu0 and 31 same-rack NPUs, switches propagate without commit");

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
            assertTrue(entry.getValue().getRoutePrefixes().isEmpty());
        }
        // 同框其他31个NPU：本地收敛到npu0的1个聚合地址前缀
        int count = 0;
        for (String deviceName : result.getRouteMap().keySet()) {
            if (!deviceName.contains("rack1") || deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
            count++;
        }
        assertEquals(31, count);

        // 其他框96个NPU：本地收敛到npu0的1个聚合前缀，
        count = 0;
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(1, prefixes.getRoutePrefixes().size());
            }
            count++;
        }
        assertEquals(96, count);
    }

    @Test
    void twoNpuL1LinkRecovery() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        assertEquals(2, npuPorts.size(), "npu0 should have 2 links to l1sw1");
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity npuPort2 = npuPorts.get(1);

        // 同一事件的 portNames 携带全部 2 条链路的本端端口，对端由拓扑查询
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            new HashSet<>(Arrays.asList(npuPort1.getPortName(), npuPort2.getPortName()))));

        // 本地收敛明细恰为 128 个设备：NPU0 + 同框其他 31 个 NPU + 其他框96个NPU
        assertEquals(128, result.getRouteMap().size(),
            "changes should cover npu0 and 31 same-rack NPUs, switches propagate without commit");

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
        // 同框其他 31 个 NPU：本地收敛到npu0的1个聚合地址前缀
        int count = 0;
        for (String deviceName : result.getRouteMap().keySet()) {
            if (!deviceName.contains("rack1") || deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
            count++;
        }
        assertEquals(31, count);

        // 其他框 96 个 NPU：本地收敛到npu0的1个聚合前缀，
        count = 0;
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(1, prefixes.getRoutePrefixes().size());
            }
            count++;
        }
        assertEquals(96, count);
    }

    @Test
    void twoNpuL1LinkDrainRecoveryWhenTwoLinkDrained() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        assertEquals(2, npuPorts.size(), "npu0 should have 2 links to l1sw1");
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity remotePort1 = getRemotePort(npuPort1);
        assertNotNull(remotePort1);
        PortEntity npuPort2 = npuPorts.get(1);
        PortEntity remotePort2 = getRemotePort(npuPort2);
        assertNotNull(remotePort2);

        npuPort1.setDrained(true);
        remotePort1.setDrained(true);
        npuPort2.setDrained(true);
        remotePort2.setDrained(true);

        // 同一事件的 portNames 携带全部 2 条链路的本端端口，对端由拓扑查询
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            new HashSet<>(Arrays.asList(npuPort1.getPortName(), npuPort2.getPortName()))));

        // 本地收敛明细恰为 128 个设备：NPU0 + 同框其他 31 个 NPU + 其他框96个NPU
        assertEquals(128, result.getRouteMap().size(),
            "changes should cover npu0 and 31 same-rack NPUs, switches propagate without commit");

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
        // 同框其他 31 个 NPU：本地收敛到npu0的1个聚合地址前缀
        for (String deviceName : result.getRouteMap().keySet()) {
            if (!deviceName.contains("rack1") || deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
        }

        // 其他框 96 个 NPU：本地收敛到npu0的1个聚合前缀，
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(1, prefixes.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void oneNpuL1LinkDrainRecoveryWhenTwoLinkDrained() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        assertEquals(2, npuPorts.size(), "npu0 should have 2 links to l1sw1");
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity remotePort1 = getRemotePort(npuPort1);
        assertNotNull(remotePort1);
        PortEntity npuPort2 = npuPorts.get(1);
        PortEntity remotePort2 = getRemotePort(npuPort2);
        assertNotNull(remotePort2);

        npuPort1.setDrained(true);
        remotePort1.setDrained(true);
        npuPort2.setDrained(true);
        remotePort2.setDrained(true);

        // 同一事件的 portNames 携带全部 2 条链路的本端端口，对端由拓扑查询
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_ENABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            new HashSet<>(Collections.singletonList(npuPort1.getPortName()))));

        // 本地收敛明细恰为 128 个设备：NPU0 + 同框其他 31 个 NPU + 其他框96个NPU
        assertEquals(128, result.getRouteMap().size(),
            "changes should cover npu0 and 31 same-rack NPUs, switches propagate without commit");

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
        // 同框其他 31 个 NPU：本地收敛到npu0的1个聚合地址前缀
        for (String deviceName : result.getRouteMap().keySet()) {
            if (!deviceName.contains("rack1") || deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
        }

        // 其他框 96 个 NPU：本地收敛到npu0的1个聚合前缀，
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(1, prefixes.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void singleNpuL1LinkDrainWhenAnotherLinkDrained() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity npuPort2 = npuPorts.get(1);
        PortEntity remotePort = getRemotePort(npuPort2);
        assertNotNull(remotePort);

        // 该link之前排空过
        npuPort2.setDrained(true);
        remotePort.setDrained(true);

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            Collections.singleton(npuPort1.getPortName())));

        // 本地收敛明细恰为 128 个设备：NPU0 + 同框其他 31 个 NPU + 其他框96个NPU
        assertEquals(128, result.getRouteMap().size(),
            "changes should cover npu0 and 31 same-rack NPUs, switches propagate without commit");

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
        }
        // 同框其他 31 个 NPU：本地收敛到npu0的1个聚合地址前缀
        for (String deviceName : result.getRouteMap().keySet()) {
            if (!deviceName.contains("rack1") || deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
        }

        // 其他框 96 个 NPU：本地收敛到npu0的1个聚合前缀，
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains("rack1")) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(1, prefixes.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1L2OneChipAllLinksDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        // L2SW1 chip1 上朝向 rack1-L1SW1 的 32 条链路 → 反查 L1SW1 侧被切端口名
        List<PortEntity> l2PortsOnChip1 = portsTo(l2sw1, 1, l1sw1);
        assertEquals(32, l2PortsOnChip1.size(), "l2sw1 chip1 should have 32 links to l1sw1");
        Set<String> drainedPorts = new HashSet<>();
        for (PortEntity l2Port : l2PortsOnChip1) {
            drainedPorts.add(l2Port.getRemotePort());
        }

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1, drainedPorts));

        // 收敛明细恰为 4 个 L1SW：本端 rack1-L1SW1+ rack2/3/4 的 L1SW1
        assertEquals(4, result.getRouteMap().size());
        assertTrue(result.getRouteMap().containsKey(l1sw1));

        // 本端 rack1-L1SW1
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(drainedPorts, l1Node.getPortPrefixes().keySet());
        for (ConvergedPrefix prefixes : l1Node.getPortPrefixes().values()) {
            assertTrue(prefixes.isAllConverged());
        }

        // 接收端 rack2/3/4 的 L1SW1
        for (int rack = 2; rack <= 4; rack++) {
            String remoteL1sw = getL1SwName(superNode.getName(), rack, 1);
            ConvergedNodeRoute remoteNode = result.getRouteMap().get(remoteL1sw);
            // 32个接口
            assertEquals(32, remoteNode.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : remoteNode.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(32 * 5 + 1, prefixes.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1L2TwoChipAllLinksDrain() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        List<PortEntity> l2PortsOnChip1 = portsTo(l2sw1, 1, l1sw1);
        List<PortEntity> l2PortsOnChip2 = portsTo(l2sw1, 2, l1sw1);
        Set<String> drainedPorts = new HashSet<>();
        for (PortEntity l2Port : l2PortsOnChip1) {
            drainedPorts.add(l2Port.getRemotePort());
        }

        for (PortEntity l2Port : l2PortsOnChip2) {
            drainedPorts.add(l2Port.getRemotePort());
        }
        assertEquals(64, drainedPorts.size());

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1, drainedPorts));

        // 收敛设备为128个npu
        assertEquals(128, result.getRouteMap().size());
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            assertTrue(entry.getKey().contains("npu"));
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                if (entry.getKey().contains("rack1")) {
                    assertEquals(96, prefix.getRoutePrefixes().size());
                } else {
                    assertEquals(32, prefix.getRoutePrefixes().size());
                }
            }
        }
    }

    @Test
    void singleL1L2LinkDrainTwice() {
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        PortEntity l1Port = portsTo(l1sw1, 1, l2sw1).get(0);
        DrainEvent event = new DrainEvent(DrainEvent.ACTION_DISABLE,
            DrainEvent.EVENT_TYPE_LINK, l1sw1, Collections.singleton(l1Port.getPortName()));

        sncService.routeConvergence(superNode, event);
        ConvergedRouteResult second = sncService.routeConvergence(superNode, event);

        assertEquals(2, second.getRouteMap().size());
    }

    // ==================== 参数与约束校验场景 ====================
    @Test
    void deviceDrainWithNpu() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, npu0, null)));
    }

    @Test
    void deviceDrainWithNotExistDevice() {
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE,
                "no-such-device", null)));
    }

    /* 链路切流事件 portNames 为空集合 */
    @Test
    void npuL1LinkDrainWithoutPortNames() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
                Collections.emptySet())));
    }

    /* 对端设备约束违规——NPU0 同时切到 L1SW1 与 L1SW2 的链路 */
    @Test
    void npuL1LinkDrainWithTwoL1() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        String l1sw2 = getL1SwName(superNode.getName(), 1, 2);
        PortEntity portToL1sw1 = portsTo(npu0, 2, l1sw1).get(0);
        PortEntity portToL1sw2 = portsTo(npu0, 2, l1sw2).get(0);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
                new HashSet<>(Arrays.asList(portToL1sw1.getPortName(),
                    portToL1sw2.getPortName())))));
    }

    @Test
    void npuL1LinkDrainWithNotExistPortName() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
                Collections.singleton("not-exist-port"))));
    }

    @Test
    void npuL1LinkDrainWithInvalidAction() {
        String npu0 = getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = getL1SwName(superNode.getName(), 1, 1);
        PortEntity npuPort = portsTo(npu0, 2, l1sw1).get(0);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent("unknown", DrainEvent.EVENT_TYPE_LINK, npu0,
                Collections.singleton(npuPort.getPortName()))));
    }

    @Test
    void routeConvergenceWithNullParams() {
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        assertThrows(IllegalArgumentException.class,
            () -> sncService.routeConvergence(null, new DrainEvent(
                DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, l2sw1, null)));
        assertThrows(IllegalArgumentException.class,
            () -> sncService.routeConvergence(superNode, null));
        assertThrows(IllegalArgumentException.class,
            () -> sncService.routeConvergence(superNode,
                new DrainEvent(DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l2sw1, null)));
    }

    /** eventType 非法 → 拒绝。 */
    @Test
    void routeConvergenceWithInvalidEventType() {
        String l2sw1 = getL2SwName(superNode.getName(), 1);
        assertThrows(IllegalArgumentException.class, () -> sncService.routeConvergence(superNode,
            new DrainEvent(DrainEvent.ACTION_DISABLE, "unknown", l2sw1, null)));
    }

    // ==================== 测试辅助 ====================

    /** 获取指定设备上朝向 peerDevice 的端口列表。 */
    private List<PortEntity> portsTo(String deviceName, int chipIndex, String peerDevice) {
        List<PortEntity> result = new ArrayList<>();
        Map<String, ? extends PortEntity> ports = superNode.getAllDevices().get(deviceName)
            .getForwardingChips().get(chipIndex).getPorts();
        for (PortEntity port : ports.values()) {
            if (peerDevice.equals(port.getRemoteDevice())) {
                result.add(port);
            }
        }
        return result;
    }

    private PortEntity getRemotePort(PortEntity portEntity) {
        DeviceEntity deviceEntity = superNode.getAllDevices().get(portEntity.getRemoteDevice());
        for (ForwardingChip chip : deviceEntity.getForwardingChips().values()) {
            for (PortEntity port : chip.getPorts().values()) {
                if (port.getRemotePort().equals(portEntity.getPortName())) {
                    return port;
                }
            }
        }

        return null;
    }

    /** 找出与指定设备直连的所有设备名（去重）。 */
    private List<String> findDevicesConnectedTo(String deviceName) {
        List<String> peers = new ArrayList<>();
        for (ForwardingChip chip : superNode.getAllDevices().get(deviceName)
            .getForwardingChips().values()) {
            for (PortEntity port : chip.getPorts().values()) {
                if (port.getRemoteDevice() != null && !peers.contains(port.getRemoteDevice())) {
                    peers.add(port.getRemoteDevice());
                }
            }
        }
        return peers;
    }
}
