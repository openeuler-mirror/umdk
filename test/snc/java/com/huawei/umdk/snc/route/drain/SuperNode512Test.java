/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: active drain service test
 * Create: 2026-11-18
 * Note:
 */

package com.huawei.umdk.snc.route.drain;

import com.huawei.umdk.snc.SncService;
import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.entity.ConvergedNodeRoute;
import com.huawei.umdk.snc.entity.ConvergedPrefix;
import com.huawei.umdk.snc.entity.ConvergedRouteResult;
import com.huawei.umdk.snc.entity.DrainEvent;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.TestUtils;
import com.huawei.umdk.snc.route.service.RouteInstantiationService;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.model.SuperNodeType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SuperNode512Test {
    private static final Logger LOG = new Logger(SuperNode512Test.class);

    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

    private static final SuperNode superNode = new SuperNode();

    private SncService sncService;

    @BeforeAll
    public void init() {
        SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        sncService = new SncService();
        sncService.init(new SNCConfig());

        topologyMap.putAll(TestUtils.parseTopoTemplate());

        TestUtils.constructSuperNode(superNode, topologyMap, 16, 16);

        Map<String, Map<String, RoutingEntry>> nodeRoutes = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_512.getValue());

        // 将实例化路由下发到 superNode 各设备芯片的 RoutingTable
        fillChipRoutingTables(nodeRoutes);
    }

    @AfterAll
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
        String l2sw1 = TestUtils.getL2SwName(superNode.getName(), 1);
        List<String> connectedL1sws = findDevicesConnectedTo(l2sw1);
        assertFalse(connectedL1sws.isEmpty(), "l2sw1 should have connected l1sw");

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, l2sw1, null));

        assertFalse(result.getRouteMap().isEmpty(), "drain l2sw1 should produce changes");

        // 16个L1 SW
        assertEquals(16, result.getRouteMap().size());
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            assertTrue(entry.getKey().contains("l1sw"));
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(16, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertTrue(prefix.isAllConverged());
            }
        }
    }

    @Test
    void l1swDrain() {
        String l1sw1 = TestUtils.getL1SwName(superNode.getName(), 1, 1);
        // rack1-L1SW1 仅与本框 32 个 NPU 和 4个L2SW互联
        List<String> connectedDevices = findDevicesConnectedTo(l1sw1);
        assertEquals(36, connectedDevices.size());

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_DEVICE, l1sw1, null));

        // 收敛明细恰为 512 个 NPU：rack1 32 个（起始节点）+ 其他框 15*32 个（接收节点）
        assertEquals(512, result.getRouteMap().size());
        for (String deviceName : result.getRouteMap().keySet()) {
            assertTrue(deviceName.contains("npu"), "changes should cover npus only");
        }

        // rack1 NPU：其他框96个NPU（1个聚合地址）+ 本框其他31个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (!entry.getKey().contains("rack1#")) {
                continue;
            }
            ConvergedNodeRoute route = entry.getValue();
            assertEquals(2, route.getPortPrefixes().size());
            for (ConvergedPrefix prefix : route.getPortPrefixes().values()) {
                assertTrue(prefix.isAllConverged());
                assertTrue(prefix.getRoutePrefixes().isEmpty());
            }
        }

        // 其他框 NPU：本框32个NPU（1个聚合地址）
        for (Map.Entry<String, ConvergedNodeRoute> entry : result.getRouteMap().entrySet()) {
            if (entry.getKey().contains("rack1#")) {
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
        String l1sw1 = TestUtils.getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = TestUtils.getL2SwName(superNode.getName(), 1);
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

    // ==================== 链路切流：跨节点传播场景 ====================
    @Test
    void twoNpuL1LinkDrain() {
        String npu0 = TestUtils.getNpuDeviceName(superNode.getName(), 1, 1, 1);
        String l1sw1 = TestUtils.getL1SwName(superNode.getName(), 1, 1);
        List<PortEntity> npuPorts = portsTo(npu0, 2, l1sw1);
        assertEquals(2, npuPorts.size(), "npu0 should have 2 links to l1sw1");
        PortEntity npuPort1 = npuPorts.get(0);
        PortEntity npuPort2 = npuPorts.get(1);

        // 同一事件的 portNames 携带全部 2 条链路的本端端口，对端由拓扑查询
        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, npu0,
            new HashSet<>(Arrays.asList(npuPort1.getPortName(), npuPort2.getPortName()))));

        // 本地收敛明细恰为 512 个设备：NPU0 + 其他 511 个 NPU
        assertEquals(512, result.getRouteMap().size());

        // NPU0 侧：其他框96个NPU（1个聚合地址） + 31个同框NPU聚合地址，本地收敛落表
        ConvergedNodeRoute npu0Route = result.getRouteMap().get(npu0);
        for (Map.Entry<String, ConvergedPrefix> entry : npu0Route.getPortPrefixes().entrySet()) {
            assertTrue(entry.getValue().isAllConverged());
            assertTrue(entry.getValue().getRoutePrefixes().isEmpty());
        }
        // 其他511个NPU：本地收敛到npu0的1个聚合地址前缀
        for (String deviceName : result.getRouteMap().keySet()) {
            if (deviceName.contains(npu0)) {
                continue;
            }
            ConvergedNodeRoute npuRoute = result.getRouteMap().get(deviceName);
            assertEquals(2, npuRoute.getPortPrefixes().size());
            for (ConvergedPrefix prefix : npuRoute.getPortPrefixes().values()) {
                assertFalse(prefix.isAllConverged());
                assertEquals(1, prefix.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1L2OneChipAllLinksDrain() {
        String l1sw1 = TestUtils.getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = TestUtils.getL2SwName(superNode.getName(), 1);
        // L2SW1 chip1 上朝向 rack1-L1SW1 的 8 条链路 → 反查 L1SW1 侧被切端口名
        List<PortEntity> l2PortsOnChip1 = portsTo(l2sw1, 1, l1sw1);
        assertEquals(8, l2PortsOnChip1.size());
        Set<String> drainedPorts = new HashSet<>();
        for (PortEntity l2Port : l2PortsOnChip1) {
            drainedPorts.add(l2Port.getRemotePort());
        }

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1, drainedPorts));

        // 收敛明细恰为 16 个 L1SW：本端 rack1-L1SW1+ 其他rack的 L1SW1
        assertEquals(16, result.getRouteMap().size());
        assertTrue(result.getRouteMap().containsKey(l1sw1));

        // 本端 rack1-L1SW1
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(drainedPorts, l1Node.getPortPrefixes().keySet());
        for (ConvergedPrefix prefixes : l1Node.getPortPrefixes().values()) {
            assertTrue(prefixes.isAllConverged());
        }

        // 其他 rack 的 L1SW1
        for (int rack = 2; rack <= 16; rack++) {
            String remoteL1sw = TestUtils.getL1SwName(superNode.getName(), rack, 1);
            ConvergedNodeRoute remoteNode = result.getRouteMap().get(remoteL1sw);
            // 8个接口
            assertEquals(8, remoteNode.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : remoteNode.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(32 * 5 + 1, prefixes.getRoutePrefixes().size());
            }
        }
    }

    @Test
    void l1L2TwoChipAllLinksDrain() {
        String l1sw1 = TestUtils.getL1SwName(superNode.getName(), 1, 1);
        String l2sw1 = TestUtils.getL2SwName(superNode.getName(), 1);
        List<PortEntity> l2PortsOnChip1 = portsTo(l2sw1, 1, l1sw1);
        List<PortEntity> l2PortsOnChip2 = portsTo(l2sw1, 2, l1sw1);
        Set<String> drainedPorts = new HashSet<>();
        for (PortEntity l2Port : l2PortsOnChip1) {
            drainedPorts.add(l2Port.getRemotePort());
        }

        for (PortEntity l2Port : l2PortsOnChip2) {
            drainedPorts.add(l2Port.getRemotePort());
        }
        assertEquals(16, drainedPorts.size());

        ConvergedRouteResult result = sncService.routeConvergence(superNode, new DrainEvent(
            DrainEvent.ACTION_DISABLE, DrainEvent.EVENT_TYPE_LINK, l1sw1, drainedPorts));

        // 收敛设备为16个l1 sw
        // 本端 rack1-L1SW1
        ConvergedNodeRoute l1Node = result.getRouteMap().get(l1sw1);
        assertEquals(drainedPorts, l1Node.getPortPrefixes().keySet());
        for (ConvergedPrefix prefixes : l1Node.getPortPrefixes().values()) {
            assertTrue(prefixes.isAllConverged());
        }

        // 其他 rack 的 L1SW1
        for (int rack = 2; rack <= 16; rack++) {
            String remoteL1sw = TestUtils.getL1SwName(superNode.getName(), rack, 1);
            ConvergedNodeRoute remoteNode = result.getRouteMap().get(remoteL1sw);
            // 16个接口
            assertEquals(16, remoteNode.getPortPrefixes().size());
            for (ConvergedPrefix prefixes : remoteNode.getPortPrefixes().values()) {
                assertFalse(prefixes.isAllConverged());
                assertEquals(32 * 5 + 1, prefixes.getRoutePrefixes().size());
            }
        }
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
