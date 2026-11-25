/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-29
 * Note:
 */

package com.huawei.umdk.snc.route.instantiation;

import com.huawei.umdk.snc.SncService;
import com.huawei.umdk.snc.config.SNCConfig;
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
import com.huawei.umdk.snc.route.TestUtils;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.model.SuperNodeType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SuperNode128Test {
    private static final Logger log = new Logger(SuperNode128Test.class);

    private static final Map<String, SncTopology> topologyMap = new HashMap<>();

    private static final SuperNode superNode = new SuperNode();

    private SncService sncService;

    @BeforeEach
    public void init() {
        SncService.registerLogCallback(((level, msg) -> {
            System.out.printf("[%s] %s\n", level.getValue(), msg);
        }));

        sncService = new SncService();
        sncService.init(new SNCConfig());

        topologyMap.putAll(TestUtils.parseTopoTemplate());

        TestUtils.constructSuperNode(superNode, topologyMap, 4, 4);
    }

    @AfterEach
    public void uninit() {
        sncService.uninit();
        sncService = null;
        topologyMap.clear();
    }

    private void printRoutingEntry(Map<String, RoutingEntry> routeMap) {
        for (Map.Entry<String, RoutingEntry> entry : routeMap.entrySet()) {
            RoutingEntry routingEntry = entry.getValue();
            log.info("address prefix %s", entry.getKey());
            List<String> interfaceList = new ArrayList<>();
            for (OutPortInfo outPortInfo : routingEntry.getOutPortInfos().values()) {
                interfaceList.add(outPortInfo.getPortName());
            }
            // 按端口从低到高打印：端口名中的数字段按数值比较（如 400GUB1/2/10 排在 400GUB1/2/2 之后）
            interfaceList.sort(SuperNode128Test::comparePortName);
            for (String interfaceName : interfaceList) {
                log.info("    %s", interfaceName);
            }
        }
    }

    private static int comparePortName(String left, String right) {
        return Integer.compare(getPortNumber(left), getPortNumber(right));
    }

    /**
     * 端口名格式：400GUB1/2/3 或 800GUB1/2/3:1（冒号后为子接口号），
     * 第2个"/"后面的数字是端口号。
     */
    private static int getPortNumber(String portName) {
        String[] parts = portName.split("/");
        String portPart = parts[parts.length - 1];
        int colonIndex = portPart.indexOf(':');
        if (colonIndex >= 0) {
            portPart = portPart.substring(0, colonIndex);
        }
        return Integer.parseInt(portPart);
    }

    @Test
    void makeRoutesTest() {
        Map<String, Map<String, RoutingEntry>> result = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());
        NpuDevice npuDevice = superNode.getNpuDevices().get(TestUtils.getNpuDeviceName(superNode.getName(), 2, 3, 4));
        // 拼接该npu对应的路由的key
        String key = npuDevice.getDeviceName().concat("#").concat("2");
        Map<String, RoutingEntry> routeMap = result.get(key);
        printRoutingEntry(routeMap);
        // 目的为本框31个npu：每个npu 1个 聚合 cna
        // 目的为本框4个l1 sw：每个l1 sw 1个 node cna
        // 框间发布地址转换：
        // 目的为其他框npu：3框，每框32个npu，每个npu 1个 聚合 cna
        Assertions.assertEquals(31 + 4 + 3 * 32, routeMap.size());
    }

    @Test
    void calculateNpuRouteTest() {
        Map<String, Map<String, RoutingEntry>> result = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());
        NpuDevice npuDevice = superNode.getNpuDevices().get(TestUtils.getNpuDeviceName(superNode.getName(), 2, 3, 4));
        Map<String, RoutingEntry> routeMap = result.get(npuDevice.getDeviceName().concat("#").concat("2"));
        printRoutingEntry(routeMap);
        // 目的为本框31个npu：每个npu 1个 聚合 cna
        // 目的为本框4个l1 sw：每个l1 sw 1个 node cna
        // 框间发布地址转换：
            // 目的为其他框npu：3框，每框32个npu，每个npu 1个 聚合 cna
        Assertions.assertEquals(31 + 4 + 3 * 32, routeMap.size());
    }

    @Test
    void calculateL1SwRouteTest() {
        Map<String, Map<String, RoutingEntry>> result = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());
        SwDevice swDevice = superNode.getSwDevices().get(TestUtils.getL1SwName(superNode.getName(), 3, 2));
        Map<String, RoutingEntry> routeMap = result.get(swDevice.getDeviceName().concat("#").concat("1"));
        printRoutingEntry(routeMap);
        // 目的为本框32个npu：每个npu 2个 port cna、1个 pg cna、1个node cna、1个聚合cna
        // 目的为1个l2 sw：每个l2 sw 2个 node cna
        // 发布地址转换：
            // 1.1 目的为其他框l1 sw：3个l1 sw，每个l1 sw 1个 node cna
            // 1.2 目的为其他框npu：3框，每框32个npu，每个npu 2个 port cna、1个 pg cna、1个node cna、1个聚合cna
        Assertions.assertEquals(32 * (2 + 1 + 1 + 1) + 2 + 3 + 3 * 32 * (2 + 1 + 1 + 1), routeMap.size());
    }

    @Test
    void calculateL2SwRouteTest() {
        Map<String, Map<String, RoutingEntry>> result = sncService.makeRoutes(superNode,
            SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue());
        SwDevice swDevice = superNode.getSwDevices().get(TestUtils.getL2SwName(superNode.getName(), 3));
        Map<String, RoutingEntry> routeMap = result.get(swDevice.getDeviceName().concat("#").concat("2"));
        printRoutingEntry(routeMap);
        // 目的128个npu：每个npu 2个 port cna、1个 pg cna、1个node cna、1个聚合cna
        // 目的为4个l1 sw：每个l1 sw 1个 node cna
        Assertions.assertEquals(128 * (2 + 1 + 1 + 1) + 4, routeMap.size());
    }
}
