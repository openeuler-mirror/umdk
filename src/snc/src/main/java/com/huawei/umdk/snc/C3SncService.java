/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route service
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.service.RouteMspService;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;
import lombok.Getter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class C3SncService {
    private static final Logger log = new Logger(C3SncService.class);

    private static final String TOPO_TEMPLATE_FILE_PATH = "src/main/resources";

    private static final Integer TOPOLOGY_NODE_MAX_COUNT = 8192;

    private static final Integer TOPOLOGY_PORT_MAX_COUNT = 30;

    private static final Integer TOPOLOGY_ADDRESS_MAX_COUNT = 10;

    @Getter
    private final SncTopology topology;

    public C3SncService(SncTopology topology) {
        checkTopology(topology);
        this.topology = topology;
        log.info("create snc service success with topology");
    }

    private void checkSncPort(SncNode node) {
        String nodeKey = node.getLabel().toString();
        Map<Integer, SncPort> portMap = node.getPortMap();
        if (portMap.isEmpty()) {
            throw new IllegalArgumentException(String.format("Node %s port is empty", nodeKey));
        }

        int portNum = portMap.size();
        if (portNum > TOPOLOGY_PORT_MAX_COUNT) {
            throw new IllegalArgumentException(String.format("node %s port number is too big %s", nodeKey,
                    portNum));
        }

        for (Map.Entry<Integer, SncPort> portEntry : portMap.entrySet()) {
            Integer srcPortId = portEntry.getKey();
            SncPort sncPort = portEntry.getValue();
            if (srcPortId == null || sncPort == null) {
                throw new IllegalArgumentException(String.format("node %s port entry key or value is null",
                    nodeKey));
            }

            if (!srcPortId.equals(sncPort.getId())) {
                throw new IllegalArgumentException(String.format("node %s port entry key %s and id %s is not equal",
                    nodeKey, srcPortId, sncPort.getId()));
            }

            if (sncPort.getId() < 0 || sncPort.getId() > TOPOLOGY_PORT_MAX_COUNT) {
                throw new IllegalArgumentException(String.format("node %s port index is too big %s",
                    nodeKey, sncPort.getId()));
            }

            int addressNum = sncPort.getAddrList().size();
            if (addressNum > TOPOLOGY_ADDRESS_MAX_COUNT) {
                throw new IllegalArgumentException(String.format("node %s port index %s address number is too big %s",
                    nodeKey, sncPort.getId(), addressNum));
            }

            Integer peerPortId = sncPort.getPeerPortId();
            if (peerPortId < 0 || peerPortId > TOPOLOGY_PORT_MAX_COUNT) {
                throw new IllegalArgumentException(String.format("node %s peer port index is too big %s",
                    nodeKey, peerPortId));
            }
        }
    }

    private void checkTopology(SncTopology topology) {
        if (topology == null) {
            throw new IllegalArgumentException("topology is null");
        }

        if (topology.getNodeMap().isEmpty()) {
            throw new IllegalArgumentException("node is empty");
        }

        if (topology.getNodeMap().size() > TOPOLOGY_NODE_MAX_COUNT) {
            throw new IllegalArgumentException("topology node number is too big");
        }

        for (Map.Entry<String, SncNode> entry : topology.getNodeMap().entrySet()) {
            String nodeKey = entry.getKey();
            SncNode node = entry.getValue();
            if (nodeKey == null || node == null) {
                throw new IllegalArgumentException("node entry key or value is null");
            }

            if (!nodeKey.equals(node.getLabel().toString())) {
                throw new IllegalArgumentException(String.format("node %s key and label %s is not equal", nodeKey,
                        node.getLabel()));
            }

            int addressNum = node.getAddrList().size();
            if (addressNum > TOPOLOGY_ADDRESS_MAX_COUNT) {
                throw new IllegalArgumentException(String.format("node %s address is too big %s", nodeKey,
                        addressNum));
            }

            checkSncPort(node);
        }
    }

    public static Map<String, Map<String, RouteTable>> routeMSP() {
        // Map<topology_type, <node label, route>>
        Map<String, Map<String, RouteTable>> topologyRouteMap = new HashMap<>();
        List<String> filePathList = new ArrayList<>();
        try (Stream<Path> stream = Files.list(Paths.get(TOPO_TEMPLATE_FILE_PATH))){
            stream.filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".json"))
                .forEach(path -> filePathList.add(path.toString()));
        } catch (IOException e) {
            throw new IllegalArgumentException("find invalid json file");
        }

        for (String filePath : filePathList) {
            try {
                String jsonStr = Files.readString(Paths.get(filePath), StandardCharsets.UTF_8);
                SncTopology topology = TopoTemplateService.parseTemplateJson(jsonStr);
                String xpodType = topology.getLabel().getNames().get("type");
                if (xpodType == null) {
                    throw new IllegalArgumentException("find invalid xpod type");
                }
                Map<String, RouteTable> routeMap = RouteMspService.routeMsp(topology);
                topologyRouteMap.put(xpodType, routeMap);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        return topologyRouteMap;
    }
}
