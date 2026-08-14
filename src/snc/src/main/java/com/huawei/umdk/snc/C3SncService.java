/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route service
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc;

import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.log.LogCallback;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.service.RouteInstantiationService;
import com.huawei.umdk.snc.route.service.RouteMspService;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;
import lombok.Getter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class C3SncService {
    private static final Logger log = new Logger(C3SncService.class);

    private static final List<String> TOPO_TEMPLATE_FILES = Arrays.asList("128_npu_rack.json",
        "128_npu_inter_rack.json");

    private final Map<String, SncTopology> topologyMap = new HashMap<>();

    private final Map<String, Map<String, RouteTable>> routeTemplateMap = new HashMap<>();

    // 超节点的路由模板
    private final Map<String, RouteTable> routes = new HashMap<>();

    // 上线的超节点的路由
    private volatile Map<String, Map<String, RoutingEntry>> instantiationRouteMap = new HashMap<>();

    private volatile boolean routeCalculated = false;

    public C3SncService() {
    }

    public static void registerLogCallback(LogCallback logCallback) {
        Logger.registerLogCallback(logCallback);
        log.info("register snc log callback success");
    }

    private static void calculateDefaultTemplateRoute(Map<String, SncTopology> topologyMap,
        Map<String, Map<String, RouteTable>> topologyRouteMap) {
        for (String filePath : TOPO_TEMPLATE_FILES) {
            SncTopology topology = TopoTemplateService.parseTemplateFile(filePath);
            String xpodType = topology.getLabel().getNames().get("type");
            if (xpodType == null) {
                throw new IllegalArgumentException("find invalid xpod type");
            }
            Map<String, RouteTable> routeMap = RouteMspService.routeMsp(topology);
            log.info("calculate default route template success");

            if (topologyMap != null) {
                topologyMap.put(xpodType, topology);
            }

            if (topologyRouteMap != null) {
                topologyRouteMap.put(xpodType, routeMap);
            }
        }
    }

    public static Map<String, Map<String, RouteTable>> routeMSP() {
        // Map<topology_type, <node label, route>>
        Map<String, Map<String, RouteTable>> topologyRouteMap = new HashMap<>();
        calculateDefaultTemplateRoute(null, topologyRouteMap);
        return topologyRouteMap;
    }

    // 路由计算加实例化
    public synchronized void routeCalculate() {
        if (routeCalculated) {
            log.info("route has calculated");
            return;
        }

        topologyMap.clear();
        routeTemplateMap.clear();
        routes.clear();

        calculateDefaultTemplateRoute(topologyMap, routeTemplateMap);

        RouteInstantiationService.instantiateXpodRoute(topologyMap, routeTemplateMap, routes);

        routeCalculated = true;
    }

    public Map<String, Map<String, RoutingEntry>> makeRoutes(SuperNode superNode) {
        if (!routeCalculated) {
            throw new IllegalStateException("calculate routeCalculate first");
        }

        if (superNode == null) {
            throw new IllegalArgumentException("superNode is null");
        }

        RouteInstantiationService service = new RouteInstantiationService();
        Map<String, Map<String, RoutingEntry>> tempRouteMap = new HashMap<>();
        if (superNode.getNpuDevices() != null) {
            log.info("find %d npu devices", superNode.getNpuDevices().size());
            for (NpuDevice npuDevice : superNode.getNpuDevices().values()) {
                service.makeNpuRoutes(npuDevice, routes, tempRouteMap);
            }
        }

        if (superNode.getSwDevices() != null) {
            log.info("find %d sw devices", superNode.getSwDevices().size());
            for (SwDevice swDevice : superNode.getSwDevices().values()) {
                service.makeSwRoutes(swDevice, routes, tempRouteMap);
            }
        }

        Map<String, Map<String, RoutingEntry>> copyRoutingEntry =
            RouteInstantiationService.deepCopyRoutingEntry(tempRouteMap);
        this.instantiationRouteMap.putAll(copyRoutingEntry);

        log.info("make routes success for %s, total %d entries", superNode.getName(), tempRouteMap.size());
        return tempRouteMap;
    }

    public Map<String, RoutingEntry> getNodeRoute(String deviceName, int chipIndex) {
        if (deviceName == null) {
            throw new IllegalArgumentException("device info is null");
        }

        String key = deviceName + "#" + chipIndex;
        Map<String, RoutingEntry> routingEntries = instantiationRouteMap.get(key);
        if (routingEntries == null) {
            throw new IllegalArgumentException("not found route for " + key);
        }

        return routingEntries;
    }
}
