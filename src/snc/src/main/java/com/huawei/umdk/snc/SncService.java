/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.log.LogCallback;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.engine.AclCheckEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.LinkEvent;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.TpAclEntity;
import com.huawei.umdk.snc.exception.SNCStateException;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.service.RouteConvergeService;
import com.huawei.umdk.snc.route.service.RouteInstantiationService;
import com.huawei.umdk.snc.route.service.RouteMspService;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;
import com.huawei.umdk.snc.service.AclService;
import com.huawei.umdk.snc.service.LinkEventService;
import com.huawei.umdk.snc.service.PathService;
import com.huawei.umdk.snc.service.SuperNodeService;
import com.huawei.umdk.snc.store.AclStore;
import com.huawei.umdk.snc.store.SuperNodeStore;

public class SncService {

    private static final Logger LOG = new Logger(SncService.class);

    private static final List<String> TOPO_TEMPLATE_FILES = Arrays.asList("128_npu_rack.json",
        "128_npu_inter_rack.json");

    private final Map<String, SncTopology> topologyMap = new HashMap<>();

    private final Map<String, Map<String, RouteTable>> routeTemplateMap = new HashMap<>();

    // 超节点的路由模板
    private final Map<String, RouteTable> routes = new HashMap<>();

    // 上线的超节点的路由
    private volatile Map<String, Map<String, RoutingEntry>> instantiationRouteMap = new HashMap<>();

    private volatile boolean routeCalculated = false;

    private enum State {
        INIT, READY, DATAREADY, UNINIT
    }

    private volatile State state = State.INIT;

    private SuperNodeStore superNodeStore;

    private AclStore aclStore;

    private SuperNodeService superNodeService;

    private AclService aclService;

    private PathService pathService;

    private LinkEventService linkEventService;

    private RouteConvergeService routeConvergeService;

    private volatile boolean superNodeLoaded;

    private volatile boolean aclLoaded;

    public static void registerLogCallback(LogCallback logCallback) {
        Logger.registerLogCallback(logCallback);
        LOG.info("register snc log callback success");
    }

    public void init(SNCConfig config) {
        if (config != null && config.getLogCallback() != null) {
            Logger.registerLogCallback(config.getLogCallback());
            LOG.info("init: LogCallback registered");
        } else {
            LOG.warn("init: warning=No LogCallback provided, logs will be silent");
        }

        this.superNodeStore = new SuperNodeStore();
        this.aclStore = new AclStore();
        this.superNodeStore.init();
        this.aclStore.init();
        LOG.debug("init: SuperNodeStore and AclStore initialized");

        PathEngine pathEngine = new PathEngine();
        RouteLookupEngine routeLookupEngine = new RouteLookupEngine();
        AclCheckEngine aclCheckEngine = new AclCheckEngine();

        this.superNodeService = new SuperNodeService(superNodeStore);
        this.aclService = new AclService(aclStore);
        this.pathService = new PathService(superNodeStore, aclStore,
            pathEngine, routeLookupEngine, aclCheckEngine);
        this.linkEventService = new LinkEventService(superNodeStore);
        this.routeConvergeService = new RouteConvergeService();
        LOG.debug("init: Service instances created (SuperNodeService, AclService, PathService, "
            + "LinkEventService, RouteConvergeService)");

        this.superNodeLoaded = false;
        this.aclLoaded = false;
        this.state = State.READY;

        LOG.info("init: state=" + state);
    }

    public void uninit() {
        LOG.info("uninit: starting cleanup");
        if (superNodeStore != null) {
            superNodeStore.clear();
            LOG.debug("uninit: SuperNodeStore cleared");
        }
        if (aclStore != null) {
            aclStore.clear();
            LOG.debug("uninit: AclStore cleared");
        }
        this.superNodeLoaded = false;
        this.aclLoaded = false;
        this.state = State.UNINIT;
        this.superNodeStore = null;
        this.aclStore = null;
        this.superNodeService = null;
        this.aclService = null;
        this.pathService = null;
        this.linkEventService = null;
        this.routeConvergeService = null;
        LOG.info("uninit: state=" + state);
    }

    public void setSuperNode(SuperNode superNode) {
        checkNotUninit();
        if (superNode == null) {
            LOG.error("setSuperNode: error=SuperNode must not be null");
            throw new IllegalArgumentException("SuperNode must not be null");
        }
        superNodeService.importSuperNode(superNode);
        superNodeLoaded = true;
        updateDataReadyState();
        LOG.info("setSuperNode: superNode=" + superNode.getName() + ", state=" + state);
    }

    public void addNpuDevices(String superNodeName, List<NpuDevice> devices) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addNpuDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            LOG.error("addNpuDevices: error=devices must not be null");
            throw new IllegalArgumentException("devices must not be null");
        }
        superNodeService.addNpuDevices(superNodeName, devices);
        LOG.info("addNpuDevices: superNode=" + superNodeName + ", count=" + devices.size());
    }

    public void addSwDevices(String superNodeName, List<SwDevice> devices) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addSwDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            LOG.error("addSwDevices: error=devices must not be null");
            throw new IllegalArgumentException("devices must not be null");
        }
        superNodeService.addSwDevices(superNodeName, devices);
        LOG.info("addSwDevices: superNode=" + superNodeName + ", count=" + devices.size());
    }

    public void removeDevices(String superNodeName, List<String> deviceNames) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceNames == null) {
            LOG.error("removeDevices: error=deviceNames must not be null");
            throw new IllegalArgumentException("deviceNames must not be null");
        }
        superNodeService.removeDevices(superNodeName, deviceNames);
        LOG.info("removeDevices: superNode=" + superNodeName + ", count=" + deviceNames.size());
    }

    public void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                  List<RoutingEntry> entries) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addRoutingEntries: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceName == null || deviceName.isEmpty()) {
            LOG.error("addRoutingEntries: error=deviceName must not be null or empty");
            throw new IllegalArgumentException("deviceName must not be null or empty");
        }
        if (chipIndex == null) {
            LOG.error("addRoutingEntries: error=chipIndex must not be null");
            throw new IllegalArgumentException("chipIndex must not be null");
        }
        if (entries == null) {
            LOG.error("addRoutingEntries: error=entries must not be null");
            throw new IllegalArgumentException("entries must not be null");
        }
        superNodeService.addRoutingEntries(superNodeName, deviceName, chipIndex, entries);
        LOG.info("addRoutingEntries: superNode=" + superNodeName + ", device=" + deviceName
            + ", chip=" + chipIndex + ", count=" + entries.size());
    }

    public void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                     List<RoutePrefix> prefixes) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeRoutingEntries: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceName == null || deviceName.isEmpty()) {
            LOG.error("removeRoutingEntries: error=deviceName must not be null or empty");
            throw new IllegalArgumentException("deviceName must not be null or empty");
        }
        if (chipIndex == null) {
            LOG.error("removeRoutingEntries: error=chipIndex must not be null");
            throw new IllegalArgumentException("chipIndex must not be null");
        }
        if (prefixes == null) {
            LOG.error("removeRoutingEntries: error=prefixes must not be null");
            throw new IllegalArgumentException("prefixes must not be null");
        }
        superNodeService.removeRoutingEntries(superNodeName, deviceName, chipIndex, prefixes);
        LOG.info("removeRoutingEntries: superNode=" + superNodeName + ", device=" + deviceName
            + ", chip=" + chipIndex + ", count=" + prefixes.size());
    }

    public void setAclData(AclData aclData) {
        checkNotUninit();
        if (aclData == null) {
            LOG.error("setAclData: error=AclData must not be null");
            throw new IllegalArgumentException("AclData must not be null");
        }
        aclService.importAclData(aclData);
        aclLoaded = true;
        updateDataReadyState();
        LOG.info("setAclData: superNode=" + aclData.getSuperNodeName() + ", state=" + state);
    }

    public void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addAclRules: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (rules == null) {
            LOG.error("addAclRules: error=rules must not be null");
            throw new IllegalArgumentException("rules must not be null");
        }
        aclService.addAclRules(superNodeName, rules);
        LOG.info("addAclRules: superNode=" + superNodeName + ", count=" + rules.size());
    }

    public void removeAclRules(String superNodeName, List<AclKey> keys) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeAclRules: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (keys == null) {
            LOG.error("removeAclRules: error=keys must not be null");
            throw new IllegalArgumentException("keys must not be null");
        }
        aclService.removeAclRules(superNodeName, keys);
        LOG.info("removeAclRules: superNode=" + superNodeName + ", count=" + keys.size());
    }

    public SuperNode getSuperNode(String name) {
        checkNotUninit();
        if (name == null || name.isEmpty()) {
            LOG.error("getSuperNode: error=name must not be null or empty");
            throw new IllegalArgumentException("name must not be null or empty");
        }
        SuperNode result = superNodeService.getSuperNode(name);
        LOG.info("getSuperNode: name=" + name + ", result=" + (result != null ? "found" : "null"));
        return result;
    }

    public void removeSuperNode(String name) {
        checkNotUninit();
        if (name == null || name.isEmpty()) {
            LOG.error("removeSuperNode: error=name must not be null or empty");
            throw new IllegalArgumentException("name must not be null or empty");
        }
        superNodeService.removeSuperNode(name);
        superNodeLoaded = superNodeService.getSuperNode(name) != null;
        updateDataReadyState();
        LOG.info("removeSuperNode: name=" + name + ", state=" + state);
    }

    public AclData getAclData(String superNodeName) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("getAclData: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        AclData result = aclService.getAclData(superNodeName);
        LOG.info("getAclData: superNode=" + superNodeName + ", result=" + (result != null ? "found" : "null"));
        return result;
    }

    public void removeAclData(String superNodeName) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeAclData: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        aclService.removeAclData(superNodeName);
        aclLoaded = aclService.getAclData(superNodeName) != null;
        updateDataReadyState();
        LOG.info("removeAclData: superNode=" + superNodeName + ", state=" + state);
    }

    public PathPlanResult planPath(PathPlanRequest request) {
        if (state != State.DATAREADY) {
            LOG.error("planPath: error=SNC is not in DATAREADY state, state=" + state);
            throw new SNCStateException("SNC is not in DATAREADY state, current state: " + state);
        }
        if (request == null) {
            LOG.error("planPath: error=PathPlanRequest must not be null");
            throw new IllegalArgumentException("PathPlanRequest must not be null");
        }
        if (request.getSuperNodeName() == null || request.getSuperNodeName().isEmpty()) {
            LOG.error("planPath: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (request.getSrcDevice() == null || request.getSrcDevice().isEmpty()) {
            LOG.error("planPath: error=srcDevice must not be null or empty");
            throw new IllegalArgumentException("srcDevice must not be null or empty");
        }
        if (request.getDestDevice() == null || request.getDestDevice().isEmpty()) {
            LOG.error("planPath: error=destDevice must not be null or empty");
            throw new IllegalArgumentException("destDevice must not be null or empty");
        }
        if (request.getSrcPort() == null || request.getSrcPort().isEmpty()) {
            LOG.error("planPath: error=srcPort must not be null or empty");
            throw new IllegalArgumentException("srcPort must not be null or empty");
        }
        if (request.getDestPort() == null || request.getDestPort().isEmpty()) {
            LOG.error("planPath: error=destPort must not be null or empty");
            throw new IllegalArgumentException("destPort must not be null or empty");
        }
        PathPlanResult result = pathService.planPath(request);
        LOG.info("planPath: src=" + request.getSrcDevice() + ", dst=" + request.getDestDevice()
            + ", status=" + result.getStatus());
        return result;
    }

    public void notifyLinkEvent(SuperNode supernode, LinkEvent event) {
        checkNotUninit();
        if (supernode == null) {
            LOG.error("notifyLinkEvent: error=supernode must not be null");
            throw new IllegalArgumentException("supernode must not be null");
        }
        if (event == null) {
            LOG.error("notifyLinkEvent: error=event must not be null");
            throw new IllegalArgumentException("event must not be null");
        }
        linkEventService.notifyLinkEvent(supernode, event);
        LOG.info("notifyLinkEvent: superNode=" + supernode.getName() + ", device=" + event.getDeviceName()
            + ", port=" + event.getPortName() + ", status=" + event.getEventType());
        // 路由收敛：基于 link 事件按 BFS 在互联转发节点间传播收敛状态
        routeConvergeService.converge(instantiationRouteMap, supernode, event);
    }

    private void checkNotUninit() {
        if (state == State.INIT || state == State.UNINIT) {
            LOG.error("checkNotUninit: error=SNC is in " + state + " state");
            throw new SNCStateException("SNC is in " + state + " state");
        }
    }

    private void updateDataReadyState() {
        if (superNodeLoaded && aclLoaded) {
            this.state = State.DATAREADY;
            LOG.info("state=" + state);
        } else if (state == State.DATAREADY) {
            this.state = State.READY;
            LOG.info("state=" + state);
        }
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
            LOG.info("calculate default route template success");

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
            LOG.info("route has calculated");
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
            LOG.info("find %d npu devices", superNode.getNpuDevices().size());
            for (NpuDevice npuDevice : superNode.getNpuDevices().values()) {
                service.makeNpuRoutes(npuDevice, routes, tempRouteMap);
            }
        }

        if (superNode.getSwDevices() != null) {
            LOG.info("find %d sw devices", superNode.getSwDevices().size());
            for (SwDevice swDevice : superNode.getSwDevices().values()) {
                service.makeSwRoutes(swDevice, routes, tempRouteMap);
            }
        }

        Map<String, Map<String, RoutingEntry>> copyRoutingEntry =
            RouteInstantiationService.deepCopyRoutingEntry(tempRouteMap);
        this.instantiationRouteMap.putAll(copyRoutingEntry);

        LOG.info("make routes success for %s, total %d entries", superNode.getName(), tempRouteMap.size());
        return tempRouteMap;
    }

    public Map<String, RoutingEntry> getNodeRoute(String deviceName, int chipIndex) {
        if (deviceName == null) {
            throw new IllegalArgumentException("device info is null");
        }

        String key = RouteInstantiationService.buildRouteTableKey(deviceName, chipIndex);
        Map<String, RoutingEntry> routingEntries = instantiationRouteMap.get(key);
        if (routingEntries == null) {
            throw new IllegalArgumentException("not found route for " + key);
        }

        return routingEntries;
    }
}
