/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.engine.AclCheckEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.TpAclEntity;
import com.huawei.umdk.snc.exception.SNCStateException;
import com.huawei.umdk.snc.service.AclService;
import com.huawei.umdk.snc.service.PathService;
import com.huawei.umdk.snc.service.SuperNodeService;
import com.huawei.umdk.snc.store.AclStore;
import com.huawei.umdk.snc.store.SuperNodeStore;

public class SNCServiceImpl implements SNCService {

    private static final Logger LOG = Logger.getLogger(SNCServiceImpl.class.getName());

    private enum State {
        INIT, READY, DATAREADY, UNINIT
    }

    private volatile State state = State.INIT;

    private SuperNodeStore superNodeStore;

    private AclStore aclStore;

    private SuperNodeService superNodeService;

    private AclService aclService;

    private PathService pathService;

    private volatile boolean superNodeLoaded;

    private volatile boolean aclLoaded;

    @Override
    public void init(SNCConfig config) {
        if (config != null && config.getLogLevel() != null) {
            LOG.setLevel(config.getLogLevel());
        }

        this.superNodeStore = new SuperNodeStore();
        this.aclStore = new AclStore();
        this.superNodeStore.init();
        this.aclStore.init();

        PathEngine pathEngine = new PathEngine();
        RouteLookupEngine routeLookupEngine = new RouteLookupEngine();
        AclCheckEngine aclCheckEngine = new AclCheckEngine();

        this.superNodeService = new SuperNodeService(superNodeStore);
        this.aclService = new AclService(aclStore);
        this.pathService = new PathService(superNodeStore, aclStore,
            pathEngine, routeLookupEngine, aclCheckEngine);

        this.superNodeLoaded = false;
        this.aclLoaded = false;
        this.state = State.READY;

        log("init: state -> READY");
    }

    @Override
    public void uninit() {
        if (superNodeStore != null) {
            superNodeStore.clear();
        }
        if (aclStore != null) {
            aclStore.clear();
        }
        this.superNodeLoaded = false;
        this.aclLoaded = false;
        this.state = State.UNINIT;
        this.superNodeStore = null;
        this.aclStore = null;
        this.superNodeService = null;
        this.aclService = null;
        this.pathService = null;
        log("uninit: state -> UNINIT");
    }

    @Override
    public void setSuperNode(SuperNode superNode) {
        checkNotUninit();
        if (superNode == null) {
            throw new IllegalArgumentException("SuperNode must not be null");
        }
        superNodeService.importSuperNode(superNode);
        superNodeLoaded = true;
        updateDataReadyState();
        log("setSuperNode: " + superNode.getName() + ", state -> " + state);
    }

    @Override
    public void addNpuDevices(String superNodeName, List<NpuDevice> devices) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            throw new IllegalArgumentException("devices must not be null");
        }
        superNodeService.addNpuDevices(superNodeName, devices);
        log("addNpuDevices: " + superNodeName + ", count=" + devices.size());
    }

    @Override
    public void addSwDevices(String superNodeName, List<SwDevice> devices) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            throw new IllegalArgumentException("devices must not be null");
        }
        superNodeService.addSwDevices(superNodeName, devices);
        log("addSwDevices: " + superNodeName + ", count=" + devices.size());
    }

    @Override
    public void removeDevices(String superNodeName, List<String> deviceNames) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceNames == null) {
            throw new IllegalArgumentException("deviceNames must not be null");
        }
        superNodeService.removeDevices(superNodeName, deviceNames);
        log("removeDevices: " + superNodeName + ", count=" + deviceNames.size());
    }

    @Override
    public void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                  List<RoutingEntry> entries) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceName == null || deviceName.isEmpty()) {
            throw new IllegalArgumentException("deviceName must not be null or empty");
        }
        if (chipIndex == null) {
            throw new IllegalArgumentException("chipIndex must not be null");
        }
        if (entries == null) {
            throw new IllegalArgumentException("entries must not be null");
        }
        superNodeService.addRoutingEntries(superNodeName, deviceName, chipIndex, entries);
        log("addRoutingEntries: " + superNodeName + "/" + deviceName + "/" + chipIndex
            + ", count=" + entries.size());
    }

    @Override
    public void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                     List<RoutePrefix> prefixes) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceName == null || deviceName.isEmpty()) {
            throw new IllegalArgumentException("deviceName must not be null or empty");
        }
        if (chipIndex == null) {
            throw new IllegalArgumentException("chipIndex must not be null");
        }
        if (prefixes == null) {
            throw new IllegalArgumentException("prefixes must not be null");
        }
        superNodeService.removeRoutingEntries(superNodeName, deviceName, chipIndex, prefixes);
        log("removeRoutingEntries: " + superNodeName + "/" + deviceName + "/" + chipIndex
            + ", count=" + prefixes.size());
    }

    @Override
    public void setAclData(AclData aclData) {
        checkNotUninit();
        if (aclData == null) {
            throw new IllegalArgumentException("AclData must not be null");
        }
        aclService.importAclData(aclData);
        aclLoaded = true;
        updateDataReadyState();
        log("setAclData: " + aclData.getSuperNodeName() + ", state -> " + state);
    }

    @Override
    public void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (rules == null) {
            throw new IllegalArgumentException("rules must not be null");
        }
        aclService.addAclRules(superNodeName, rules);
        log("addAclRules: " + superNodeName + ", count=" + rules.size());
    }

    @Override
    public void removeAclRules(String superNodeName, List<AclKey> keys) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (keys == null) {
            throw new IllegalArgumentException("keys must not be null");
        }
        aclService.removeAclRules(superNodeName, keys);
        log("removeAclRules: " + superNodeName + ", count=" + keys.size());
    }

    @Override
    public SuperNode getSuperNode(String name) {
        checkNotUninit();
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }
        SuperNode result = superNodeService.getSuperNode(name);
        log("getSuperNode: " + name + " -> " + (result != null ? "found" : "null"));
        return result;
    }

    @Override
    public void removeSuperNode(String name) {
        checkNotUninit();
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }
        superNodeService.removeSuperNode(name);
        superNodeLoaded = superNodeService.getSuperNode(name) != null;
        updateDataReadyState();
        log("removeSuperNode: " + name + ", state -> " + state);
    }

    @Override
    public AclData getAclData(String superNodeName) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        AclData result = aclService.getAclData(superNodeName);
        log("getAclData: " + superNodeName + " -> " + (result != null ? "found" : "null"));
        return result;
    }

    @Override
    public void removeAclData(String superNodeName) {
        checkNotUninit();
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        aclService.removeAclData(superNodeName);
        aclLoaded = aclService.getAclData(superNodeName) != null;
        updateDataReadyState();
        log("removeAclData: " + superNodeName + ", state -> " + state);
    }

    @Override
    public PathPlanResult planPath(PathPlanRequest request) {
        if (state != State.DATAREADY) {
            throw new SNCStateException("SNC is not in DATAREADY state, current state: " + state);
        }
        if (request == null) {
            throw new IllegalArgumentException("PathPlanRequest must not be null");
        }
        if (request.getSuperNodeName() == null || request.getSuperNodeName().isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (request.getSrcDevice() == null || request.getSrcDevice().isEmpty()) {
            throw new IllegalArgumentException("srcDevice must not be null or empty");
        }
        if (request.getDestDevice() == null || request.getDestDevice().isEmpty()) {
            throw new IllegalArgumentException("destDevice must not be null or empty");
        }
        if (request.getSrcPort() == null || request.getSrcPort().isEmpty()) {
            throw new IllegalArgumentException("srcPort must not be null or empty");
        }
        if (request.getDestPort() == null || request.getDestPort().isEmpty()) {
            throw new IllegalArgumentException("destPort must not be null or empty");
        }
        PathPlanResult result = pathService.planPath(request);
        log("planPath: " + request.getSrcDevice() + " -> " + request.getDestDevice()
            + " status=" + result.getStatus());
        return result;
    }

    private void checkNotUninit() {
        if (state == State.INIT || state == State.UNINIT) {
            throw new SNCStateException("SNC is in " + state + " state");
        }
    }

    private void updateDataReadyState() {
        if (superNodeLoaded && aclLoaded) {
            this.state = State.DATAREADY;
            log("state -> DATAREADY");
        } else if (state == State.DATAREADY) {
            this.state = State.READY;
            log("state -> READY");
        }
    }

    private void log(String msg) {
        LOG.info(msg);
    }
}
