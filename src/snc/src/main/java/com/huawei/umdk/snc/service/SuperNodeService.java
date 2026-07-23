/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.service;

import java.util.List;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.store.SuperNodeStore;

public class SuperNodeService {

    private static final Logger LOG = new Logger(SuperNodeService.class);

    private final SuperNodeStore store;

    public SuperNodeService(SuperNodeStore store) {
        this.store = store;
    }

    public void importSuperNode(SuperNode superNode) {
        if (superNode == null) {
            LOG.error("importSuperNode: error=SuperNode must not be null");
            throw new IllegalArgumentException("SuperNode must not be null");
        }
        if (superNode.getName() == null || superNode.getName().isEmpty()) {
            LOG.error("importSuperNode: error=SuperNode name must not be null or empty");
            throw new IllegalArgumentException("SuperNode name must not be null or empty");
        }
        if ((superNode.getNpuDevices() == null || superNode.getNpuDevices().isEmpty())
            && (superNode.getSwDevices() == null || superNode.getSwDevices().isEmpty())) {
            LOG.error("importSuperNode: error=SuperNode devices must not be null or empty, name=%s", superNode.getName());
            throw new IllegalArgumentException("SuperNode devices must not be null or empty");
        }
        LOG.info("importSuperNode: name=%s, npuDevices=%d, swDevices=%d",
            superNode.getName(),
            superNode.getNpuDevices() != null ? superNode.getNpuDevices().size() : 0,
            superNode.getSwDevices() != null ? superNode.getSwDevices().size() : 0);
        store.replace(superNode);
    }

    public void addNpuDevices(String superNodeName, List<NpuDevice> devices) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addNpuDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            LOG.error("addNpuDevices: error=devices must not be null");
            throw new IllegalArgumentException("devices must not be null");
        }
        LOG.info("addNpuDevices: superNode=%s, count=%d", superNodeName, devices.size());
        for (NpuDevice device : devices) {
            if (device == null) {
                LOG.error("addNpuDevices: error=device in list must not be null");
                throw new IllegalArgumentException("device in list must not be null");
            }
        }
        for (NpuDevice device : devices) {
            LOG.debug("addNpuDevices: device=%s, superNode=%s", device.getDeviceName(), superNodeName);
            store.addNpuDevice(superNodeName, device);
        }
    }

    public void addSwDevices(String superNodeName, List<SwDevice> devices) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addSwDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            LOG.error("addSwDevices: error=devices must not be null");
            throw new IllegalArgumentException("devices must not be null");
        }
        LOG.info("addSwDevices: superNode=%s, count=%d", superNodeName, devices.size());
        for (SwDevice device : devices) {
            if (device == null) {
                LOG.error("addSwDevices: error=device in list must not be null");
                throw new IllegalArgumentException("device in list must not be null");
            }
        }
        for (SwDevice device : devices) {
            LOG.debug("addSwDevices: device=%s, superNode=%s", device.getDeviceName(), superNodeName);
            store.addSwDevice(superNodeName, device);
        }
    }

    public void removeDevices(String superNodeName, List<String> deviceNames) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeDevices: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceNames == null) {
            LOG.error("removeDevices: error=deviceNames must not be null");
            throw new IllegalArgumentException("deviceNames must not be null");
        }
        LOG.info("removeDevices: superNode=%s, count=%d", superNodeName, deviceNames.size());
        for (String deviceName : deviceNames) {
            if (deviceName == null || deviceName.isEmpty()) {
                LOG.error("removeDevices: error=deviceName in list must not be null or empty");
                throw new IllegalArgumentException("deviceName in list must not be null or empty");
            }
        }
        for (String deviceName : deviceNames) {
            LOG.debug("removeDevices: device=%s, superNode=%s", deviceName, superNodeName);
            store.removeDevice(superNodeName, deviceName);
        }
    }

    public void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                  List<RoutingEntry> entries) {
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
        LOG.info("addRoutingEntries: superNode=%s, device=%s, chip=%d, count=%d",
            superNodeName, deviceName, chipIndex, entries.size());
        for (RoutingEntry entry : entries) {
            if (entry == null || entry.getPrefix() == null) {
                LOG.error("addRoutingEntries: error=entry or entry.prefix in list must not be null");
                throw new IllegalArgumentException("entry or entry.prefix in list must not be null");
            }
        }
        for (RoutingEntry entry : entries) {
            LOG.debug("addRoutingEntries: prefix=%s, superNode=%s, device=%s, chip=%d",
                entry.getPrefix(), superNodeName, deviceName, chipIndex);
            store.addRoutingEntry(superNodeName, deviceName, chipIndex, entry.getPrefix(), entry);
        }
    }

    public void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                     List<RoutePrefix> prefixes) {
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
        LOG.info("removeRoutingEntries: superNode=%s, device=%s, chip=%d, count=%d",
            superNodeName, deviceName, chipIndex, prefixes.size());
        for (RoutePrefix prefix : prefixes) {
            if (prefix == null) {
                LOG.error("removeRoutingEntries: error=prefix in list must not be null");
                throw new IllegalArgumentException("prefix in list must not be null");
            }
        }
        for (RoutePrefix prefix : prefixes) {
            LOG.debug("removeRoutingEntries: prefix=%s, superNode=%s, device=%s, chip=%d",
                prefix, superNodeName, deviceName, chipIndex);
            store.removeRoutingEntry(superNodeName, deviceName, chipIndex, prefix);
        }
    }

    public SuperNode getSuperNode(String name) {
        LOG.debug("getSuperNode: name=%s", name);
        return store.getSuperNode(name);
    }

    public void removeSuperNode(String name) {
        LOG.info("removeSuperNode: name=%s", name);
        store.removeSuperNode(name);
    }
}