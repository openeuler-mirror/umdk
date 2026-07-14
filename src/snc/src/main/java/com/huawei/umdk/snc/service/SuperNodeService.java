/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.service;

import java.util.List;

import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.store.SuperNodeStore;

public class SuperNodeService {

    private final SuperNodeStore store;

    public SuperNodeService(SuperNodeStore store) {
        this.store = store;
    }

    public void importSuperNode(SuperNode superNode) {
        if (superNode == null) {
            throw new IllegalArgumentException("SuperNode must not be null");
        }
        if (superNode.getName() == null || superNode.getName().isEmpty()) {
            throw new IllegalArgumentException("SuperNode name must not be null or empty");
        }
        if ((superNode.getNpuDevices() == null || superNode.getNpuDevices().isEmpty())
            && (superNode.getSwDevices() == null || superNode.getSwDevices().isEmpty())) {
            throw new IllegalArgumentException("SuperNode devices must not be null or empty");
        }
        store.replace(superNode);
    }

    public void addNpuDevices(String superNodeName, List<NpuDevice> devices) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            throw new IllegalArgumentException("devices must not be null");
        }
        for (NpuDevice device : devices) {
            if (device == null) {
                throw new IllegalArgumentException("device in list must not be null");
            }
            store.addNpuDevice(superNodeName, device);
        }
    }

    public void addSwDevices(String superNodeName, List<SwDevice> devices) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (devices == null) {
            throw new IllegalArgumentException("devices must not be null");
        }
        for (SwDevice device : devices) {
            if (device == null) {
                throw new IllegalArgumentException("device in list must not be null");
            }
            store.addSwDevice(superNodeName, device);
        }
    }

    public void removeDevices(String superNodeName, List<String> deviceNames) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (deviceNames == null) {
            throw new IllegalArgumentException("deviceNames must not be null");
        }
        for (String deviceName : deviceNames) {
            if (deviceName == null || deviceName.isEmpty()) {
                throw new IllegalArgumentException("deviceName in list must not be null or empty");
            }
            store.removeDevice(superNodeName, deviceName);
        }
    }

    public void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                  List<RoutingEntry> entries) {
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
        for (RoutingEntry entry : entries) {
            if (entry == null || entry.getPrefix() == null) {
                throw new IllegalArgumentException("entry or entry.prefix in list must not be null");
            }
            store.addRoutingEntry(superNodeName, deviceName, chipIndex, entry.getPrefix(), entry);
        }
    }

    public void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                                     List<RoutePrefix> prefixes) {
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
        for (RoutePrefix prefix : prefixes) {
            if (prefix == null) {
                throw new IllegalArgumentException("prefix in list must not be null");
            }
            store.removeRoutingEntry(superNodeName, deviceName, chipIndex, prefix);
        }
    }

    public SuperNode getSuperNode(String name) {
        return store.getSuperNode(name);
    }

    public void removeSuperNode(String name) {
        store.removeSuperNode(name);
    }
}
