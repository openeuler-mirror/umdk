/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.DeviceEntity;
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
        if (superNode.getAllDevices() == null || superNode.getAllDevices().isEmpty()) {
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

        List<NpuDevice> addedDevices = new ArrayList<>();
        Map<String, NpuDevice> previousDevices = new HashMap<>();
        try {
            for (NpuDevice device : devices) {
                if (device == null) {
                    throw new IllegalArgumentException("device in list must not be null");
                }
                SuperNode sn = store.getSuperNode(superNodeName);
                NpuDevice previous = (sn != null && sn.getNpuDevices() != null)
                    ? sn.getNpuDevices().get(device.getDeviceName()) : null;
                previousDevices.put(device.getDeviceName(), previous);
                LOG.debug("addNpuDevices: device=%s, superNode=%s", device.getDeviceName(), superNodeName);
                store.addNpuDevice(superNodeName, device);
                addedDevices.add(device);
            }
        } catch (RuntimeException e) {
            rollbackNpuDevices(superNodeName, addedDevices, previousDevices, e);
            throw e;
        }
    }

    private void rollbackNpuDevices(String superNodeName, List<NpuDevice> addedDevices,
                                     Map<String, NpuDevice> previousDevices, RuntimeException cause) {
        if (addedDevices.isEmpty()) {
            return;
        }
        LOG.error("addNpuDevices: rollback superNode=%s, addedCount=%d, cause=%s",
            superNodeName, addedDevices.size(), cause.getMessage());
        for (int i = addedDevices.size() - 1; i >= 0; i--) {
            NpuDevice device = addedDevices.get(i);
            String deviceName = device.getDeviceName();
            NpuDevice previous = previousDevices.get(deviceName);
            try {
                if (previous != null) {
                    store.addNpuDevice(superNodeName, previous);
                } else {
                    store.removeDevice(superNodeName, deviceName);
                }
            } catch (RuntimeException re) {
                LOG.error("addNpuDevices: rollback failed for device=%s, superNode=%s, error=%s",
                    deviceName, superNodeName, re.getMessage());
            }
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

        List<SwDevice> addedDevices = new ArrayList<>();
        Map<String, SwDevice> previousDevices = new HashMap<>();
        try {
            for (SwDevice device : devices) {
                if (device == null) {
                    throw new IllegalArgumentException("device in list must not be null");
                }
                SuperNode sn = store.getSuperNode(superNodeName);
                SwDevice previous = (sn != null && sn.getSwDevices() != null)
                    ? sn.getSwDevices().get(device.getDeviceName()) : null;
                previousDevices.put(device.getDeviceName(), previous);
                LOG.debug("addSwDevices: device=%s, superNode=%s", device.getDeviceName(), superNodeName);
                store.addSwDevice(superNodeName, device);
                addedDevices.add(device);
            }
        } catch (RuntimeException e) {
            rollbackSwDevices(superNodeName, addedDevices, previousDevices, e);
            throw e;
        }
    }

    private void rollbackSwDevices(String superNodeName, List<SwDevice> addedDevices,
                                    Map<String, SwDevice> previousDevices, RuntimeException cause) {
        if (addedDevices.isEmpty()) {
            return;
        }
        LOG.error("addSwDevices: rollback superNode=%s, addedCount=%d, cause=%s",
            superNodeName, addedDevices.size(), cause.getMessage());
        for (int i = addedDevices.size() - 1; i >= 0; i--) {
            SwDevice device = addedDevices.get(i);
            String deviceName = device.getDeviceName();
            SwDevice previous = previousDevices.get(deviceName);
            try {
                if (previous != null) {
                    store.addSwDevice(superNodeName, previous);
                } else {
                    store.removeDevice(superNodeName, deviceName);
                }
            } catch (RuntimeException re) {
                LOG.error("addSwDevices: rollback failed for device=%s, superNode=%s, error=%s",
                    deviceName, superNodeName, re.getMessage());
            }
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
