/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.store;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutingTableKey;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;

public class SuperNodeStore {

    private static final Logger LOG = new Logger(SuperNodeStore.class);

    private Map<String, SuperNode> superNodeMap;
    private Map<RoutingTableKey, RoutingTable> routingTableMap;

    public void init() {
        this.superNodeMap = new ConcurrentHashMap<>();
        this.routingTableMap = new ConcurrentHashMap<>();
        LOG.info("init: SuperNodeStore initialized");
    }

    public void replace(SuperNode superNode) {
        String name = superNode.getName();
        LOG.info("replace: superNode=" + name);
        superNodeMap.put(name, superNode);

        routingTableMap.entrySet().removeIf(e -> e.getKey().getSuperNodeName().equals(name));

        int deviceCount = 0;
        for (DeviceEntity device : superNode.getMutableAllDevices().values()) {
            indexRoutingTable(name, device);
            deviceCount++;
        }
        LOG.debug("replace: deviceCount=" + deviceCount + ", superNode=" + name);
    }

    private void indexRoutingTable(String superNodeName, DeviceEntity device) {
        if (device.getForwardingChips() != null) {
            for (ForwardingChip chip : device.getForwardingChips().values()) {
                if (chip.getRoutingTable() != null) {
                    RoutingTable rt = chip.getRoutingTable();
                    if (rt.getRoutes() != null) {
                        updateMaskLengths(rt);
                    }
                    RoutingTableKey key = new RoutingTableKey(
                        superNodeName, device.getDeviceName(), chip.getChipIndex());
                    routingTableMap.put(key, rt);
                    LOG.debug("indexRoutingTable: superNode=" + superNodeName
                        + ", device=" + device.getDeviceName()
                        + ", chip=" + chip.getChipIndex()
                        + ", routes=" + (rt.getRoutes() != null ? rt.getRoutes().size() : 0));
                }
            }
        }
    }

    public void clear() {
        if (superNodeMap != null) {
            superNodeMap.clear();
        }
        if (routingTableMap != null) {
            routingTableMap.clear();
        }
        LOG.info("clear: SuperNodeStore cleared");
    }

    public void removeSuperNode(String superNodeName) {
        LOG.info("removeSuperNode: superNode=" + superNodeName);
        if (superNodeMap != null) {
            superNodeMap.remove(superNodeName);
        }
        if (routingTableMap != null) {
            routingTableMap.entrySet().removeIf(e -> e.getKey().getSuperNodeName().equals(superNodeName));
        }
    }

    public SuperNode getSuperNode(String name) {
        return superNodeMap.get(name);
    }

    public RoutingTable getRoutingTable(RoutingTableKey key) {
        return routingTableMap.get(key);
    }

    public void addNpuDevice(String superNodeName, NpuDevice device) {
        SuperNode superNode = superNodeMap.get(superNodeName);
        if (superNode == null) {
            LOG.error("addNpuDevice: superNode=" + superNodeName + ", error=SuperNode not found, hint=Call setSuperNode() first");
            throw new IllegalStateException(
                "SuperNode not found: " + superNodeName + ". Call setSuperNode() first.");
        }
        LOG.info("addNpuDevice: superNode=" + superNodeName + ", device=" + device.getDeviceName());
        if (superNode.getMutableNpuDevices() == null) {
            superNode.setNpuDevices(new ConcurrentHashMap<>());
        }
        superNode.getMutableNpuDevices().put(device.getDeviceName(), device);
        indexRoutingTable(superNodeName, device);
    }

    public void addSwDevice(String superNodeName, SwDevice device) {
        SuperNode superNode = superNodeMap.get(superNodeName);
        if (superNode == null) {
            LOG.error("addSwDevice: superNode=" + superNodeName + ", error=SuperNode not found, hint=Call setSuperNode() first");
            throw new IllegalStateException(
                "SuperNode not found: " + superNodeName + ". Call setSuperNode() first.");
        }
        LOG.info("addSwDevice: superNode=" + superNodeName + ", device=" + device.getDeviceName());
        if (superNode.getMutableSwDevices() == null) {
            superNode.setSwDevices(new ConcurrentHashMap<>());
        }
        superNode.getMutableSwDevices().put(device.getDeviceName(), device);
        indexRoutingTable(superNodeName, device);
    }

    public void removeDevice(String superNodeName, String deviceName) {
        LOG.info("removeDevice: superNode=" + superNodeName + ", device=" + deviceName);
        if (superNodeMap != null) {
            SuperNode superNode = superNodeMap.get(superNodeName);
            if (superNode != null) {
                if (superNode.getMutableNpuDevices() != null) {
                    superNode.getMutableNpuDevices().remove(deviceName);
                }
                if (superNode.getMutableSwDevices() != null) {
                    superNode.getMutableSwDevices().remove(deviceName);
                }
            } else {
                LOG.warn("removeDevice: superNode=" + superNodeName + ", warning=SuperNode not found, action=skip device removal");
            }
        }
        if (routingTableMap != null) {
            routingTableMap.entrySet().removeIf(e ->
                e.getKey().getSuperNodeName().equals(superNodeName)
                    && e.getKey().getDeviceName().equals(deviceName));
        }
    }

    public void addRoutingEntry(String superNodeName, String deviceName, Integer chipIndex,
                                 RoutePrefix prefix, RoutingEntry entry) {
        RoutingTableKey key = new RoutingTableKey(superNodeName, deviceName, chipIndex);
        RoutingTable rt = routingTableMap.get(key);
        if (rt == null) {
            LOG.error("addRoutingEntry: superNode=" + superNodeName + ", device=" + deviceName
                + ", chip=" + chipIndex + ", error=RoutingTable not found"
                + ", hint=Call setSuperNode() or addNpuDevices()/addSwDevices() first");
            throw new IllegalStateException(
                "RoutingTable not found for " + superNodeName + "/" + deviceName + "/" + chipIndex
                    + ". Call setSuperNode() or addNpuDevices()/addSwDevices() first.");
        }
        if (rt.getRoutes() == null) {
            LOG.error("addRoutingEntry: superNode=" + superNodeName + ", device=" + deviceName
                + ", chip=" + chipIndex + ", error=RoutingTable routes is null");
            throw new IllegalStateException(
                "RoutingTable routes is null for " + superNodeName + "/" + deviceName + "/" + chipIndex);
        }
        LOG.info("addRoutingEntry: superNode=" + superNodeName + ", device=" + deviceName
            + ", chip=" + chipIndex + ", prefix=" + prefix);
        Map<RoutePrefix, RoutingEntry> mutableRoutes = new java.util.HashMap<>(rt.getRoutes());
        mutableRoutes.put(prefix, entry);
        rt.setRoutes(mutableRoutes);
        updateMaskLengths(rt);
    }

    public void removeRoutingEntry(String superNodeName, String deviceName, Integer chipIndex,
                                   RoutePrefix prefix) {
        LOG.info("removeRoutingEntry: superNode=" + superNodeName + ", device=" + deviceName
            + ", chip=" + chipIndex + ", prefix=" + prefix);
        RoutingTableKey key = new RoutingTableKey(superNodeName, deviceName, chipIndex);
        RoutingTable rt = routingTableMap.get(key);
        if (rt != null && rt.getRoutes() != null) {
            Map<RoutePrefix, RoutingEntry> mutableRoutes = new java.util.HashMap<>(rt.getRoutes());
            mutableRoutes.remove(prefix);
            rt.setRoutes(mutableRoutes);
            updateMaskLengths(rt);
        } else {
            LOG.warn("removeRoutingEntry: superNode=" + superNodeName + ", device=" + deviceName
                + ", chip=" + chipIndex + ", warning=RoutingTable not found or routes is null");
        }
    }

    private void updateMaskLengths(RoutingTable rt) {
        List<Integer> masks = rt.getRoutes().keySet().stream()
            .map(RoutePrefix::getMaskLength)
            .sorted(Comparator.reverseOrder())
            .collect(Collectors.toList());
        rt.setMaskLengths(masks);
    }
}
