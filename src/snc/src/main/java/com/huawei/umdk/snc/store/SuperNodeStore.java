/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.store;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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

    private Map<String, SuperNode> superNodeMap;
    private Map<RoutingTableKey, RoutingTable> routingTableMap;

    public void init() {
        this.superNodeMap = new ConcurrentHashMap<>();
        this.routingTableMap = new ConcurrentHashMap<>();
    }

    public void replace(SuperNode superNode) {
        String name = superNode.getName();
        superNodeMap.put(name, superNode);

        routingTableMap.entrySet().removeIf(e -> e.getKey().getSuperNodeName().equals(name));

        for (DeviceEntity device : superNode.getMutableAllDevices().values()) {
            indexRoutingTable(name, device);
        }
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
    }

    public void removeSuperNode(String superNodeName) {
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
            throw new IllegalStateException(
                "SuperNode not found: " + superNodeName + ". Call setSuperNode() first.");
        }
        if (superNode.getMutableNpuDevices() == null) {
            superNode.setNpuDevices(new ConcurrentHashMap<>());
        }
        superNode.getMutableNpuDevices().put(device.getDeviceName(), device);
        indexRoutingTable(superNodeName, device);
    }

    public void addSwDevice(String superNodeName, SwDevice device) {
        SuperNode superNode = superNodeMap.get(superNodeName);
        if (superNode == null) {
            throw new IllegalStateException(
                "SuperNode not found: " + superNodeName + ". Call setSuperNode() first.");
        }
        if (superNode.getMutableSwDevices() == null) {
            superNode.setSwDevices(new ConcurrentHashMap<>());
        }
        superNode.getMutableSwDevices().put(device.getDeviceName(), device);
        indexRoutingTable(superNodeName, device);
    }

    public void removeDevice(String superNodeName, String deviceName) {
        if (superNodeMap != null) {
            SuperNode superNode = superNodeMap.get(superNodeName);
            if (superNode != null) {
                if (superNode.getMutableNpuDevices() != null) {
                    superNode.getMutableNpuDevices().remove(deviceName);
                }
                if (superNode.getMutableSwDevices() != null) {
                    superNode.getMutableSwDevices().remove(deviceName);
                }
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
            throw new IllegalStateException(
                "RoutingTable not found for " + superNodeName + "/" + deviceName + "/" + chipIndex
                    + ". Call setSuperNode() or addNpuDevices()/addSwDevices() first.");
        }
        if (rt.getRoutes() == null) {
            throw new IllegalStateException(
                "RoutingTable routes is null for " + superNodeName + "/" + deviceName + "/" + chipIndex);
        }
        Map<RoutePrefix, RoutingEntry> mutableRoutes = new java.util.HashMap<>(rt.getRoutes());
        mutableRoutes.put(prefix, entry);
        rt.setRoutes(mutableRoutes);
        updateMaskLengths(rt);
    }

    public void removeRoutingEntry(String superNodeName, String deviceName, Integer chipIndex,
                                   RoutePrefix prefix) {
        RoutingTableKey key = new RoutingTableKey(superNodeName, deviceName, chipIndex);
        RoutingTable rt = routingTableMap.get(key);
        if (rt != null && rt.getRoutes() != null) {
            Map<RoutePrefix, RoutingEntry> mutableRoutes = new java.util.HashMap<>(rt.getRoutes());
            mutableRoutes.remove(prefix);
            rt.setRoutes(mutableRoutes);
            updateMaskLengths(rt);
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
