/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage route augmentor
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwitchLevel;

/**
 * Augments L1SW / L2SW routing tables with ECMP default routes and cross-chassis
 * /32 routes so that {@link com.huawei.umdk.snc.engine.CoveragePlanEngine} can
 * trace forward/reverse paths through the L2SW spine for every NPU pair.
 *
 * <p>The raw topology JSON (from {@link FullRackTopologyGenerator}) only has
 * /32 routes whose outPorts are the single NPU-facing port for same-chassis
 * destinations. This is insufficient for coverage mode, which requires every
 * cross-chassis path to go NPU → L1SW → L2SW → L1SW → NPU (always traversing
 * the L2 spine, even for same-chassis pairs).
 *
 * <p>After augmentation:
 * <ul>
 *   <li>L1SW: 0.0.0.0/0 default route with ALL 64 L2-facing ports as ECMP;
 *       same-chassis NPU CNAs keep their single NPU-facing /32 route;
 *       cross-chassis NPU CNAs get a /32 route with ALL 64 L2-facing ports as ECMP.</li>
 *   <li>L2SW: 0.0.0.0/0 default route with ALL L1-facing ports as ECMP;
 *       every NPU CNA gets a /32 route whose outPorts are the L1-facing ports
 *       on the same chip that connect to the destination chassis's L1SW.</li>
 * </ul>
 */
public final class CoverageRouteAugmentor {

    private CoverageRouteAugmentor() {
    }

    // ------------------------------------------------------------------
    //  L1SW augmentation
    // ------------------------------------------------------------------

    private static boolean isL2Sw(Map<String, DeviceEntity> devices, String deviceName) {
        DeviceEntity dev = devices.get(deviceName);
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice
            && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L2;
    }

    /**
     * Augment L1SW routing tables.
     *
     * <p>Cross-chassis /32 routes are split by L2SW chip: each CNA is assigned
     * to one chip, and its /32 route contains only that chip's L2-facing ports
     * (32 ports). This ensures {@code ecmpCnt=32} on both L1SW and L2SW,
     * avoiding the hash coupling {@code h%64} vs {@code h%32} that would
     * otherwise make 50% of L2SW out-ports unreachable when ports are
     * interleaved in JSON order.
     */
    @SuppressWarnings("unchecked")
    public static void augmentL1swRouting(SuperNode superNode) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();

        // Collect every NPU port CNA → (npuName, npuPort, npuChassis)
        Map<String, String[]> cnaToNpu = new LinkedHashMap<>();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.NPU) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (port.getCna() != null) {
                        cnaToNpu.put(port.getCna(),
                            new String[]{dev.getDeviceName(), port.getPortName(), dev.getRack()});
                    }
                }
            }
        }

        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L1) continue;
            String l1swChassis = sw.getRack();

            for (ForwardingChip chip : sw.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;

                // Group L2-facing ports by L2SW chip index
                Map<Integer, List<String>> l2PortsByChip = new LinkedHashMap<>();
                List<String> allL2PortNames = new ArrayList<>();
                Map<String, ? extends PortEntity> chipPorts =
                    (Map<String, ? extends PortEntity>) chip.getPorts();
                for (Map.Entry<String, ? extends PortEntity> e : chipPorts.entrySet()) {
                    if (!isL2Sw(devices, e.getValue().getRemoteDevice())) continue;
                    allL2PortNames.add(e.getKey());
                    PortEntity l2swPort = findPortInDevice(
                        devices.get(e.getValue().getRemoteDevice()),
                        e.getValue().getRemotePort());
                    int l2ChipIdx = l2swPort != null ? l2swPort.getChipIndex() : 0;
                    l2PortsByChip.computeIfAbsent(l2ChipIdx, k -> new ArrayList<>())
                        .add(e.getKey());
                }
                if (allL2PortNames.isEmpty()) continue;

                Map<RoutePrefix, RoutingEntry> newRoutes = new LinkedHashMap<>();

                // Default route: 0.0.0.0/0 → all L2-facing ports (ECMP)
                Map<String, OutPortInfo> defaultOutPorts = new LinkedHashMap<>();
                for (String pn : allL2PortNames) {
                    PortEntity pe = chipPorts.get(pn);
                    defaultOutPorts.put(pn,
                        new OutPortInfo(pn, pe.getRemoteDevice(), 60, 0, "static", 0));
                }
                newRoutes.put(new RoutePrefix("0.0.0.0", 0),
                    new RoutingEntry(new RoutePrefix("0.0.0.0", 0), defaultOutPorts, true));

                // Cross-chassis /32 routes: per-chip ECMP (32 ports per chip)
                // Assign each CNA to a chip so both chips' ports are exercised.
                List<Integer> availableChips = new ArrayList<>(l2PortsByChip.keySet());
                for (Map.Entry<String, String[]> ce : cnaToNpu.entrySet()) {
                    String cna = ce.getKey();
                    String npuChassis = ce.getValue()[2];
                    if (l1swChassis.equals(npuChassis)) continue;

                    int chipIdx = availableChips.get(
                        Math.floorMod(cna.hashCode(), availableChips.size()));
                    List<String> chipL2Ports = l2PortsByChip.get(chipIdx);
                    if (chipL2Ports == null || chipL2Ports.isEmpty()) continue;

                    Map<String, OutPortInfo> outPorts = new LinkedHashMap<>();
                    for (String pn : chipL2Ports) {
                        PortEntity pe = chipPorts.get(pn);
                        outPorts.put(pn,
                            new OutPortInfo(pn, pe.getRemoteDevice(), 60, 0, "static", 0));
                    }
                    newRoutes.put(new RoutePrefix(cna, 32),
                        new RoutingEntry(new RoutePrefix(cna, 32), outPorts, true));
                }

                mergeRoutes(chip, newRoutes);
            }
        }
    }

    // ------------------------------------------------------------------
    //  L2SW augmentation
    // ------------------------------------------------------------------

    private static boolean isL1Sw(Map<String, DeviceEntity> devices, String deviceName) {
        DeviceEntity dev = devices.get(deviceName);
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice
            && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L1;
    }

    /**
     * Augment L2SW routing tables.
     */
    @SuppressWarnings("unchecked")
    public static void augmentL2swRouting(SuperNode superNode) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();

        // All NPU CNAs → destination chassis
        Map<String, String> cnaToChassis = new LinkedHashMap<>();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.NPU) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (port.getCna() != null) {
                        cnaToChassis.put(port.getCna(), dev.getRack());
                    }
                }
            }
        }

        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L2) continue;

            for (ForwardingChip chip : sw.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                Map<String, ? extends PortEntity> chipPorts =
                    (Map<String, ? extends PortEntity>) chip.getPorts();

                // Group L1-facing ports by destination chassis
                Map<String, List<String>> portsByChassis = new LinkedHashMap<>();
                for (Map.Entry<String, ? extends PortEntity> e : chipPorts.entrySet()) {
                    PortEntity port = e.getValue();
                    if (!isL1Sw(devices, port.getRemoteDevice())) continue;
                    String chassis = devices.get(port.getRemoteDevice()).getRack();
                    portsByChassis.computeIfAbsent(chassis, k -> new ArrayList<>())
                        .add(e.getKey());
                }

                Map<RoutePrefix, RoutingEntry> newRoutes = new LinkedHashMap<>();

                // Default route: 0.0.0.0/0 → ALL L1-facing ports (ECMP)
                Map<String, OutPortInfo> defaultOutPorts = new LinkedHashMap<>();
                for (List<String> portNames : portsByChassis.values()) {
                    for (String pn : portNames) {
                        PortEntity pe = chipPorts.get(pn);
                        defaultOutPorts.put(pn,
                            new OutPortInfo(pn, pe.getRemoteDevice(), 60, 0, "static", 0));
                    }
                }
                newRoutes.put(new RoutePrefix("0.0.0.0", 0),
                    new RoutingEntry(new RoutePrefix("0.0.0.0", 0), defaultOutPorts, true));

                // Per-CNA /32 routes → ports to destination chassis's L1SW
                for (Map.Entry<String, String> ce : cnaToChassis.entrySet()) {
                    String cna = ce.getKey();
                    String dstChassis = ce.getValue();
                    List<String> chassisPorts = portsByChassis.get(dstChassis);
                    if (chassisPorts == null || chassisPorts.isEmpty()) continue;

                    Map<String, OutPortInfo> outPorts = new LinkedHashMap<>();
                    for (String pn : chassisPorts) {
                        PortEntity pe = chipPorts.get(pn);
                        outPorts.put(pn,
                            new OutPortInfo(pn, pe.getRemoteDevice(), 60, 0, "static", 0));
                    }
                    newRoutes.put(new RoutePrefix(cna, 32),
                        new RoutingEntry(new RoutePrefix(cna, 32), outPorts, true));
                }

                mergeRoutes(chip, newRoutes);
            }
        }
    }

    // ------------------------------------------------------------------
    //  Link counting helpers (used by test assertions)
    // ------------------------------------------------------------------

    public static int countL1swToL2swLinks(SuperNode superNode) {
        int count = 0;
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L1) continue;
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (isL2Sw(devices, port.getRemoteDevice())) count++;
                }
            }
        }
        return count;
    }

    public static int countL2swToL1swLinks(SuperNode superNode) {
        int count = 0;
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L2) continue;
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (isL1Sw(devices, port.getRemoteDevice())) count++;
                }
            }
        }
        return count;
    }

    // ------------------------------------------------------------------
    //  Internal
    // ------------------------------------------------------------------

    private static PortEntity findPortInDevice(DeviceEntity dev, String portName) {
        if (dev == null || dev.getForwardingChips() == null) return null;
        for (ForwardingChip chip : dev.getForwardingChips().values()) {
            if (chip.getPorts() == null) continue;
            PortEntity pe = chip.getPorts().get(portName);
            if (pe != null) return pe;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static void mergeRoutes(ForwardingChip chip,
                                     Map<RoutePrefix, RoutingEntry> newRoutes) {
        RoutingTable rt = chip.getRoutingTable();
        if (rt == null) {
            rt = new RoutingTable();
            chip.setRoutingTable(rt);
        }
        if (rt.getRoutes() == null) {
            rt.setRoutes(new LinkedHashMap<>());
        }
        // Put into a mutable copy, then merge new routes on top
        Map<RoutePrefix, RoutingEntry> merged =
            new LinkedHashMap<>(rt.getRoutes());
        merged.putAll(newRoutes);
        rt.setRoutes(merged);

        // Recompute maskLengths (descending order so /32 is tried before /0)
        List<Integer> masks = merged.keySet().stream()
            .map(RoutePrefix::getMaskLength)
            .sorted(Comparator.reverseOrder())
            .collect(Collectors.toList());
        rt.setMaskLengths(masks);
    }
}
