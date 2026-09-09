/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: super node service test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.store.SuperNodeStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SuperNodeService")
class SuperNodeServiceTest {

    private SuperNodeStore store;
    private SuperNodeService service;

    @BeforeEach
    void setUp() {
        store = new SuperNodeStore();
        store.init();
        service = new SuperNodeService(store);
    }

    @Test
    @DisplayName("importSuperNode stores valid SuperNode")
    void importSuperNode() {
        SuperNode sn = createSuperNode("superNode1");
        service.importSuperNode(sn);
        assertSame(sn, service.getSuperNode("superNode1"));
    }

    @Test
    @DisplayName("importSuperNode null throws IllegalArgumentException")
    void importSuperNode_null() {
        assertThrows(IllegalArgumentException.class, () -> service.importSuperNode(null));
    }

    @Test
    @DisplayName("importSuperNode with null name throws IllegalArgumentException")
    void importSuperNode_nullName() {
        SuperNode sn = new SuperNode(null, "v1", Map.of("npu1", createNpu("npu1")), null);
        assertThrows(IllegalArgumentException.class, () -> service.importSuperNode(sn));
    }

    @Test
    @DisplayName("importSuperNode with empty name throws IllegalArgumentException")
    void importSuperNode_emptyName() {
        SuperNode sn = new SuperNode("", "v1", Map.of("npu1", createNpu("npu1")), null);
        assertThrows(IllegalArgumentException.class, () -> service.importSuperNode(sn));
    }

    @Test
    @DisplayName("importSuperNode with null devices throws IllegalArgumentException")
    void importSuperNode_nullDevices() {
        SuperNode sn = new SuperNode("superNode1", "v1", null, null);
        assertThrows(IllegalArgumentException.class, () -> service.importSuperNode(sn));
    }

    @Test
    @DisplayName("importSuperNode with empty devices throws IllegalArgumentException")
    void importSuperNode_emptyDevices() {
        SuperNode sn = new SuperNode("superNode1", "v1", new HashMap<>(), null);
        assertThrows(IllegalArgumentException.class, () -> service.importSuperNode(sn));
    }

    @Test
    @DisplayName("addDevices adds devices to existing superNode")
    void addDevices() {
        service.importSuperNode(createSuperNode("superNode1"));
        NpuDevice newDev = createNpu("npu2");
        service.addNpuDevices("superNode1", List.of(newDev));
        assertSame(newDev, service.getSuperNode("superNode1").getNpuDevices().get("npu2"));
    }

    @Test
    @DisplayName("addDevices with null superNodeName throws IllegalArgumentException")
    void addDevices_nullSuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addNpuDevices(null, List.of(createNpu("npu1"))));
    }

    @Test
    @DisplayName("addDevices with null devices throws IllegalArgumentException")
    void addDevices_nullDevices() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addNpuDevices("superNode1", null));
    }

    @Test
    @DisplayName("removeDevices removes from existing superNode")
    void removeDevices() {
        service.importSuperNode(createSuperNode("superNode1"));
        service.removeDevices("superNode1", List.of("npu1"));
        assertNull(service.getSuperNode("superNode1").getNpuDevices().get("npu1"));
    }

    @Test
    @DisplayName("removeDevices with null superNodeName throws IllegalArgumentException")
    void removeDevices_nullSuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeDevices(null, List.of("npu1")));
    }

    @Test
    @DisplayName("removeDevices with null deviceNames throws IllegalArgumentException")
    void removeDevices_nullDeviceNames() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeDevices("superNode1", null));
    }

    @Test
    @DisplayName("removeSuperNode delegates to store")
    void removeSuperNode() {
        service.importSuperNode(createSuperNode("superNode1"));
        service.removeSuperNode("superNode1");
        assertNull(service.getSuperNode("superNode1"));
    }

    @Test
    @DisplayName("getSuperNode non-existent returns null")
    void getSuperNode_nonExistent() {
        assertNull(service.getSuperNode("nonexistent"));
    }

    @Test
    @DisplayName("addRoutingEntries delegates to store with validation")
    void addRoutingEntries() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setRoutingTable(new RoutingTable(null, null, new HashMap<>(), new java.util.ArrayList<>()));
        npu.setForwardingChips(Map.of(0, chip));
        SuperNode sn = new SuperNode("superNode1", "v1", Map.of("npu1", npu), null);
        service.importSuperNode(sn);

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        service.addRoutingEntries("superNode1", "npu1", 0, List.of(entry));

        RoutingTable rt = store.getRoutingTable(new RoutingTableKey("superNode1", "npu1", 0));
        assertSame(entry, rt.getRoutes().get(prefix));
    }

    @Test
    @DisplayName("addRoutingEntries null superNodeName throws")
    void addRoutingEntries_nullSuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries(null, "dev", 0, List.of(new RoutingEntry())));
    }

    @Test
    @DisplayName("addRoutingEntries null deviceName throws")
    void addRoutingEntries_nullDeviceName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode", null, 0, List.of(new RoutingEntry())));
    }

    @Test
    @DisplayName("addRoutingEntries null chipIndex throws")
    void addRoutingEntries_nullChipIndex() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode", "dev", null, List.of(new RoutingEntry())));
    }

    @Test
    @DisplayName("addRoutingEntries null entries throws")
    void addRoutingEntries_nullEntries() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode", "dev", 0, null));
    }

    @Test
    @DisplayName("removeRoutingEntries delegates to store with validation")
    void removeRoutingEntries() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = new RoutingTable(null, null, new HashMap<>(), new ArrayList<>());
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        service.importSuperNode(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port", new OutPortInfo("port", "hop", null, null, null, 0));
        store.addRoutingEntry("superNode1", "npu1", 0, prefix, new RoutingEntry(prefix, outPortInfos, true));
        service.removeRoutingEntries("superNode1", "npu1", 0, List.of(prefix));

        assertNull(rt.getRoutes().get(prefix));
    }

    @Test
    @DisplayName("removeRoutingEntries null superNodeName throws")
    void removeRoutingEntries_nullSuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries(null, "dev", 0, List.of(new RoutePrefix("0.0.0.0", 0))));
    }

    @Test
    @DisplayName("removeRoutingEntries null deviceName throws")
    void removeRoutingEntries_nullDeviceName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("superNode", null, 0, List.of(new RoutePrefix("0.0.0.0", 0))));
    }

    @Test
    @DisplayName("removeRoutingEntries null chipIndex throws")
    void removeRoutingEntries_nullChipIndex() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("superNode", "dev", null, List.of(new RoutePrefix("0.0.0.0", 0))));
    }

    @Test
    @DisplayName("removeRoutingEntries null prefixes throws")
    void removeRoutingEntries_nullPrefixes() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("superNode", "dev", 0, null));
    }

    @Test
    @DisplayName("addDevices with empty superNodeName throws IllegalArgumentException")
    void addDevices_emptySuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addNpuDevices("", List.of(createNpu("npu1"))));
    }

    @Test
    @DisplayName("addDevices with null device in list throws IllegalArgumentException")
    void addDevices_nullDeviceInList() {
        service.importSuperNode(createSuperNode("superNode1"));
        assertThrows(IllegalArgumentException.class,
            () -> service.addNpuDevices("superNode1", Arrays.asList(createNpu("npu2"), null)));
    }

    @Test
    @DisplayName("removeDevices with empty superNodeName throws IllegalArgumentException")
    void removeDevices_emptySuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeDevices("", List.of("npu1")));
    }

    @Test
    @DisplayName("removeDevices with null deviceName in list throws IllegalArgumentException")
    void removeDevices_nullDeviceNameInList() {
        service.importSuperNode(createSuperNode("superNode1"));
        assertThrows(IllegalArgumentException.class,
            () -> service.removeDevices("superNode1", Arrays.asList("npu1", null)));
    }

    @Test
    @DisplayName("removeDevices with empty deviceName in list throws IllegalArgumentException")
    void removeDevices_emptyDeviceNameInList() {
        service.importSuperNode(createSuperNode("superNode1"));
        assertThrows(IllegalArgumentException.class,
            () -> service.removeDevices("superNode1", Arrays.asList("npu1", "")));
    }

    @Test
    @DisplayName("addRoutingEntries with empty superNodeName throws")
    void addRoutingEntries_emptySuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("", "dev", 0, List.of(new RoutingEntry())));
    }

    @Test
    @DisplayName("addRoutingEntries with empty deviceName throws")
    void addRoutingEntries_emptyDeviceName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode", "", 0, List.of(new RoutingEntry())));
    }

    @Test
    @DisplayName("addRoutingEntries with null entry in list throws")
    void addRoutingEntries_nullEntryInList() {
        service.importSuperNode(createSuperNode("superNode1"));
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode1", "npu1", 0, Arrays.asList(null, entry)));
    }

    @Test
    @DisplayName("addRoutingEntries with null prefix in entry throws")
    void addRoutingEntries_nullPrefixInEntry() {
        service.importSuperNode(createSuperNode("superNode1"));
        RoutingEntry entry = new RoutingEntry();
        entry.setOutPortInfos(new HashMap<>());
        assertThrows(IllegalArgumentException.class,
            () -> service.addRoutingEntries("superNode1", "npu1", 0, List.of(entry)));
    }

    @Test
    @DisplayName("removeRoutingEntries with empty superNodeName throws")
    void removeRoutingEntries_emptySuperNodeName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("", "dev", 0, List.of(new RoutePrefix("0.0.0.0", 0))));
    }

    @Test
    @DisplayName("removeRoutingEntries with empty deviceName throws")
    void removeRoutingEntries_emptyDeviceName() {
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("superNode", "", 0, List.of(new RoutePrefix("0.0.0.0", 0))));
    }

    @Test
    @DisplayName("removeRoutingEntries with null prefix in list throws")
    void removeRoutingEntries_nullPrefixInList() {
        service.importSuperNode(createSuperNode("superNode1"));
        assertThrows(IllegalArgumentException.class,
            () -> service.removeRoutingEntries("superNode1", "npu1", 0, Arrays.asList(new RoutePrefix("0.0.0.0", 0), null)));
    }

    private static SuperNode createSuperNode(String name) {
        Map<String, NpuDevice> devices = new HashMap<>();
        devices.put("npu1", createNpu("npu1"));
        return new SuperNode(name, "v1", devices, null);
    }

    private static NpuDevice createNpu(String name) {
        NpuDevice dev = new NpuDevice();
        dev.setDeviceName(name);
        dev.setOsName("os");
        dev.setOsIp("ip");
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);
        return dev;
    }
}
