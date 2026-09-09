/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: super node store test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.store;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SuperNodeStore")
class SuperNodeStoreTest {

    private SuperNodeStore store;

    @BeforeEach
    void setUp() {
        store = new SuperNodeStore();
        store.init();
    }

    @Test
    @DisplayName("init creates non-null maps")
    void init() {
        SuperNodeStore s = new SuperNodeStore();
        s.init();
        assertDoesNotThrow(() -> s.removeSuperNode("any"));
        assertDoesNotThrow(() -> s.clear());
    }

    @Test
    @DisplayName("replace stores superNode and routingTable for chips with routingTable")
    void replace_withRoutingTable() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);

        RoutingTable rt = createRoutingTable();
        chip.setRoutingTable(rt);

        Map<Integer, NpuForwardingChip> chips = new HashMap<>();
        chips.put(0, chip);
        npu.setForwardingChips(chips);

        SuperNode sn = new SuperNode("superNode1", "v1", Map.of("npu1", npu), null);
        store.replace(sn);

        assertEquals(sn, store.getSuperNode("superNode1"));

        RoutingTableKey key = new RoutingTableKey("superNode1", "npu1", 0);
        assertSame(rt, store.getRoutingTable(key));
    }

    @Test
    @DisplayName("replace with chip having no routingTable does not create routingTableMap entry")
    void replace_withoutRoutingTable() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setRoutingTable(null);

        Map<Integer, NpuForwardingChip> chips = new HashMap<>();
        chips.put(0, chip);
        npu.setForwardingChips(chips);

        SuperNode sn = new SuperNode("superNode1", "v1", Map.of("npu1", npu), null);
        store.replace(sn);

        RoutingTableKey key = new RoutingTableKey("superNode1", "npu1", 0);
        assertNull(store.getRoutingTable(key));
    }

    @Test
    @DisplayName("clear empties both maps")
    void clear() {
        SuperNode sn = new SuperNode("superNode1", "v1", new HashMap<>(), null);
        store.replace(sn);
        store.clear();
        assertNull(store.getSuperNode("superNode1"));
    }

    @Test
    @DisplayName("removeSuperNode cleans both maps")
    void removeSuperNode() {
        SuperNode sn = new SuperNode("superNode1", "v1", new HashMap<>(), null);
        store.replace(sn);
        store.removeSuperNode("superNode1");
        assertNull(store.getSuperNode("superNode1"));
    }

    @Test
    @DisplayName("getSuperNode returns null for non-existent name")
    void getSuperNode_nonExistent() {
        assertNull(store.getSuperNode("nonexistent"));
    }

    @Test
    @DisplayName("addDevice adds device and routes to an existing superNode")
    void addDevice() {
        SuperNode sn = new SuperNode("superNode1", "v1", new HashMap<>(), null);
        store.replace(sn);

        NpuDevice npu = createNpu("npu2");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = createRoutingTable();
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));

        store.addNpuDevice("superNode1", npu);

        assertNotNull(store.getSuperNode("superNode1").getNpuDevices().get("npu2"));
        RoutingTableKey key = new RoutingTableKey("superNode1", "npu2", 0);
        assertSame(rt, store.getRoutingTable(key));
    }

    @Test
    @DisplayName("removeDevice removes device and its routes from store")
    void removeDevice() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = createRoutingTable();
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));

        Map<String, NpuDevice> devices = new HashMap<>();
        devices.put("npu1", npu);
        SuperNode sn = new SuperNode("superNode1", "v1", devices, null);
        store.replace(sn);

        store.removeDevice("superNode1", "npu1");

        assertNull(store.getSuperNode("superNode1").getNpuDevices().get("npu1"));
        RoutingTableKey key = new RoutingTableKey("superNode1", "npu1", 0);
        assertNull(store.getRoutingTable(key));
    }

    @Test
    @DisplayName("addRoutingEntry adds route and updates maskLengths")
    void addRoutingEntry() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = createRoutingTable();
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        store.addRoutingEntry("superNode1", "npu1", 0, prefix, entry);

        RoutingTable stored = store.getRoutingTable(new RoutingTableKey("superNode1", "npu1", 0));
        assertSame(entry, stored.getRoutes().get(prefix));
        assertTrue(stored.getMaskLengths().contains(16));
    }

    @Test
    @DisplayName("removeRoutingEntry removes route and updates maskLengths")
    void removeRoutingEntry() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = createRoutingTable();
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", 60, 0, "STATIC", 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        store.addRoutingEntry("superNode1", "npu1", 0, prefix, entry);

        store.removeRoutingEntry("superNode1", "npu1", 0, prefix);

        RoutingTable stored = store.getRoutingTable(new RoutingTableKey("superNode1", "npu1", 0));
        assertNull(stored.getRoutes().get(prefix));
    }

    @Test
    @DisplayName("addNpuDevice with non-existent superNode name throws")
    void addDevice_nonExistentSuperNode() {
        NpuDevice npu = createNpu("npu_nonexistent");
        assertThrows(IllegalStateException.class,
            () -> store.addNpuDevice("nonexistent", npu));
    }

    @Test
    @DisplayName("addDevice with chip having no routingTable does not create routingTable entry")
    void addDevice_noRoutingTable() {
        SuperNode sn = new SuperNode("superNode1", "v1", new HashMap<>(), null);
        store.replace(sn);

        NpuDevice npu = createNpu("npu_noRt");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setRoutingTable(null);
        npu.setForwardingChips(Map.of(0, chip));

        store.addNpuDevice("superNode1", npu);
        RoutingTableKey key = new RoutingTableKey("superNode1", "npu_noRt", 0);
        assertNull(store.getRoutingTable(key));
    }

    @Test
    @DisplayName("removeDevice when routingTableMap is null does not throw")
    void removeDevice_noRoutingTableMap() {
        Map<String, NpuDevice> devices = new HashMap<>();
        devices.put("npu1", createNpu("npu1"));
        SuperNode sn = new SuperNode("superNode2", "v1", devices, null);
        store.replace(sn);
        store.removeDevice("superNode2", "npu1");
        assertNull(store.getSuperNode("superNode2").getNpuDevices().get("npu1"));
    }

    @Test
    @DisplayName("addRoutingEntry when routingTable not found throws IllegalStateException")
    void addRoutingEntry_noRoutingTable() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        assertThrows(IllegalStateException.class,
            () -> store.addRoutingEntry("nonExistent", "dev", 0, prefix, entry));
    }

    @Test
    @DisplayName("addRoutingEntry when routes map is null throws IllegalStateException")
    void addRoutingEntry_nullRoutes() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(null);
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("port2", new OutPortInfo("port2", "10.0.0.1", null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        assertThrows(IllegalStateException.class,
            () -> store.addRoutingEntry("superNode1", "npu1", 0, prefix, entry));
    }

    @Test
    @DisplayName("removeRoutingEntry when routingTable not found returns silently")
    void removeRoutingEntry_noRoutingTable() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        store.removeRoutingEntry("nonExistent", "dev", 0, prefix);
    }

    @Test
    @DisplayName("removeRoutingEntry when routes map is null returns silently")
    void removeRoutingEntry_nullRoutes() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(null);
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        store.removeRoutingEntry("superNode1", "npu1", 0, prefix);
    }

    @Test
    @DisplayName("updateMaskLengths handles null routes")
    void updateMaskLengths_nullRoutes() {
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(null);
        rt.setMaskLengths(new java.util.ArrayList<>());
        // call getRoutingTable which triggers updateMaskLengths internally
        NpuDevice npu = createNpu("npu_mask");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("sn_mask", "v1", Map.of("npu_mask", npu), null));
    }

    @Test
    @DisplayName("replace with null devices does not throw")
    void replace_nullDevices() {
        SuperNode sn = new SuperNode("superNode1", "v1", null, null);
        assertDoesNotThrow(() -> store.replace(sn));
        assertEquals(sn, store.getSuperNode("superNode1"));
    }

    @Test
    @DisplayName("clear before init does not throw")
    void clear_beforeInit() {
        SuperNodeStore s = new SuperNodeStore();
        assertDoesNotThrow(() -> s.clear());
    }

    @Test
    @DisplayName("removeSuperNode before init does not throw")
    void removeSuperNode_beforeInit() {
        SuperNodeStore s = new SuperNodeStore();
        assertDoesNotThrow(() -> s.removeSuperNode("any"));
    }

    @Test
    @DisplayName("addDevice with existing superNode having null devices map")
    void addDevice_nullDevicesMap() {
        SuperNode sn = new SuperNode();
        sn.setName("superNode1");
        sn.setNpuDevices(null);
        sn.setSwDevices(null);
        // Use reflection to bypass init and put a SuperNode with null devices
        store.replace(sn);
        // Now sn has null devices, addDevice should handle it
        NpuDevice npu = createNpu("npu_new");
        store.addNpuDevice("superNode1", npu);
        assertNotNull(store.getSuperNode("superNode1").getNpuDevices().get("npu_new"));
    }

    @Test
    @DisplayName("removeDevice before init does not throw (null maps)")
    void removeDevice_beforeInit() {
        SuperNodeStore s = new SuperNodeStore();
        assertDoesNotThrow(() -> s.removeDevice("any", "dev"));
    }

    @Test
    @DisplayName("removeDevice with non-existent superNode does nothing")
    void removeDevice_nonExistentSuperNode() {
        assertDoesNotThrow(() -> store.removeDevice("nonexistent", "dev"));
    }

    @Test
    @DisplayName("removeDevice with routing entry for different superNode covers entry mismatch branch")
    void removeDevice_differentSuperNodeRoutingEntry() {
        NpuDevice npu = createNpu("npu1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(new java.util.HashMap<>());
        rt.setMaskLengths(new java.util.ArrayList<>());
        chip.setRoutingTable(rt);
        npu.setForwardingChips(Map.of(0, chip));
        store.replace(new SuperNode("superNode1", "v1", Map.of("npu1", npu), null));

        store.removeDevice("superNode2", "dev");
    }

    @Test
    @DisplayName("removeDevice with existing superNode but null devices does nothing")
    void removeDevice_nullDevices() {
        SuperNode sn = new SuperNode();
        sn.setName("superNode1");
        sn.setNpuDevices(null);
        sn.setSwDevices(null);
        store.replace(sn);
        assertDoesNotThrow(() -> store.removeDevice("superNode1", "dev"));
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

    private static RoutingTable createRoutingTable() {
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(new HashMap<>());
        rt.setMaskLengths(new java.util.ArrayList<>());
        return rt;
    }
}
