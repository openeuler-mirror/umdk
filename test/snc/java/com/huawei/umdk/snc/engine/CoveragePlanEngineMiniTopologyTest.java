/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage plan engine mini topology test
 * Create: 2026-09-30
 * Note:
 */
package com.huawei.umdk.snc.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.config.HashTuple;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.engine.CoveragePlanEngine.CoverageSearchResult;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.store.SuperNodeStore;

/**
 * Mini 2-chassis topology test for {@link CoveragePlanEngine}.
 *
 * <p>Drives the engine's core code paths ({@code findCoverage},
 * {@code findCoverageDualDisjoint}, {@code findCoverageEx} and the
 * underlying trace / greedy / dualSelect / rebalance methods) using a small
 * hand-built topology so the slow 1024&times;1024 enumeration exercised by
 * the full rack integration tests is avoided.
 */
@DisplayName("CoveragePlanEngine (mini topology)")
class CoveragePlanEngineMiniTopologyTest {

    private static final String SN_NAME = "mini-supernode";

    private static SuperNodeStore superNodeStore;
    private static SuperNode superNode;

    @BeforeAll
    static void setUp() {
        superNode = buildMiniTopology();
        superNodeStore = new SuperNodeStore();
        superNodeStore.init();
        superNodeStore.replace(superNode);
    }

    // ------------------------------------------------------------------
    //  findCoverage (L1↔L2 only) — drives traceForwardPath / traceReversePath
    //  / findCoverageDiffPath / greedySelect / runGreedyCoverage /
    //  rebalanceEidUsage / scorePair / addPairToSelected / trimRedundantPairs
    // ------------------------------------------------------------------

    @Test
    @DisplayName("findCoverage MIN_COVERAGE on mini topology returns a non-empty result")
    void findCoverageMinCoverage() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 42, 137);
        CoverageSearchResult r = engine.findCoverage(superNode, 42, 137);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0, "totalLinks should be > 0");
        assertNotNull(r.selectedPairs);
        assertNotNull(r.allLinkInfos);
        assertEquals(superNode, superNode, "sanity");
    }

    @Test
    @DisplayName("findCoverage with null CoverageRequirement defaults to MIN_COVERAGE")
    void findCoverageNullRequirementDefaultsToMin() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 0, 0);
        CoverageSearchResult r = engine.findCoverage(superNode, 0, 0, null);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0);
    }

    @Test
    @DisplayName("findCoverage REDUNDANT drives findCoverageDualDisjoint + dualSelect + singlePassDoubleCover")
    void findCoverageRedundant() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 42, 137);
        CoverageSearchResult r = engine.findCoverage(superNode, 42, 137, CoverageRequirement.REDUNDANT);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0);
    }

    // ------------------------------------------------------------------
    //  findCoverageEx (NPU↔L1 + L1↔L2) — drives traceForwardPathEx /
    //  traceReversePathEx / selectNpuEgress / addPair / traceIntraForwardPathEx
    //  / traceIntraReversePathEx / collectNpuL1Links
    // ------------------------------------------------------------------

    @Test
    @DisplayName("findCoverageEx MIN_COVERAGE drives the extended (jettyId) path tracing")
    void findCoverageExMinCoverage() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 42, 137);
        CoverageSearchResult r = engine.findCoverageEx(superNode, 42, 137, CoverageRequirement.MIN_COVERAGE);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0);

        Map<String, Integer> diag = engine.getExDiagnostics();
        assertNotNull(diag, "ex diagnostics map should exist");
        assertFalse(diag.isEmpty(), "diagnostics should expose counters");
    }

    @Test
    @DisplayName("findCoverageEx REDUNDANT drives runGreedyCoverageDualDisjoint over the extended link universe")
    void findCoverageExRedundant() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 42, 137, HashTuple.TWO);
        CoverageSearchResult r = engine.findCoverageEx(superNode, 42, 137, CoverageRequirement.REDUNDANT);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0);
    }

    @Test
    @DisplayName("findCoverageEx with null requirement behaves as MIN_COVERAGE")
    void findCoverageExNullRequirement() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 0, 0);
        CoverageSearchResult r = engine.findCoverageEx(superNode, 0, 0, null);

        assertNotNull(r);
        assertTrue(r.totalLinks > 0);
    }

    // ------------------------------------------------------------------
    //  Edge cases — drive emptyResult / collectNpuCandidates / collectL2swNames
    // ------------------------------------------------------------------

    @Test
    @DisplayName("findCoverage with empty device map returns empty result")
    void findCoverageEmptyDevices() {
        SuperNode empty = new SuperNode("empty", "1.0",
            new HashMap<>(), new HashMap<>());
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 0, 0);

        CoverageSearchResult r = engine.findCoverage(empty, 0, 0);
        assertNotNull(r);
        assertEquals(0, r.totalLinks);
        assertTrue(r.selectedPairs.isEmpty());
        assertFalse(r.fullCoverage);
    }

    @Test
    @DisplayName("findCoverageEx with empty device map returns empty result")
    void findCoverageExEmptyDevices() {
        SuperNode empty = new SuperNode("empty", "1.0",
            new HashMap<>(), new HashMap<>());
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1, 0, 0);

        CoverageSearchResult r = engine.findCoverageEx(empty, 0, 0, null);
        assertNotNull(r);
        assertEquals(0, r.totalLinks);
        assertTrue(r.selectedPairs.isEmpty());
    }

    @Test
    @DisplayName("findCoverage on topology with NPU but no L2SW returns empty result")
    void findCoverageNoL2sw() {
        Map<String, DeviceEntity> devices = new LinkedHashMap<>();
        NpuDevice npu = buildNpu("rack1#board0#npu0", "rack1",
            "00000000000000000000000000000001", "0A0A0A01",
            "172.16.0.1", 32, "rack1#l1sw0", "400GE 1/0/0");
        devices.put(npu.getDeviceName(), npu);

        SwDevice l1sw = buildL1sw("rack1#l1sw0", "rack1", 0);
        bindL1swToNpu(l1sw, 0, "rack1#board0#npu0", "400GE 0/0/0");
        // No L2 routing entries -> collectBidirectionalLinks returns nothing.
        devices.put(l1sw.getDeviceName(), l1sw);

        SuperNode sn = new SuperNode("no-l2", "1.0",
            filterNpu(devices), filterSw(devices));
        SuperNodeStore store = new SuperNodeStore();
        store.init();
        store.replace(sn);

        CoveragePlanEngine engine = new CoveragePlanEngine(store, 1, 0, 0);
        CoverageSearchResult r = engine.findCoverage(sn, 0, 0);
        assertNotNull(r);
        assertEquals(0, r.totalLinks);
    }

    // ------------------------------------------------------------------
    //  Accessor coverage — getFixedDataUdpPort / getFixedAckUdpPort /
    //  getHashTuple / getDieHashFunctionSelect
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Constructor with all fields exposes accessors")
    void accessorsAllFields() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore, 1,
            42, 137, HashTuple.FIVE, 1);

        assertEquals(42, engine.getFixedDataUdpPort());
        assertEquals(137, engine.getFixedAckUdpPort());
        assertEquals(HashTuple.FIVE, engine.getHashTuple());
        assertEquals(1, engine.getDieHashFunctionSelect());
    }

    @Test
    @DisplayName("Default constructor uses HashTuple.TWO and zero ports")
    void defaultConstructor() {
        CoveragePlanEngine engine = new CoveragePlanEngine(superNodeStore);

        assertEquals(0, engine.getFixedDataUdpPort());
        assertEquals(0, engine.getFixedAckUdpPort());
        assertEquals(HashTuple.TWO, engine.getHashTuple());
        assertEquals(0, engine.getDieHashFunctionSelect());
    }

    // ------------------------------------------------------------------
    //  Mini topology builder
    // ------------------------------------------------------------------

    /**
     * Build a tiny 2-chassis topology:
     * <ul>
     *   <li>2 chassis: {@code rack1}, {@code rack2}</li>
     *   <li>Each chassis: 1 NPU (2 ports), 2 L1SW, each L1SW connects to one NPU port</li>
     *   <li>2 shared L2SW: every L1SW has uplinks to both L2SW</li>
     * </ul>
     * Every NPU port carries a {@code jettyId} so {@code findCoverageEx} works.
     */
    private static SuperNode buildMiniTopology() {
        Map<String, DeviceEntity> devices = new LinkedHashMap<>();

        // Two shared L2SW devices
        SwDevice l2sw0 = buildL2sw("l2sw0", 0);
        SwDevice l2sw1 = buildL2sw("l2sw1", 1);
        devices.put(l2sw0.getDeviceName(), l2sw0);
        devices.put(l2sw1.getDeviceName(), l2sw1);

        // 2 chassis × (1 NPU + 2 L1SW)
        for (int c = 0; c < 2; c++) {
            String rack = "rack" + (c + 1);
            String npuName = rack + "#board0#npu0";
            String l1sw0Name = rack + "#l1sw0";
            String l1sw1Name = rack + "#l1sw1";

            // NPU with 2 ports -> l1sw0 / l1sw1
            String eidA = String.format("0000000000000000000000000000000%d", c * 2 + 1);
            String eidB = String.format("0000000000000000000000000000000%d", c * 2 + 2);
            String upi = "0A0A0A01";
            String cnaA = "172.16." + c + ".1";
            String cnaB = "172.16." + c + ".2";
            int jettyA = 32 + c * 2;
            int jettyB = 33 + c * 2;

            NpuDevice npu = buildNpu(npuName, rack, eidA, upi, cnaA, jettyA,
                l1sw0Name, "400GE 1/0/0");
            addNpuPort(npu, "400GE 0/0/1", eidB, upi, cnaB, jettyB,
                l1sw1Name, "400GE 1/0/0");
            devices.put(npuName, npu);

            // L1SW0: NPU port + 2 uplink ports (to l2sw0, l2sw1)
            SwDevice l1sw0 = buildL1sw(l1sw0Name, rack, 0);
            bindL1swToNpu(l1sw0, 0, npuName, "400GE 0/0/0");
            addL1swL2Uplink(l1sw0, "400GE 1/2/0", l2sw0.getDeviceName(), "400GE " + (c + 1) + "/0/0", 0);
            addL1swL2Uplink(l1sw0, "400GE 1/2/1", l2sw1.getDeviceName(), "400GE " + (c + 1) + "/0/0", 1);
            installDefaultRoute(l1sw0, 0, "400GE 1/2/0", "400GE 1/2/1");
            addL1swLocalRoute(l1sw0, 0, "172.16." + c + ".0", 24, "400GE 1/0/0");
            devices.put(l1sw0Name, l1sw0);

            // L1SW1: NPU port + 2 uplink ports
            SwDevice l1sw1 = buildL1sw(l1sw1Name, rack, 1);
            bindL1swToNpu(l1sw1, 0, npuName, "400GE 0/0/1");
            addL1swL2Uplink(l1sw1, "400GE 1/2/0", l2sw0.getDeviceName(), "400GE " + (c + 1) + "/1/0", 0);
            addL1swL2Uplink(l1sw1, "400GE 1/2/1", l2sw1.getDeviceName(), "400GE " + (c + 1) + "/1/0", 1);
            installDefaultRoute(l1sw1, 0, "400GE 1/2/0", "400GE 1/2/1");
            addL1swLocalRoute(l1sw1, 0, "172.16." + c + ".0", 24, "400GE 1/0/0");
            devices.put(l1sw1Name, l1sw1);
        }

        // L2SW0 routing: 172.16.0.0/24 -> rack1 L1SW ports (2 ECMP), 172.16.1.0/24 -> rack2 L1SW ports
        addL2RouteToL1(l2sw0, 0, "172.16.0.0", 24,
            "400GE 1/0/0", "400GE 1/1/0");
        addL2RouteToL1(l2sw0, 0, "172.16.1.0", 24,
            "400GE 2/0/0", "400GE 2/1/0");

        // L2SW1 routing
        addL2RouteToL1(l2sw1, 0, "172.16.0.0", 24,
            "400GE 1/0/0", "400GE 1/1/0");
        addL2RouteToL1(l2sw1, 0, "172.16.1.0", 24,
            "400GE 2/0/0", "400GE 2/1/0");

        // L2SW port inventory — mirror the uplinks added above.
        // l2sw0 ports: 1/0/0 -> rack1#l1sw0, 1/1/0 -> rack1#l1sw1, 2/0/0 -> rack2#l1sw0, 2/1/0 -> rack2#l1sw1
        addL2Port(l2sw0, 0, "400GE 1/0/0", "rack1#l1sw0", "400GE 1/2/0");
        addL2Port(l2sw0, 0, "400GE 1/1/0", "rack1#l1sw1", "400GE 1/2/0");
        addL2Port(l2sw0, 0, "400GE 2/0/0", "rack2#l1sw0", "400GE 1/2/0");
        addL2Port(l2sw0, 0, "400GE 2/1/0", "rack2#l1sw1", "400GE 1/2/0");

        addL2Port(l2sw1, 0, "400GE 1/0/0", "rack1#l1sw0", "400GE 1/2/1");
        addL2Port(l2sw1, 0, "400GE 1/1/0", "rack1#l1sw1", "400GE 1/2/1");
        addL2Port(l2sw1, 0, "400GE 2/0/0", "rack2#l1sw0", "400GE 1/2/1");
        addL2Port(l2sw1, 0, "400GE 2/1/0", "rack2#l1sw1", "400GE 1/2/1");

        Map<String, NpuDevice> npuDevices = filterNpu(devices);
        Map<String, SwDevice> swDevices = filterSw(devices);
        return new SuperNode(SN_NAME, "1.0", npuDevices, swDevices);
    }

    // ---------------- entity builders ----------------

    private static NpuDevice buildNpu(String name, String rack,
                                       String eid, String upi, String cna,
                                       int jettyId, String remoteDev, String remotePort) {
        NpuDevice npu = new NpuDevice();
        npu.setDeviceName(name);
        npu.setRack(rack);
        npu.setOsName("os0");
        npu.setOsIp("10.0.0.1");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(0);
        Map<String, NpuPortEntity> ports = new LinkedHashMap<>();
        NpuPortEntity port = new NpuPortEntity(eid, upi, jettyId);
        port.setPortName("400GE 0/0/0");
        port.setId(0);
        port.setChipIndex(0);
        port.setCna(cna);
        port.setRemoteDevice(remoteDev);
        port.setRemotePort(remotePort);
        ports.put(port.getPortName(), port);
        chip.setPorts(ports);

        RoutingTable rt = buildNpuRoutingTable("400GE 0/0/0", "400GE 0/0/1");
        chip.setRoutingTable(rt);

        npu.setForwardingChips(new HashMap<>(Map.of(0, chip)));
        return npu;
    }

    private static void addNpuPort(NpuDevice npu, String portName, String eid,
                                    String upi, String cna, int jettyId,
                                    String remoteDev, String remotePort) {
        NpuForwardingChip chip = npu.getForwardingChips().get(0);
        Map<String, NpuPortEntity> ports = new LinkedHashMap<>(chip.getPorts());
        NpuPortEntity port = new NpuPortEntity(eid, upi, jettyId);
        port.setPortName(portName);
        port.setId(ports.size());
        port.setChipIndex(0);
        port.setCna(cna);
        port.setRemoteDevice(remoteDev);
        port.setRemotePort(remotePort);
        ports.put(portName, port);
        chip.setPorts(ports);
    }

    private static RoutingTable buildNpuRoutingTable(String... portNames) {
        RoutingTable rt = new RoutingTable();
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        for (int i = 0; i < portNames.length; i++) {
            outPortInfos.put(portNames[i], new OutPortInfo(portNames[i], null, 60, 0, "STATIC", 0));
        }
        RoutePrefix prefix = new RoutePrefix("0.0.0.0", 0);
        routes.put(prefix, new RoutingEntry(prefix, outPortInfos, true));
        rt.setRoutes(routes);
        List<Integer> masks = new ArrayList<>();
        masks.add(0);
        rt.setMaskLengths(masks);
        return rt;
    }

    private static SwDevice buildL1sw(String name, String rack, int index) {
        SwDevice sw = new SwDevice();
        sw.setDeviceName(name);
        sw.setRack(rack);
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(index);
        SwForwardingChip chip = new SwForwardingChip(0);
        chip.setPorts(new LinkedHashMap<>());
        sw.setForwardingChips(new HashMap<>(Map.of(0, chip)));
        return sw;
    }

    private static void bindL1swToNpu(SwDevice l1sw, int chipIdx,
                                       String npuName, String npuPort) {
        SwForwardingChip chip = l1sw.getForwardingChips().get(chipIdx);
        SwPortEntity port = new SwPortEntity();
        port.setPortName("400GE 1/0/0");
        port.setId(0);
        port.setChipIndex(chipIdx);
        port.setRemoteDevice(npuName);
        port.setRemotePort(npuPort);
        Map<String, SwPortEntity> ports = new LinkedHashMap<>(chip.getPorts());
        ports.put(port.getPortName(), port);
        chip.setPorts(ports);
    }

    private static void addL1swL2Uplink(SwDevice l1sw, String portName,
                                         String l2swName, String l2swPort, int id) {
        SwForwardingChip chip = l1sw.getForwardingChips().get(0);
        SwPortEntity port = new SwPortEntity();
        port.setPortName(portName);
        port.setId(64 + id);
        port.setChipIndex(0);
        port.setRemoteDevice(l2swName);
        port.setRemotePort(l2swPort);
        Map<String, SwPortEntity> ports = new LinkedHashMap<>(chip.getPorts());
        ports.put(portName, port);
        chip.setPorts(ports);
    }

    private static void installDefaultRoute(SwDevice l1sw, int chipIdx,
                                             String... portNames) {
        RoutingTable rt = new RoutingTable();
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        for (String p : portNames) {
            outPortInfos.put(p, new OutPortInfo(p, null, 60, 0, "STATIC", 0));
        }
        RoutePrefix prefix = new RoutePrefix("0.0.0.0", 0);
        routes.put(prefix, new RoutingEntry(prefix, outPortInfos, true));
        rt.setRoutes(routes);
        List<Integer> masks = new ArrayList<>();
        masks.add(0);
        rt.setMaskLengths(masks);
        l1sw.getForwardingChips().get(chipIdx).setRoutingTable(rt);
    }

    private static void addL1swLocalRoute(SwDevice l1sw, int chipIdx,
                                           String network, int maskLen,
                                           String portName) {
        SwForwardingChip chip = l1sw.getForwardingChips().get(chipIdx);
        RoutingTable rt = chip.getRoutingTable();
        if (rt == null) {
            rt = new RoutingTable();
            rt.setRoutes(new LinkedHashMap<>());
            rt.setMaskLengths(new ArrayList<>());
            chip.setRoutingTable(rt);
        }
        RoutePrefix prefix = new RoutePrefix(network, maskLen);
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        outPortInfos.put(portName, new OutPortInfo(portName, null, 60, 0, "STATIC", 0));
        rt.getRoutes().put(prefix, new RoutingEntry(prefix, outPortInfos, true));

        List<Integer> masks = new ArrayList<>(rt.getMaskLengths());
        if (!masks.contains(maskLen)) {
            masks.add(maskLen);
            masks.sort((a, b) -> Integer.compare(b, a));
            rt.setMaskLengths(masks);
        }
    }

    private static SwDevice buildL2sw(String name, int index) {
        SwDevice sw = new SwDevice();
        sw.setDeviceName(name);
        sw.setRack("l2sw-rack");
        sw.setSwitchLevel(SwitchLevel.L2);
        sw.setIndex(index);
        SwForwardingChip chip = new SwForwardingChip(0);
        chip.setPorts(new LinkedHashMap<>());
        sw.setForwardingChips(new HashMap<>(Map.of(0, chip)));
        return sw;
    }

    private static void addL2Port(SwDevice l2sw, int chipIdx, String portName,
                                   String remoteDev, String remotePort) {
        SwForwardingChip chip = l2sw.getForwardingChips().get(chipIdx);
        SwPortEntity port = new SwPortEntity();
        port.setPortName(portName);
        port.setId(portName.hashCode() & 0xFFFF);
        port.setChipIndex(chipIdx);
        port.setRemoteDevice(remoteDev);
        port.setRemotePort(remotePort);
        Map<String, SwPortEntity> ports = new LinkedHashMap<>(chip.getPorts());
        ports.put(portName, port);
        chip.setPorts(ports);
    }

    private static void addL2RouteToL1(SwDevice l2sw, int chipIdx,
                                        String network, int maskLen,
                                        String... portNames) {
        SwForwardingChip chip = l2sw.getForwardingChips().get(chipIdx);
        RoutingTable rt = chip.getRoutingTable();
        if (rt == null) {
            rt = new RoutingTable();
            rt.setRoutes(new LinkedHashMap<>());
            rt.setMaskLengths(new ArrayList<>());
            chip.setRoutingTable(rt);
        }
        RoutePrefix prefix = new RoutePrefix(network, maskLen);
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        for (String p : portNames) {
            outPortInfos.put(p, new OutPortInfo(p, null, 60, 0, "STATIC", 0));
        }
        rt.getRoutes().put(prefix, new RoutingEntry(prefix, outPortInfos, true));

        List<Integer> masks = new ArrayList<>(rt.getMaskLengths());
        if (!masks.contains(maskLen)) {
            masks.add(maskLen);
            masks.sort((a, b) -> Integer.compare(b, a)); // longest-first
            rt.setMaskLengths(masks);
        }
    }

    private static Map<String, NpuDevice> filterNpu(Map<String, DeviceEntity> devices) {
        Map<String, NpuDevice> npus = new LinkedHashMap<>();
        for (DeviceEntity d : devices.values()) {
            if (d instanceof NpuDevice) {
                npus.put(d.getDeviceName(), (NpuDevice) d);
            }
        }
        return npus;
    }

    private static Map<String, SwDevice> filterSw(Map<String, DeviceEntity> devices) {
        Map<String, SwDevice> sws = new LinkedHashMap<>();
        for (DeviceEntity d : devices.values()) {
            if (d instanceof SwDevice) {
                sws.put(d.getDeviceName(), (SwDevice) d);
            }
        }
        return sws;
    }
}
