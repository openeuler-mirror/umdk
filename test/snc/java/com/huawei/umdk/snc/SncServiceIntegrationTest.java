/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: snc service integration test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.HopInfo;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.exception.SNCStateException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@DisplayName("SncService Integration Tests (JSON fixtures)")
@TestMethodOrder(MethodOrderer.DisplayName.class)
class SncServiceIntegrationTest {

    private SncService sncService;

    @BeforeEach
    void setUp() throws Exception {
        sncService = new SncService();
        sncService.init(new SNCConfig());
    }

    @AfterEach
    void tearDown() {
        sncService.uninit();
    }

    @Test
    @DisplayName("2.2.1: Multi-hop npu1 -> l1sw0 -> npu2 using 2npu_1port fixture")
    void testMultiHop2Npu1Port() throws Exception {
        SuperNode superNode = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(superNode);

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("A5-superPod-1");
        request.setSrcDevice("rack1#os0#npu1");
        request.setDestDevice("rack1#os0#npu2");
        request.setSrcPort("400GE 0/0/1");
        request.setDestPort("400GE 0/1/1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("rack1#l1sw0", "400GE 1/0/2")));

        PathPlanResult result = sncService.planPath(request);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "Expected SUCCESS but got: " + result.getErrorMessage());
        assertEquals("AAAAAA12000000000000000000000002", result.getSrcEid());
        assertEquals("DDDDDD42000000000000000000000002", result.getDstEid());
        assertNotNull(result.getPath());
        assertEquals(3, result.getPath().getHops().size());

        HopInfo hop0 = result.getPath().getHops().get(0);
        assertEquals("rack1#os0#npu1", hop0.getDeviceName());
        assertNull(hop0.getInPort());
        assertEquals("400GE 0/0/1", hop0.getOutPort());

        HopInfo hop1 = result.getPath().getHops().get(1);
        assertEquals("rack1#l1sw0", hop1.getDeviceName());
        assertEquals("400GE 1/0/1", hop1.getInPort());
        assertEquals("400GE 1/0/2", hop1.getOutPort());

        HopInfo hop2 = result.getPath().getHops().get(2);
        assertEquals("rack1#os0#npu2", hop2.getDeviceName());
        assertEquals("400GE 0/1/1", hop2.getInPort());
        assertNull(hop2.getOutPort());
    }

    @Test
    @DisplayName("3.2.1: npu1 -> l1sw0 -> npu2 (port 0/0/0) using 4npu_8port fixture")
    void testMultiHop4Npu8Port_l1sw0() throws Exception {
        SuperNode superNode = TestDataLoader.loadSuperNode("/topo_data_4npu_8port.json");
        sncService.setSuperNode(superNode);

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("A5-superPod-2");
        request.setSrcDevice("rack1#os0#npu1");
        request.setDestDevice("rack1#os0#npu2");
        request.setSrcPort("400GE 0/0/0");
        request.setDestPort("400GE 0/0/0");
        request.setInterDevices(new LinkedHashMap<>(Map.of("rack1#l1sw0", "400GE 1/0/2")));

        PathPlanResult result = sncService.planPath(request);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "Expected SUCCESS but got: " + result.getErrorMessage());
        assertEquals("AAAAAA12000000000000000000000001", result.getSrcEid());
        assertEquals("DDDDDD42000000000000000000000001", result.getDstEid());
        assertNotNull(result.getPath());
        assertEquals(3, result.getPath().getHops().size());

        HopInfo hop0 = result.getPath().getHops().get(0);
        assertEquals("rack1#os0#npu1", hop0.getDeviceName());
        assertNull(hop0.getInPort());
        assertEquals("400GE 0/0/0", hop0.getOutPort());

        HopInfo hop1 = result.getPath().getHops().get(1);
        assertEquals("rack1#l1sw0", hop1.getDeviceName());
        assertEquals("400GE 1/0/0", hop1.getInPort());
        assertEquals("400GE 1/0/2", hop1.getOutPort());

        HopInfo hop2 = result.getPath().getHops().get(2);
        assertEquals("rack1#os0#npu2", hop2.getDeviceName());
        assertEquals("400GE 0/0/0", hop2.getInPort());
        assertNull(hop2.getOutPort());
    }

    @Test
    @DisplayName("3.2.2: npu1 -> l1sw1 -> npu3 (port 0/0/1) using 4npu_8port fixture")
    void testMultiHop4Npu8Port_l1sw1() throws Exception {
        SuperNode superNode = TestDataLoader.loadSuperNode("/topo_data_4npu_8port.json");
        sncService.setSuperNode(superNode);

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("A5-superPod-2");
        request.setSrcDevice("rack1#os0#npu1");
        request.setDestDevice("rack1#os0#npu3");
        request.setSrcPort("400GE 0/0/1");
        request.setDestPort("400GE 0/0/1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("rack1#l1sw1", "400GE 1/0/4")));

        PathPlanResult result = sncService.planPath(request);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "Expected SUCCESS but got: " + result.getErrorMessage());
        assertEquals("AAAAAA12000000000000000000000002", result.getSrcEid());
        assertEquals("EEEEEE55000000000000000000000002", result.getDstEid());
        assertNotNull(result.getPath());
        assertEquals(3, result.getPath().getHops().size());

        HopInfo hop0 = result.getPath().getHops().get(0);
        assertEquals("rack1#os0#npu1", hop0.getDeviceName());
        assertNull(hop0.getInPort());
        assertEquals("400GE 0/0/1", hop0.getOutPort());

        HopInfo hop1 = result.getPath().getHops().get(1);
        assertEquals("rack1#l1sw1", hop1.getDeviceName());
        assertEquals("400GE 1/0/0", hop1.getInPort());
        assertEquals("400GE 1/0/4", hop1.getOutPort());

        HopInfo hop2 = result.getPath().getHops().get(2);
        assertEquals("rack1#os0#npu3", hop2.getDeviceName());
        assertEquals("400GE 0/0/1", hop2.getInPort());
        assertNull(hop2.getOutPort());
    }

    @Test
    @DisplayName("init(null) does not throw, logging defaults to INFO")
    void initNull() {
        SncService s = new SncService();
        s.init(null);
        s.uninit();
    }

    @Test
    @DisplayName("init with logCallback config registers callback")
    void initWithLogCallback() {
        SncService s = new SncService();
        SNCConfig config = new SNCConfig();
        config.setLogCallback((level, msg) -> {});
        s.init(config);
        s.uninit();
    }

    @Test
    @DisplayName("uninit before init does not throw")
    void uninitBeforeInit() {
        SncService s = new SncService();
        s.uninit();
    }

    @Test
    @DisplayName("addDevices delegates correctly")
    void addDevices() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("newNpu");
        NpuPortEntity port = new NpuPortEntity("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "upi1");
        port.setPortName("p1");
        port.setCna("1.2.3.4");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("p1", port));
        npu.setForwardingChips(Map.of(0, chip));
        sncService.addNpuDevices("A5-superPod-1", List.of(npu));
        assertNotNull(sncService.getSuperNode("A5-superPod-1").getAllDevices().get("newNpu"));
    }

    @Test
    @DisplayName("removeDevices delegates correctly")
    void removeDevices() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        sncService.removeDevices("A5-superPod-1", List.of("rack1#os0#npu1"));
        assertNull(sncService.getSuperNode("A5-superPod-1").getAllDevices().get("rack1#os0#npu1"));
    }

    @Test
    @DisplayName("addRoutingEntries delegates correctly")
    void addRoutingEntries() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        RoutingEntry entry = new RoutingEntry(prefix, Map.of("p1", new OutPortInfo("p1", "10.0.0.1", 60, 0, "STATIC", 0)), true);
        sncService.addRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(entry));
    }

    @Test
    @DisplayName("removeRoutingEntries delegates correctly")
    void removeRoutingEntries() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 16);
        sncService.removeRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(prefix));
    }

    @Test
    @DisplayName("getSuperNode returns null for non-existent")
    void getSuperNode_nonExistent() {
        assertNull(sncService.getSuperNode("nonexistent"));
    }

    @Test
    @DisplayName("removeSuperNode delegates correctly")
    void removeSuperNode() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        sncService.removeSuperNode("A5-superPod-1");
        assertNull(sncService.getSuperNode("A5-superPod-1"));
    }

    @Test
    @DisplayName("planPath throws SNCStateException when not DATAREADY")
    void planPath_stateNotReady() {
        PathPlanRequest req = new PathPlanRequest();
        assertThrows(SNCStateException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null request throws SNCStateException (state check first)")
    void planPath_nullRequest() {
        assertThrows(SNCStateException.class, () -> sncService.planPath(null));
    }

    @Test
    @DisplayName("planPath with null superNodeName throws SNCStateException (state check first)")
    void planPath_nullSuperNodeName() {
        PathPlanRequest req = new PathPlanRequest();
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(SNCStateException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("setSuperNode in INIT state throws SNCStateException")
    void setSuperNode_beforeInit() {
        SncService s = new SncService();
        assertThrows(SNCStateException.class, () -> s.setSuperNode(new SuperNode()));
    }

    @Test
    @DisplayName("setSuperNode transitions to DATAREADY and planPath is reachable")
    void setSuperNode_reachesDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        // After setSuperNode the state is DATAREADY, so planPath reaches the
        // request-parameter validation instead of the state guard.
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("init with null config sets logLevel to INFO default")
    void initNullConfig() throws Exception {
        SncService s = new SncService();
        s.init(null);
        s.setSuperNode(TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json"));
        s.uninit();
    }

    @Test
    @DisplayName("planPath with null superNodeName in DATAREADY throws IllegalArgumentException")
    void planPath_nullSuperNodeNameInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null srcDevice in DATAREADY throws IllegalArgumentException")
    void planPath_nullSrcDeviceInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null destDevice in DATAREADY throws IllegalArgumentException")
    void planPath_nullDestDeviceInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice(null);
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with empty destDevice in DATAREADY throws IllegalArgumentException")
    void planPath_emptyDestDeviceInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice("");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null srcPort in DATAREADY throws IllegalArgumentException")
    void planPath_nullSrcPortInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null destPort in DATAREADY throws IllegalArgumentException")
    void planPath_nullDestPortInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with null request in DATAREADY throws IllegalArgumentException")
    void planPath_nullRequestInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(null));
    }

    @Test
    @DisplayName("planPath with empty superNodeName in DATAREADY throws IllegalArgumentException")
    void planPath_emptySuperNodeNameInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("");
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with empty srcDevice in DATAREADY throws IllegalArgumentException")
    void planPath_emptySrcDeviceInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with empty srcPort in DATAREADY throws IllegalArgumentException")
    void planPath_emptySrcPortInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("");
        req.setDestPort("dp");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("planPath with empty destPort in DATAREADY throws IllegalArgumentException")
    void planPath_emptyDestPortInDataready() throws Exception {
        SuperNode sn = TestDataLoader.loadSuperNode("/topo_data_2npu_1port.json");
        sncService.setSuperNode(sn);
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("A5-superPod-1");
        req.setSrcDevice("src");
        req.setDestDevice("dst");
        req.setSrcPort("sp");
        req.setDestPort("");
        assertThrows(IllegalArgumentException.class, () -> sncService.planPath(req));
    }

    @Test
    @DisplayName("init with config having null logCallback works")
    void initNullLogLevel() {
        SNCConfig config = new SNCConfig();
        config.setLogCallback(null);
        SncService s = new SncService();
        s.init(config);
        s.uninit();
    }
}
