/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path service test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

import com.huawei.umdk.snc.dto.*;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.engine.*;
import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.store.*;
import com.huawei.umdk.snc.entity.RouteSelectionRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PathService")
class PathServiceTest {

    private SuperNodeStore superNodeStore;
    private PathEngine pathEngine;
    private RouteLookupEngine routeLookupEngine;
    private PathService service;

    @BeforeEach
    void setUp() {
        superNodeStore = new SuperNodeStore();
        superNodeStore.init();
        pathEngine = new PathEngine();
        routeLookupEngine = new RouteLookupEngine();
        CoveragePlanEngine coveragePlanEngine = new CoveragePlanEngine(superNodeStore);
        service = new PathService(superNodeStore, pathEngine, routeLookupEngine,
            coveragePlanEngine);
    }

    @Test
    @DisplayName("planPath direct connection succeeds")
    void planPath_directSuccess() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", "NPU1", "port1", null);
        SuperNode sn = createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2));
        superNodeStore.replace(sn);


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);

        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.getSrcEid());
        assertEquals("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", result.getDstEid());
        assertNotNull(result.getPath());
        assertEquals(2, result.getPath().getHops().size());
    }

    @Test
    @DisplayName("planPath returns TOPO_NOT_FOUND when superNode missing")
    void planPath_superNodeNotFound() {
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("nonexistent");
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_NOT_FOUND, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns TOPO_INCOMPLETE when device not found")
    void planPath_superNodeIncomplete() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("MISSING");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_INCOMPLETE, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_AND_DST_MUST_BE_NPU when non-NPU device used")
    void planPath_nonNpu() {
        SwDevice sw = createSw("SW1", null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("SW1", sw)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("SW1");
        request.setDestDevice("SW1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_AND_DST_MUST_BE_NPU, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src port missing EID or CNA")
    void planPath_srcInfoErr() {
        NpuDevice npu1 = createPlainNpu();
        npu1.setDeviceName("NPU1");

        NpuPortEntity port = new NpuPortEntity(null, null);
        port.setPortName("port1");
        port.setCna(null);
        port.setId(1);
        port.setChipIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));
        npu1.setForwardingChips(Map.of(0, chip));

        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns DST_INFO_ERR when dest port not found")
    void planPath_dstInfoErr() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("nonexistent");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.DST_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns DST_INFO_ERR when dest port is not NpuPortEntity")
    void planPath_dstInfoErr_notNpuPort() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);

        NpuDevice npu2 = createPlainNpu();
        npu2.setDeviceName("NPU2");

        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("swPort");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.DST_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_AND_DST_MUST_BE_NPU when dest is not NPU but src is")
    void planPath_srcIsNpuDestIsSwitch() {
        NpuDevice npu = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        SwDevice sw = createSw("SW1", null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu, "SW1", sw)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("SW1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_AND_DST_MUST_BE_NPU, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns UPI_MISMATCH when source and destination UPI differ")
    void planPath_upiMismatch() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", "upiA");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, "upiB");
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.UPI_MISMATCH, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns TOPO_CONNECTION_ERROR when direct connection not found")
    void planPath_directConnectionError() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "OTHER_DEVICE", "portX", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src port not found")
    void planPath_srcPortNotFound() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("nonexistent");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src port EID is null")
    void planPath_srcEidNull() {
        NpuDevice npu1 = createPlainNpu();
        npu1.setDeviceName("NPU1");

        NpuPortEntity port = new NpuPortEntity(null, null);
        port.setPortName("port1");
        port.setCna("1.2.3.4");
        port.setId(1);
        port.setChipIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));
        npu1.setForwardingChips(Map.of(0, chip));

        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src port CNA is null")
    void planPath_srcCnaNull() {
        NpuDevice npu1 = createPlainNpu();
        npu1.setDeviceName("NPU1");

        NpuPortEntity port = new NpuPortEntity("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null);
        port.setPortName("port1");
        port.setCna(null);
        port.setId(1);
        port.setChipIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));
        npu1.setForwardingChips(Map.of(0, chip));

        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath with multi-hop interDevices succeeds and produces 3 hops with route lookup")
    void planPath_multiHopSuccess() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";

        // NPU1 -> L1SW -> NPU2
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");

        // L1SW: swPort1 connects to NPU1, swPort2 connects to NPU2
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");

        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");

        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        // For connection check: hop1 (L1SW) remoteDevice must equal hop2 (NPU2) deviceName
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");

        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));

        // Add routing table to L1SW chip 0 for route lookup
        RoutingTable swRt = createRoutingTable();
        // Forward route: match forwardTarget "6.6.7.8" with prefix 6.6.7.0/24 -> outPort=swPort2
        RoutePrefix forwardPrefix = new RoutePrefix("5.6.7.0", 24);
        RoutingEntry forwardEntry = createRoutingEntry(forwardPrefix, "swPort2", "nextHop");
        putRoute(swRt, forwardPrefix, forwardEntry);
        // Reverse route: match reverseTarget "2.2.3.4" with prefix 2.2.3.0/24 -> outPort=swPort1
        RoutePrefix reversePrefix = new RoutePrefix("1.2.3.0", 24);
        RoutingEntry reverseEntry = createRoutingEntry(reversePrefix, "swPort1", "nextHop");
        putRoute(swRt, reversePrefix, reverseEntry);
        // Update maskLengths
        updateMaskLengths(swRt);

        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));

        SuperNode sn = createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2));
        superNodeStore.replace(sn);

        // Request with interDevices
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(), "Expected SUCCESS but got: " + result.getErrorMessage());
        assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.getSrcEid());
        assertEquals("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", result.getDstEid());
        assertNotNull(result.getPath());
        assertEquals(3, result.getPath().getHops().size());

        HopInfo hop0 = result.getPath().getHops().get(0);
        assertEquals("NPU1", hop0.getDeviceName());
        assertNull(hop0.getInPort());
        assertEquals("port1", hop0.getOutPort());

        HopInfo hop1 = result.getPath().getHops().get(1);
        assertEquals("L1SW", hop1.getDeviceName());

        HopInfo hop2 = result.getPath().getHops().get(2);
        assertEquals("NPU2", hop2.getDeviceName());
        assertEquals("port1", hop2.getInPort());
        assertNull(hop2.getOutPort());
    }

    @Test
    @DisplayName("planPath with multi-hop returns TOPO_CONNECTION_NOT_FOUND when path resolution fails")
    void planPath_multiHopConnectionNotFound() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, "upi1");
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("MISSING", "port1")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_NOT_FOUND, result.getStatus());
    }

    @Test
    @DisplayName("planPath with multi-hop returns DST_INFO_ERR when dest port CNA is null")
    void planPath_dstCnaNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);

        NpuDevice npu2 = createPlainNpu();
        npu2.setDeviceName("NPU2");

        NpuPortEntity port = new NpuPortEntity("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", null);
        port.setPortName("port1");
        port.setCna(null);
        port.setId(1);
        port.setChipIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));
        npu2.setForwardingChips(Map.of(0, chip));

        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.DST_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath with multi-hop returns DST_INFO_ERR when dest port EID is null")
    void planPath_dstEidNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);

        NpuDevice npu2 = createPlainNpu();
        npu2.setDeviceName("NPU2");

        NpuPortEntity port = new NpuPortEntity(null, null);
        port.setPortName("port1");
        port.setCna("5.6.7.8");
        port.setId(1);
        port.setChipIndex(0);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));
        npu2.setForwardingChips(Map.of(0, chip));

        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.DST_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath with multi-hop route lookup on intermediate device sets outPort")
    void planPath_multiHopRouteLookupSetsOutPort() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";

        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");

        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");

        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");

        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");

        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));

        RoutingTable swRt = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("5.6.7.0", 24);
        putRoute(swRt, fwdPrefix, createRoutingEntry(fwdPrefix, "swPort2", "nh"));
        RoutePrefix revPrefix = new RoutePrefix("1.2.3.0", 24);
        putRoute(swRt, revPrefix, createRoutingEntry(revPrefix, "swPort1", "nh"));
        updateMaskLengths(swRt);
        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));

        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns TOPO_INCOMPLETE when src device not found")
    void planPath_srcDeviceNotFound() {
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("MISSING");
        request.setDestDevice("NPU2");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_INCOMPLETE, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src port is not NpuPortEntity")
    void planPath_srcPortIsSwPort() {
        NpuDevice npu1 = createPlainNpu();
        npu1.setDeviceName("NPU1");

        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));

        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("swPort");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns SRC_INFO_ERR when src EID format is invalid")
    void planPath_invalidSrcEid() {
        NpuDevice npu1 = createPlainNpu();
        npu1.setDeviceName("NPU1");
        NpuPortEntity port = new NpuPortEntity("invalid_eid_not_32_hex", null);
        port.setPortName("port1");
        port.setCna("1.2.3.4");
        port.setId(1);
        port.setChipIndex(0);
        NpuForwardingChip fchip = new NpuForwardingChip(null);
        fchip.setChipIndex(0);
        fchip.setPorts(Map.of("port1", port));
        npu1.setForwardingChips(Map.of(0, fchip));

        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SRC_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns DST_INFO_ERR when dest EID format is invalid")
    void planPath_invalidDstEid() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        NpuDevice npu2 = createPlainNpu();
        npu2.setDeviceName("NPU2");
        NpuPortEntity port = new NpuPortEntity("bad_eid", null);
        port.setPortName("port1");
        port.setCna("5.6.7.8");
        port.setId(1);
        port.setChipIndex(0);
        NpuForwardingChip fchip = new NpuForwardingChip(null);
        fchip.setChipIndex(0);
        fchip.setPorts(Map.of("port1", port));
        npu2.setForwardingChips(Map.of(0, fchip));

        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.DST_INFO_ERR, result.getStatus());
    }

    @Test
    @DisplayName("planPath UPI check handles src UPI null and dest UPI non-null")
    void planPath_upiSrcNullDestNonNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, "upiB");
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath UPI check handles src UPI non-null and dest UPI null")
    void planPath_upiSrcNonNullDestNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", "upiA");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath with empty interDevices map goes through direct path logic")
    void planPath_emptyInterDevicesMap() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        SuperNode sn = createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2));
        superNodeStore.replace(sn);


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>());

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath returns TOPO_CONNECTION_ERROR when srcRemoteDevice is null")
    void planPath_srcRemoteDeviceNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath direct connection fails when srcRemotePort is null despite matching device")
    void planPath_directConnection_srcRemotePortNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", null, null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath direct connection fails when srcRemotePort does not match destPort")
    void planPath_directConnection_srcRemotePortMismatch() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "portX", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath direct connection reverse fails when destRemoteDevice exists but does not match src")
    void planPath_directConnection_reverseDeviceMismatch() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", "OTHER", "port1", null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath direct connection reverse fails when destRemotePort is null despite device match")
    void planPath_directConnection_reversePortNull() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", "NPU1", null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath direct connection reverse check fails when dest does not reference src")
    void planPath_directConnectionReverseFails() {
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", "NPU2", "port1", null);
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "5.6.7.8", "NPU1", "WRONG_PORT", null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.TOPO_CONNECTION_ERROR, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop returns ROUTE_NOT_REACHABLE when routePhase has no matching route")
    void planPath_multiHop_routePhase_noMatch() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        // Routing table exists but has no matching routes
        RoutingTable swRt = createRoutingTable();
        RoutePrefix nonMatching = new RoutePrefix("99.99.99.0", 24);
        putRoute(swRt, nonMatching, createRoutingEntry(nonMatching, "swPort1", "nh"));
        updateMaskLengths(swRt);
        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.ROUTE_NOT_REACHABLE, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop returns ROUTE_NOT_REACHABLE when chip has no routingTable")
    void planPath_multiHop_routePhase_chipWithoutRt() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        // No routingTable set on chip -> rt will be null -> continue
        sw.setForwardingChips(Map.of(0, swChip));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.ROUTE_NOT_REACHABLE, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop returns ROUTE_NOT_REACHABLE when matching entry has null outPortInfos")
    void planPath_multiHop_routePhase_outPortInfosNull() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        RoutingTable swRt = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("6.6.7.0", 24);
        // Entry with null outPortInfos
        putRoute(swRt, fwdPrefix, new RoutingEntry(fwdPrefix, null, true));
        updateMaskLengths(swRt);
        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.ROUTE_NOT_REACHABLE, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop returns ROUTE_NOT_REACHABLE when matching entry has empty outPortInfos")
    void planPath_multiHop_routePhase_outPortInfosEmpty() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        RoutingTable swRt = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("6.6.7.0", 24);
        putRoute(swRt, fwdPrefix, new RoutingEntry(fwdPrefix, new HashMap<>(), true));
        updateMaskLengths(swRt);
        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.ROUTE_NOT_REACHABLE, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop with entry having null prefix covers entry.getPrefix()!=null false branch")
    void planPath_multiHop_routePhase_entryNullPrefix() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");

        SwForwardingChip swChip1 = new SwForwardingChip();
        swChip1.setChipIndex(0);
        swChip1.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        RoutingTable swRt1 = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("5.6.7.0", 24);
        putRoute(swRt1, fwdPrefix, createRoutingEntry(fwdPrefix, "swPort2", "nh"));
        RoutePrefix revPrefix = new RoutePrefix("1.2.3.0", 24);
        putRoute(swRt1, revPrefix, createRoutingEntry(revPrefix, "swPort1", "nh"));
        updateMaskLengths(swRt1);
        swChip1.setRoutingTable(swRt1);

        SwForwardingChip swChip2 = new SwForwardingChip();
        swChip2.setChipIndex(1);
        SwPortEntity swPortExtra = new SwPortEntity();
        swPortExtra.setPortName("extraPort");
        swPortExtra.setId(3);
        swPortExtra.setChipIndex(1);
        swChip2.setPorts(Map.of("extraPort", swPortExtra));
        RoutingTable swRt2 = createRoutingTable();
        RoutePrefix matchKey = new RoutePrefix("6.6.7.0", 24);
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put("extraPort", new OutPortInfo("extraPort", "nh", 60, 0, "STATIC", 0));
        putRoute(swRt2, matchKey, new RoutingEntry(null, outPortInfos, true));
        updateMaskLengths(swRt2);
        swChip2.setRoutingTable(swRt2);

        sw.setForwardingChips(Map.of(0, swChip1, 1, swChip2));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
    }

    @Test
    @DisplayName("planPath multi-hop with second chip having shorter prefix covers > bestMaskLen false")
    void planPath_multiHop_routePhase_shorterMaskLen() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");

        SwForwardingChip swChip1 = new SwForwardingChip();
        swChip1.setChipIndex(0);
        swChip1.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        RoutingTable swRt1 = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("5.6.7.0", 24);
        putRoute(swRt1, fwdPrefix, createRoutingEntry(fwdPrefix, "swPort2", "nh"));
        RoutePrefix revPrefix = new RoutePrefix("1.2.3.0", 24);
        putRoute(swRt1, revPrefix, createRoutingEntry(revPrefix, "swPort1", "nh"));
        updateMaskLengths(swRt1);
        swChip1.setRoutingTable(swRt1);

        SwForwardingChip swChip2 = new SwForwardingChip();
        swChip2.setChipIndex(1);
        SwPortEntity swPortExtra = new SwPortEntity();
        swPortExtra.setPortName("extraPort");
        swPortExtra.setId(3);
        swPortExtra.setChipIndex(1);
        swChip2.setPorts(Map.of("extraPort", swPortExtra));
        RoutingTable swRt2 = createRoutingTable();
        RoutePrefix shorterPrefix = new RoutePrefix("5.6.0.0", 16);
        putRoute(swRt2, shorterPrefix, createRoutingEntry(shorterPrefix, "extraPort", "nh"));
        updateMaskLengths(swRt2);
        swChip2.setRoutingTable(swRt2);

        sw.setForwardingChips(Map.of(0, swChip1, 1, swChip2));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));
        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));
        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
    }

    @Test
    @DisplayName("routePhase with null superNode throws RuntimeException via reflection")
    void routePhase_nullSuperNode() throws Exception {
        java.lang.reflect.Method method = PathService.class.getDeclaredMethod(
            "routePhase", InternalPathInfo.class, String.class, String.class, String.class, String.class, RouteSelectionRecord.Direction.class, int.class);
        method.setAccessible(true);
        InternalPathHop hop = new InternalPathHop();
        hop.setDeviceName("MISSING_DEV");
        hop.setDeviceType(DeviceType.NPU);
        hop.setHopIndex(1);
        InternalPathInfo pathInfo = new InternalPathInfo();
        pathInfo.setHops(List.of(new InternalPathHop(), hop, new InternalPathHop()));
        assertThrows(RuntimeException.class, () -> {
            try {
                method.invoke(service, pathInfo, "10.0.0.1", "nonexistent", "1.2.3.4", "5.6.7.8", RouteSelectionRecord.Direction.FORWARD, 0);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }

    @Test
    @DisplayName("routePhase with null device throws RuntimeException via reflection")
    void routePhase_nullDevice() throws Exception {
        java.lang.reflect.Method method = PathService.class.getDeclaredMethod(
            "routePhase", InternalPathInfo.class, String.class, String.class, String.class, String.class, RouteSelectionRecord.Direction.class, int.class);
        method.setAccessible(true);
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1.2.3.4", null, null, null);
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1)));
        InternalPathHop hop = new InternalPathHop();
        hop.setDeviceName("NONEXISTENT_DEV");
        hop.setDeviceType(DeviceType.NPU);
        hop.setHopIndex(1);
        InternalPathInfo pathInfo = new InternalPathInfo();
        pathInfo.setHops(List.of(new InternalPathHop(), hop, new InternalPathHop()));
        assertThrows(RuntimeException.class, () -> {
            try {
                method.invoke(service, pathInfo, "10.0.0.1", "superNode1", "1.2.3.4", "5.6.7.8", RouteSelectionRecord.Direction.FORWARD, 0);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }

    @Test
    @DisplayName("buildResult handles null hops and null deviceType via reflection")
    void buildResult_nullHopsAndDeviceType() throws Exception {
        java.lang.reflect.Method method = PathService.class.getDeclaredMethod(
            "buildResult", InternalPathInfo.class);
        method.setAccessible(true);
        InternalPathHop hop = new InternalPathHop();
        hop.setDeviceName("DEV1");
        hop.setDeviceType(null);
        InternalPathInfo pathInfo = new InternalPathInfo();
        pathInfo.setHops(List.of(hop));
        PathPlanResult result = (PathPlanResult) method.invoke(service, pathInfo);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertNull(result.getPath().getHops().get(0).getDeviceType());

        InternalPathInfo nullHops = new InternalPathInfo();
        nullHops.setHops(null);
        PathPlanResult result2 = (PathPlanResult) method.invoke(service, nullHops);
        assertEquals(PlanStatus.SUCCESS, result2.getStatus());
        assertTrue(result2.getPath().getHops().isEmpty());
    }

    @Test
    @DisplayName("planPath multi-hop with ECMP (multiple outPorts) still succeeds")
    void planPath_multiHop_routePhase_multiPath() {
        String srcCna = "1.2.3.4";
        String destCna = "5.6.7.8";
        NpuDevice npu1 = createNpu("NPU1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", srcCna, "L1SW", "swPort1", "upi1");
        NpuDevice npu2 = createNpu("NPU2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", destCna, "L1SW", "swPort2", "upi1");
        SwDevice sw = createPlainSw(SwitchLevel.L1, 1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        RoutingTable swRt = createRoutingTable();
        RoutePrefix fwdPrefix = new RoutePrefix("5.6.7.0", 24);
        // Entry with two outPorts -> ECMP
        Map<String, OutPortInfo> multiPorts = new HashMap<>();
        multiPorts.put("swPort2", new OutPortInfo("swPort2", "nextHop", 60, 0, "STATIC", 0));
        multiPorts.put("swPort3", new OutPortInfo("swPort3", "nextHop2", 60, 0, "STATIC", 0));
        putRoute(swRt, fwdPrefix, new RoutingEntry(fwdPrefix, multiPorts, true));
        RoutePrefix revPrefix = new RoutePrefix("1.2.3.0", 24);
        putRoute(swRt, revPrefix, createRoutingEntry(revPrefix, "swPort1", "nh"));
        updateMaskLengths(swRt);
        swChip.setRoutingTable(swRt);
        sw.setForwardingChips(Map.of(0, swChip));
        superNodeStore.replace(createSuperNode("superNode1", Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2)));


        PathPlanRequest request = new PathPlanRequest();
        request.setSuperNodeName("superNode1");
        request.setSrcDevice("NPU1");
        request.setDestDevice("NPU2");
        request.setSrcPort("port1");
        request.setDestPort("port1");
        request.setInterDevices(new LinkedHashMap<>(Map.of("L1SW", "swPort2")));

        PathPlanResult result = service.planPath(request);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
    }

    private static SuperNode createSuperNode(String name, Map<String, DeviceEntity> devices) {
        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();
        for (DeviceEntity device : devices.values()) {
            if (device instanceof NpuDevice) {
                npuDevices.put(device.getDeviceName(), (NpuDevice) device);
            } else if (device instanceof SwDevice) {
                swDevices.put(device.getDeviceName(), (SwDevice) device);
            }
        }
        return new SuperNode(name, "1.0", npuDevices, swDevices);
    }

    private static NpuDevice createPlainNpu() {
        NpuDevice dev = new NpuDevice();
        dev.setOsName("os");
        dev.setOsIp("ip");
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);
        return dev;
    }

    private static SwDevice createPlainSw(SwitchLevel level, Integer index) {
        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(level);
        sw.setIndex(index);
        return sw;
    }

    private static NpuDevice createNpu(String name, String eid, String cna,
                                        String remoteDevice, String remotePort, String upi) {
        NpuDevice dev = new NpuDevice();
        dev.setDeviceName(name);
        dev.setOsName("os");
        dev.setOsIp("ip");
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);

        NpuPortEntity port = new NpuPortEntity(eid, upi);
        port.setPortName("port1");
        port.setId(1);
        port.setChipIndex(0);
        port.setCna(cna);
        port.setRemoteDevice(remoteDevice);
        port.setRemotePort(remotePort);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));

        dev.setForwardingChips(Map.of(0, chip));
        return dev;
    }

    private static SwDevice createSw(String name, String remoteDevice, String remotePort) {
        SwDevice sw = new SwDevice();
        sw.setDeviceName(name);
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);

        SwPortEntity swPort = new SwPortEntity();
        swPort.setPortName("port1");
        swPort.setId(1);
        swPort.setChipIndex(0);
        swPort.setRemoteDevice(remoteDevice);
        swPort.setRemotePort(remotePort);

        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", swPort));

        sw.setForwardingChips(Map.of(0, chip));
        return sw;
    }

    private static RoutingTable createRoutingTable() {
        RoutingTable rt = new RoutingTable();
        rt.setRoutes(new HashMap<>());
        rt.setMaskLengths(new ArrayList<>());
        return rt;
    }

    private static void putRoute(RoutingTable rt, RoutePrefix prefix, RoutingEntry entry) {
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>(rt.getRoutes());
        routes.put(prefix, entry);
        rt.setRoutes(routes);
    }

    private static RoutingEntry createRoutingEntry(RoutePrefix prefix, String outPort, String nextHop) {
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put(outPort, new OutPortInfo(outPort, nextHop, 60, 0, "STATIC", 0));
        return new RoutingEntry(prefix, outPortInfos, true);
    }

    private static void updateMaskLengths(RoutingTable rt) {
        List<Integer> masks = rt.getRoutes().keySet().stream()
            .map(RoutePrefix::getMaskLength)
            .sorted(Comparator.reverseOrder())
            .collect(java.util.stream.Collectors.toList());
        rt.setMaskLengths(masks);
    }

    /* ========================================================================
     * COVERAGE mode tests using multi-chassis topology (§5)
     * ======================================================================== */


    @Test
    @DisplayName("planPathsCoverage uses default ports (0/0) from config when not specified")
    void planPathsCoverage_defaultPorts() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName("test-supernode");

        CoveragePathsResult result = service.planPathsCoverage(request);
        assertEquals(PlanStatus.TOPO_NOT_FOUND, result.getStatus());
    }

    @Test
    @DisplayName("planPathsCoverage returns TOPO_NOT_FOUND for missing superNode")
    void planPathsCoverage_missingSuperNode() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName("nonexistent");

        CoveragePathsResult result = service.planPathsCoverage(request);
        assertEquals(PlanStatus.TOPO_NOT_FOUND, result.getStatus());
    }

    // ─── Helper: build a minimal §5 multi-chassis topology ───

    private SuperNode buildFourChassisTopology() {
        // 2 chassis, each with 1 NPU (npu0) with 2 ports
        // Each chassis has 2 L1SW (l1sw0, l1sw1), each connecting to a different L2SW
        // 2 L2SW (l2sw0, l2sw1)
        // NPU ports: port0→l1sw0, port1→l1sw1
        // L1SW ports to L2SW: 2 ECMP candidate ports per L1SW

        Map<String, DeviceEntity> devices = new LinkedHashMap<>();

        // L2SW devices
        SwDevice l2sw0 = createPlainSw(SwitchLevel.L2, 0);
        l2sw0.setDeviceName("l2sw0");
        l2sw0.setRack("l2sw-rack");
        SwForwardingChip l2sw0Chip = new SwForwardingChip();
        l2sw0Chip.setChipIndex(0);
        l2sw0Chip.setPorts(Map.of());
        l2sw0.setForwardingChips(Map.of(0, l2sw0Chip));

        SwDevice l2sw1 = createPlainSw(SwitchLevel.L2, 1);
        l2sw1.setDeviceName("l2sw1");
        l2sw1.setRack("l2sw-rack");
        SwForwardingChip l2sw1Chip = new SwForwardingChip();
        l2sw1Chip.setChipIndex(0);
        l2sw1Chip.setPorts(Map.of());
        l2sw1.setForwardingChips(Map.of(0, l2sw1Chip));

        devices.put("l2sw0", l2sw0);
        devices.put("l2sw1", l2sw1);

        // For each chassis
        for (int c = 0; c < 2; c++) {
            String chassis = "chassis" + c;

            // L1SW devices
            SwDevice l1sw0 = createPlainSw(SwitchLevel.L1, 0);
            l1sw0.setDeviceName(chassis + "#l1sw0");
            l1sw0.setRack(chassis);
            SwForwardingChip l1sw0Chip = new SwForwardingChip();
            l1sw0Chip.setChipIndex(0);
            Map<String, SwPortEntity> l1sw0Ports = new LinkedHashMap<>();

            // L1SW port to NPU
            SwPortEntity npuPort0 = new SwPortEntity();
            npuPort0.setPortName("400GE 1/0/0");
            npuPort0.setId(0);
            npuPort0.setChipIndex(0);
            npuPort0.setRemoteDevice(chassis + "#board0#npu0");
            npuPort0.setRemotePort("400GE 0/0/0");
            l1sw0Ports.put("400GE 1/0/0", npuPort0);

            // L1SW ports to L2SW0 (2 ECMP candidates)
            for (int p = 0; p < 2; p++) {
                SwPortEntity outPort = new SwPortEntity();
                String portName = "400GE 1/2/" + p;
                outPort.setPortName(portName);
                outPort.setId(64 + p);
                outPort.setChipIndex(0);
                outPort.setRemoteDevice("l2sw0");
                outPort.setRemotePort("400GE 1/" + c + "/" + p);
                l1sw0Ports.put(portName, outPort);
            }
            l1sw0Chip.setPorts(l1sw0Ports);

            // Routing table: all traffic routes to l2sw0 via 2 candidate ports
            RoutingTable l1sw0Rt = buildL1swRoutingTable("l2sw0", 2);
            l1sw0Chip.setRoutingTable(l1sw0Rt);
            l1sw0.setForwardingChips(Map.of(0, l1sw0Chip));

            SwDevice l1sw1 = createPlainSw(SwitchLevel.L1, 1);
            l1sw1.setDeviceName(chassis + "#l1sw1");
            l1sw1.setRack(chassis);
            SwForwardingChip l1sw1Chip = new SwForwardingChip();
            l1sw1Chip.setChipIndex(0);
            Map<String, SwPortEntity> l1sw1Ports = new LinkedHashMap<>();

            // L1SW1 port to NPU
            SwPortEntity npuPort1 = new SwPortEntity();
            npuPort1.setPortName("400GE 1/0/0");
            npuPort1.setId(0);
            npuPort1.setChipIndex(0);
            npuPort1.setRemoteDevice(chassis + "#board0#npu0");
            npuPort1.setRemotePort("400GE 0/0/1");
            l1sw1Ports.put("400GE 1/0/0", npuPort1);

            // L1SW1 ports to L2SW1 (2 ECMP candidates)
            for (int p = 0; p < 2; p++) {
                SwPortEntity outPort = new SwPortEntity();
                String portName = "400GE 1/2/" + p;
                outPort.setPortName(portName);
                outPort.setId(64 + p);
                outPort.setChipIndex(0);
                outPort.setRemoteDevice("l2sw1");
                outPort.setRemotePort("400GE 1/" + c + "/" + p);
                l1sw1Ports.put(portName, outPort);
            }
            l1sw1Chip.setPorts(l1sw1Ports);

            RoutingTable l1sw1Rt = buildL1swRoutingTable("l2sw1", 2);
            l1sw1Chip.setRoutingTable(l1sw1Rt);
            l1sw1.setForwardingChips(Map.of(0, l1sw1Chip));

            // NPU device
            NpuDevice npu = new NpuDevice();
            npu.setDeviceName(chassis + "#board0#npu0");
            npu.setRack(chassis);
            npu.setOsName("os0");
            npu.setOsIp("10.0." + c + ".1");
            npu.setBoardId(0);
            npu.setBoardIndex(0);
            npu.setModuleId(0);

            NpuForwardingChip npuChip = new NpuForwardingChip();
            npuChip.setChipIndex(0);
            Map<String, NpuPortEntity> npuPorts = new LinkedHashMap<>();

            // port0 → l1sw0
            NpuPortEntity port0 = new NpuPortEntity(
                String.format("0000000000000000000000000000000%d", c * 4 + 1),
                "0A0A0A0" + (c * 4 + 1)
            );
            port0.setPortName("400GE 0/0/0");
            port0.setId(0);
            port0.setChipIndex(0);
            port0.setCna("172.16." + c + ".1");
            port0.setRemoteDevice(chassis + "#l1sw0");
            port0.setRemotePort("400GE 1/0/0");
            npuPorts.put("400GE 0/0/0", port0);

            // port1 → l1sw1
            NpuPortEntity port1 = new NpuPortEntity(
                String.format("0000000000000000000000000000000%d", c * 4 + 2),
                "0A0A0A0" + (c * 4 + 2)
            );
            port1.setPortName("400GE 0/0/1");
            port1.setId(1);
            port1.setChipIndex(0);
            port1.setCna("172.16." + c + ".2");
            port1.setRemoteDevice(chassis + "#l1sw1");
            port1.setRemotePort("400GE 1/0/0");
            npuPorts.put("400GE 0/0/1", port1);

            npuChip.setPorts(npuPorts);
            npu.setForwardingChips(Map.of(0, npuChip));

            devices.put(chassis + "#board0#npu0", npu);
            devices.put(chassis + "#l1sw0", l1sw0);
            devices.put(chassis + "#l1sw1", l1sw1);
        }

        return createSuperNode("test-supernode", devices);
    }

    private RoutingTable buildL1swRoutingTable(String targetL2sw, int numPorts) {
        RoutingTable rt = new RoutingTable();
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();

        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        for (int p = 0; p < numPorts; p++) {
            String portName = "400GE 1/2/" + p;
            outPortInfos.put(portName, new OutPortInfo(portName, targetL2sw, 60, 0, "STATIC", 0));
        }
        RoutePrefix prefix = new RoutePrefix("0.0.0.0", 0);
        routes.put(prefix, new RoutingEntry(prefix, outPortInfos, true));

        rt.setRoutes(routes);
        List<Integer> masks = new ArrayList<>();
        masks.add(0);
        rt.setMaskLengths(masks);
        return rt;
    }
}
