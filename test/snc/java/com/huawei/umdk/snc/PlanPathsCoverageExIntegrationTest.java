/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: planPathsCoverageEx northbound integration test
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.CoverageLayerStats;
import com.huawei.umdk.snc.dto.CoverageLink;
import com.huawei.umdk.snc.dto.CoverageLinkLayer;
import com.huawei.umdk.snc.dto.CoverageLinkScope;
import com.huawei.umdk.snc.dto.CoveragePathType;
import com.huawei.umdk.snc.dto.CoveragePathsRequest;
import com.huawei.umdk.snc.dto.CoveragePathsResult;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.dto.CoveredEidPair;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.exception.SNCStateException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Northbound ({@link SncService#planPathsCoverageEx}) integration test, the
 * counterpart of {@link PlanPathsCoverageIntegrationTest} for the extended
 * interface.
 *
 * <p>Fixture: the full 4-rack topology produced by {@link FullRackTopologyGenerator}
 * (148 devices: 128 NPU + 16 L1SW + 4 L2SW), loaded through
 * {@link RackTopologyLoader} without any pruning. With the complete rack the
 * two-phase extended coverage runs end-to-end: phase 1 produces CROSS_L2
 * (inter-chassis) pairs that traverse the L2 spine {@code NPU -> L1SW -> L2SW
 * -> L1SW -> NPU}, and phase 2 fills the remaining NPU↔L1SW out-ports with
 * LOCAL_L1 (intra-chassis) pairs {@code NPU -> L1SW -> NPU}.
 */
@DisplayName("planPathsCoverageEx 接口集成测试（SncService 北向 + FullRackTopologyGenerator 完整 4 机框拓扑）")
class PlanPathsCoverageExIntegrationTest {

    private static final String SN_NAME = "A5-superPod-rack";

    private static SncService sncService;

    @BeforeAll
    static void setUp() throws Exception {
        // Full 4-rack topology (148 devices: 128 NPU + 16 L1SW + 4 L2SW) from
        // FullRackTopologyGenerator, loaded via RackTopologyLoader without any
        // pruning — the test exercises planPathsCoverageEx on the complete rack.
        SuperNode sn = RackTopologyLoader.loadRawTopology();

        sncService = new SncService();
        sncService.init(new SNCConfig());
        sncService.setSuperNode(sn);
    }

    @AfterAll
    static void tearDown() {
        sncService.uninit();
    }

    private static CoveragePathsRequest request(CoverageRequirement requirement) {
        CoveragePathsRequest req = new CoveragePathsRequest();
        req.setSuperNodeName(SN_NAME);
        req.setCoverageRequirement(requirement);
        return req;
    }

    /** Common assertions of an extended-coverage result on the full 4-rack topology. */
    private static void assertCoverageOk(CoveragePathsResult result, String label) {
        assertTrue(result.getStatus() == PlanStatus.SUCCESS
                || result.getStatus() == PlanStatus.COVERAGE_INCOMPLETE,
            label + ": status should be SUCCESS or COVERAGE_INCOMPLETE, was "
                + result.getStatus());
        assertEquals(CoverageLinkScope.NPU_L1_L2, result.getScope(), label);
        assertNotNull(result.getLayerStats(), label + ": layerStats");
        assertNotNull(result.getEidPairs(), label + ": eidPairs");
        assertFalse(result.getEidPairs().isEmpty(), label + ": at least one EID pair");
        assertTrue(result.getStats().getCoverageRate() > 0, label + ": coverageRate > 0");

        // Full 4-rack topology => phase 1 produces CROSS_L2 (inter-chassis) pairs
        // that traverse the L2 spine, so the L1SW↔L2SW layer carries links. Phase 2
        // fills any remaining NPU↔L1SW out-ports with LOCAL_L1 (intra-chassis)
        // pairs; when phase 1 already covers all NPU↔L1SW out-ports, phase 2 has
        // nothing to fill and produces no LOCAL_L1 pair, which is also valid.
        assertTrue(result.getLayerStats().get(CoverageLinkLayer.L1_L2)
                .getTotalLinks() > 0,
            label + ": L1SW↔L2SW links must exist in the 4-rack topology");

        boolean hasCrossL2 = false;
        for (CoveredEidPair p : result.getEidPairs()) {
            assertNotEquals(p.getSrcDevice(), p.getDestDevice(), label + ": distinct NPUs");
            CoveragePathType type = p.getType();
            if (type == CoveragePathType.CROSS_L2) {
                hasCrossL2 = true;
                assertEquals(8, p.getCoveredLinks().size(),
                    label + ": CROSS_L2 pair = 4 forward + 4 ACK links");
            } else if (type == CoveragePathType.LOCAL_L1) {
                assertEquals(4, p.getCoveredLinks().size(),
                    label + ": LOCAL_L1 pair = 2 forward + 2 ACK links");
            }
            for (CoverageLink l : p.getCoveredLinks()) {
                assertTrue(l.getLayer() == CoverageLinkLayer.NPU_L1
                        || l.getLayer() == CoverageLinkLayer.L1_L2,
                    label + ": link layer must be NPU_L1 or L1_L2");
            }
        }
        assertTrue(hasCrossL2, label + ": at least one CROSS_L2 (inter-chassis) pair");
        // LOCAL_L1 (phase 2) is optional: when phase 1's CROSS_L2 pairs already
        // cover all NPU↔L1SW out-ports, phase 2 has nothing to fill.

        // per-layer numbers add up to the aggregate ones
        int layerTotal = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getTotalLinks).sum();
        assertEquals(result.getStats().getTotalLinks().intValue(), layerTotal, label);
        int layerCovered = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getCoveredCount).sum();
        assertEquals(result.getStats().getCoveredCount().intValue(), layerCovered, label);
    }

    @Test
    @Timeout(600)
    @DisplayName("MIN_COVERAGE：北向返回完整 4 框覆盖结果（CROSS_L2 + LOCAL_L1）")
    void minCoverage() {
        CoveragePathsResult result = sncService.planPathsCoverageEx(
            request(CoverageRequirement.MIN_COVERAGE));

        assertCoverageOk(result, "MIN_COVERAGE");
        assertTrue(result.getLayerStats().get(CoverageLinkLayer.NPU_L1)
            .getCoveredCount() > 0, "MIN_COVERAGE: NPU↔L1SW out-ports must be covered");
        assertTrue(result.getLayerStats().get(CoverageLinkLayer.L1_L2)
            .getCoveredCount() > 0, "MIN_COVERAGE: L1SW↔L2SW out-ports must be covered");
    }

    @Test
    @Timeout(600)
    @DisplayName("REDUNDANT：每条被覆盖链路（NPU_L1 + L1_L2）至少被 2 个 EID 对覆盖")
    void redundant() {
        CoveragePathsResult result = sncService.planPathsCoverageEx(
            request(CoverageRequirement.REDUNDANT));

        assertCoverageOk(result, "REDUNDANT");
        for (CoverageLink l : result.getCoverageLinks()) {
            if (l.getCoverCount() == null || l.getCoverCount() == 0) continue;
            assertTrue(l.getCoverCount() >= 2,
                "REDUNDANT: covered link must have >= 2 covers, but "
                    + l.getSwitchDevice() + ":" + l.getOutPort()
                    + " has " + l.getCoverCount());
        }
    }

    @Test
    @DisplayName("未 setSuperNode（非 DATAREADY）时调用抛 SNCStateException")
    void notDataReady() {
        SncService svc = new SncService();
        svc.init(new SNCConfig());
        try {
            assertThrows(SNCStateException.class,
                () -> svc.planPathsCoverageEx(new CoveragePathsRequest()));
        } finally {
            svc.uninit();
        }
    }

    @Test
    @DisplayName("request 为 null 抛 IllegalArgumentException")
    void nullRequest() {
        assertThrows(IllegalArgumentException.class,
            () -> sncService.planPathsCoverageEx(null));
    }

    @Test
    @DisplayName("superNodeName 不存在时返回 TOPO_NOT_FOUND")
    void missingSuperNode() {
        CoveragePathsRequest req = new CoveragePathsRequest();
        req.setSuperNodeName("nonexistent");
        CoveragePathsResult result = sncService.planPathsCoverageEx(req);
        assertEquals(PlanStatus.TOPO_NOT_FOUND, result.getStatus());
    }

    @Test
    @DisplayName("uninit 后调用抛 SNCStateException")
    void afterUninit() {
        SncService svc = new SncService();
        svc.init(new SNCConfig());
        svc.uninit();
        try {
            assertThrows(SNCStateException.class,
                () -> svc.planPathsCoverageEx(request(CoverageRequirement.MIN_COVERAGE)));
        } finally {
            svc.uninit();
        }
    }

    @Test
    @DisplayName("NPU 端口缺少 jettyId 时返回 TOPO_INCOMPLETE")
    void npuPortMissingJettyId() {
        // Load the full rack topology, then null out the jettyId of one NPU
        // port to simulate an incomplete topology input.
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        String removedPort = null;
        for (DeviceEntity dev : sn.getAllDevices().values()) {
            if (dev.getDeviceType() != DeviceType.NPU || dev.getForwardingChips() == null) {
                continue;
            }
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (port instanceof NpuPortEntity npuPort
                        && npuPort.getJettyId() != null) {
                        removedPort = dev.getDeviceName() + "#" + port.getPortName();
                        npuPort.setJettyId(null);
                        break;
                    }
                }
                if (removedPort != null) break;
            }
            if (removedPort != null) break;
        }
        assertNotNull(removedPort, "fixture must have at least one NPU port with jettyId");

        SncService svc = new SncService();
        svc.init(new SNCConfig());
        svc.setSuperNode(sn);
        try {
            CoveragePathsResult result = svc.planPathsCoverageEx(
                request(CoverageRequirement.MIN_COVERAGE));
            assertEquals(PlanStatus.TOPO_INCOMPLETE, result.getStatus(),
                "missing jettyId must yield TOPO_INCOMPLETE");
            assertNotNull(result.getErrorMessage(),
                "error message must describe the missing jettyId port");
            assertTrue(result.getErrorMessage().contains(removedPort),
                "error message must mention the offending port " + removedPort
                    + ", was: " + result.getErrorMessage());
        } finally {
            svc.uninit();
        }
    }
}
