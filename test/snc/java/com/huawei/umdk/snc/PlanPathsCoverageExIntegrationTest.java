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

import java.util.HashSet;
import java.util.Set;

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
 * <p>Fixture: the topology produced by {@link FullRackTopologyGenerator}
 * (through {@link RackTopologyLoader}), pruned to a <b>single chassis</b>
 * (rack1 NPU + rack1 L1SW, no L2SW), matching the test convention that the
 * 2-chassis scenario is reserved for the old interface. With a single chassis
 * the inter-chassis (框间) phase has no usable EID pair, so the whole NPU↔L1SW
 * coverage comes from the intra-chassis (框内) phase.
 */
@DisplayName("planPathsCoverageEx 接口集成测试（SncService 北向 + 全机架生成器单机框子集）")
class PlanPathsCoverageExIntegrationTest {

    private static final String SN_NAME = "A5-superPod-rack";

    private static SncService sncService;

    @BeforeAll
    static void setUp() throws Exception {
        // Topology built by FullRackTopologyGenerator (148 devices), then pruned
        // to a single chassis: rack1 NPUs + rack1 L1SWs, no L2SW at all.
        SuperNode sn = RackTopologyLoader.loadRawTopology();

        Set<String> keepNpu = new HashSet<>();
        Set<String> keepSw = new HashSet<>();
        for (int b = 1; b <= 2; b++) {
            for (int n = 1; n <= 2; n++) {
                keepNpu.add("rack1#board" + b + "#npu" + n);
            }
        }
        for (int l = 1; l <= 4; l++) {
            keepSw.add("rack1#l1sw" + l);
        }
        sn.getNpuDevices().keySet().removeIf(k -> !keepNpu.contains(k));
        sn.getSwDevices().keySet().removeIf(k -> !keepSw.contains(k));

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

    /** Common assertions of an extended-coverage result. */
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

        // single chassis => every pair is 框内 with 2 forward + 2 ACK links, and
        // the L1SW↔L2SW layer has no link at all
        assertEquals(0, result.getLayerStats().get(CoverageLinkLayer.L1_L2)
            .getTotalLinks().intValue(), label + ": no L1SW↔L2SW links in one chassis");
        for (CoveredEidPair p : result.getEidPairs()) {
            assertEquals(CoveragePathType.LOCAL_L1, p.getType(), label + ": LOCAL_L1 pair");
            assertEquals(4, p.getCoveredLinks().size(), label + ": 2 forward + 2 ACK");
            assertNotEquals(p.getSrcDevice(), p.getDestDevice(), label + ": distinct NPUs");
            for (CoverageLink l : p.getCoveredLinks()) {
                assertEquals(CoverageLinkLayer.NPU_L1, l.getLayer(),
                    label + ": 框内 links stay in the NPU↔L1SW layer");
            }
        }

        // per-layer numbers add up to the aggregate ones
        int layerTotal = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getTotalLinks).sum();
        assertEquals(result.getStats().getTotalLinks().intValue(), layerTotal, label);
        int layerCovered = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getCoveredCount).sum();
        assertEquals(result.getStats().getCoveredCount().intValue(), layerCovered, label);
    }

    @Test
    @Timeout(300)
    @DisplayName("MIN_COVERAGE：北向返回框内覆盖结果")
    void minCoverage() {
        CoveragePathsResult result = sncService.planPathsCoverageEx(
            request(CoverageRequirement.MIN_COVERAGE));

        assertCoverageOk(result, "MIN_COVERAGE");
        assertTrue(result.getLayerStats().get(CoverageLinkLayer.NPU_L1)
            .getCoveredCount() > 0, "MIN_COVERAGE: NPU↔L1SW out-ports must be covered");
    }

    @Test
    @Timeout(300)
    @DisplayName("REDUNDANT：每条被覆盖链路至少被 2 个 EID 对覆盖")
    void redundant() {
        CoveragePathsResult result = sncService.planPathsCoverageEx(
            request(CoverageRequirement.REDUNDANT));

        assertCoverageOk(result, "REDUNDANT");
        for (CoverageLink l : result.getCoverageLinks()) {
            if (l.getLayer() != CoverageLinkLayer.NPU_L1) continue;
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
}
