/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: plan paths coverage integration test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import java.util.Set;

import com.huawei.umdk.snc.config.SNCConfig;
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

@DisplayName("planPathsCoverage 接口集成测试（基于 rack 拓扑 2 机框子集）")
class PlanPathsCoverageIntegrationTest {

    private static final String SN_NAME = "A5-superPod-rack";

    private static SncService sncService;

    @BeforeAll
    static void setUp() throws Exception {
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        CoverageRouteAugmentor.augmentL1swRouting(sn);
        CoverageRouteAugmentor.augmentL2swRouting(sn);

        Set<String> keepNpu = new HashSet<>();
        Set<String> keepSw = new HashSet<>();
        for (int c = 1; c <= 2; c++) {
            for (int b = 1; b <= 2; b++) {
                for (int n = 1; n <= 2; n++) {
                    keepNpu.add("rack" + c + "#board" + b + "#npu" + n);
                }
            }
            for (int l = 1; l <= 4; l++) {
                keepSw.add("rack" + c + "#l1sw" + l);
            }
        }
        for (int l = 1; l <= 4; l++) {
            keepSw.add("l2sw" + l);
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

    private static void assertCoverageOk(CoveragePathsResult result, String label) {
        assertTrue(result.getStatus() == PlanStatus.SUCCESS
                || result.getStatus() == PlanStatus.COVERAGE_INCOMPLETE,
            label + ": 状态应为 SUCCESS 或 COVERAGE_INCOMPLETE，实际: " + result.getStatus());
        assertNotNull(result.getEidPairs(), label + ": eidPairs 不能为 null");
        assertFalse(result.getEidPairs().isEmpty(), label + ": 至少选择一个 EID 对");
        assertTrue(result.getStats().getCoverageRate() > 0, label + ": 覆盖率应 > 0");
        for (CoveredEidPair pair : result.getEidPairs()) {
            String srcChassis = pair.getSrcDevice().split("#")[0];
            String dstChassis = pair.getDestDevice().split("#")[0];
            assertNotEquals(srcChassis, dstChassis,
                label + ": 必须跨 chassis: " + pair.getSrcDevice() + " -> " + pair.getDestDevice());
        }
    }

    @Test
    @Timeout(300)
    @DisplayName("MIN_COVERAGE")
    void minCoverage() {
        CoveragePathsResult result = sncService.planPathsCoverage(
            request(CoverageRequirement.MIN_COVERAGE));
        assertCoverageOk(result, "MIN_COVERAGE");
    }

    @Test
    @Timeout(300)
    @DisplayName("REDUNDANT")
    void redundant() {
        CoveragePathsResult result = sncService.planPathsCoverage(
            request(CoverageRequirement.REDUNDANT));
        assertCoverageOk(result, "REDUNDANT");
    }

    @Test
    @DisplayName("未 setSuperNode（非 DATAREADY）时调用抛 SNCStateException")
    void notDataReady() {
        SncService svc = new SncService();
        svc.init(new SNCConfig());
        try {
            assertThrows(SNCStateException.class,
                () -> svc.planPathsCoverage(new CoveragePathsRequest()));
        } finally {
            svc.uninit();
        }
    }

    @Test
    @DisplayName("null 请求抛 IllegalArgumentException")
    void nullRequest() {
        assertThrows(IllegalArgumentException.class,
            () -> sncService.planPathsCoverage(null));
    }
}
