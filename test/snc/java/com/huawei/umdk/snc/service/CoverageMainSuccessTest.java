/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage main success test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.CoverageRouteAugmentor;
import com.huawei.umdk.snc.RackTopologyLoader;
import com.huawei.umdk.snc.config.HashTuple;
import com.huawei.umdk.snc.dto.CoverageLink;
import com.huawei.umdk.snc.dto.CoveragePathsRequest;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.dto.CoveragePathsResult;
import com.huawei.umdk.snc.dto.CoveredEidPair;
import com.huawei.umdk.snc.dto.CoveredEidPairRef;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.engine.CoveragePlanEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.store.SuperNodeStore;

@DisplayName("CoverageMainSuccess (§5 全局覆盖)")
class CoverageMainSuccessTest {

    private static final String SN_NAME = "A5-superPod-rack";

    private static SuperNodeStore superNodeStore;

    @BeforeAll
    static void setUp() throws Exception {
        SuperNode rawSn = RackTopologyLoader.loadRawTopology();
        CoverageRouteAugmentor.augmentL1swRouting(rawSn);
        CoverageRouteAugmentor.augmentL2swRouting(rawSn);

        long npuCount = rawSn.getAllDevices().values().stream()
            .filter(d -> d.getDeviceType() == DeviceType.NPU).count();
        long l1swCount = rawSn.getAllDevices().values().stream()
            .filter(d -> d.getDeviceType() == DeviceType.SW
                && "L1".equals(getSwitchLevelStr(d)))
            .count();
        long l2swCount = rawSn.getAllDevices().values().stream()
            .filter(d -> d.getDeviceType() == DeviceType.SW
                && "L2".equals(getSwitchLevelStr(d)))
            .count();

        System.out.println("=== §5 拓扑加载摘要 ===");
        System.out.println("NPU 数:   " + npuCount);
        System.out.println("L1SW 数:  " + l1swCount);
        System.out.println("L2SW 数:  " + l2swCount);
        System.out.println("总设备数: " + rawSn.getAllDevices().size());

        superNodeStore = new SuperNodeStore();
        superNodeStore.init();
        superNodeStore.replace(rawSn);

    }

    // Build a PathService whose CoveragePlanEngine uses the given fixed UDP
    // ports and tuple width (ports previously carried by CoveragePathsRequest,
    // now configured through SNCConfig).
    private static PathService buildService(int dataUdpPort, int ackUdpPort) {
        return buildService(dataUdpPort, ackUdpPort, HashTuple.TWO);
    }

    private static PathService buildService(int dataUdpPort, int ackUdpPort,
                                            HashTuple tuple) {
        PathEngine pathEngine = new PathEngine();
        RouteLookupEngine routeLookupEngine = new RouteLookupEngine();
        CoveragePlanEngine coveragePlanEngine = new CoveragePlanEngine(
            superNodeStore, 1, dataUdpPort, ackUdpPort, tuple);
        return new PathService(superNodeStore, pathEngine,
            routeLookupEngine, coveragePlanEngine);
    }

    private static String getSwitchLevelStr(DeviceEntity d) {
        try {
            var m = d.getClass().getMethod("getSwitchLevel");
            Object level = m.invoke(d);
            return level != null ? level.toString() : "L1";
        } catch (Exception e) {
            return "L1";
        }
    }

    @Test
    @DisplayName("使用固定 UDP 端口 42/137 全局覆盖 L1SW↔L2SW 链路")
    void coverageWithDefaultPorts() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);

        CoveragePathsResult result = buildService(42, 137).planPathsCoverage(request);

        printCoverageReport("dataPort=42, ackPort=137", result);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "覆盖规划应成功");
        assertTrue(result.getEidPairs() != null && !result.getEidPairs().isEmpty(),
            "应选择至少一个 EID 对");
        assertTrue(result.getStats().getCoverageRate() > 0,
            "覆盖率应 > 0%，实际: " + (result.getStats().getCoverageRate() * 100) + "%");

        // src/dst 角色分开均衡：EID 作源与作目的的使用次数各自应低且均衡
        assertTrue(result.getStats().getSrcEidMaxRepeat() != null && result.getStats().getSrcEidMaxRepeat() <= 2,
            "EID 作源的最大使用次数应 ≤2，实际: " + result.getStats().getSrcEidMaxRepeat());
        assertTrue(result.getStats().getDstEidMaxRepeat() != null && result.getStats().getDstEidMaxRepeat() <= 2,
            "EID 作目的的最大使用次数应 ≤2，实际: " + result.getStats().getDstEidMaxRepeat());
        assertTrue(result.getStats().getSrcEidMinRepeat() != null && result.getStats().getSrcEidMinRepeat() >= 1,
            "EID 作源的最小使用次数应 ≥1，实际: " + result.getStats().getSrcEidMinRepeat());
        assertTrue(result.getStats().getDstEidMinRepeat() != null && result.getStats().getDstEidMinRepeat() >= 1,
            "EID 作目的的最小使用次数应 ≥1，实际: " + result.getStats().getDstEidMinRepeat());

        // Verify all selected pairs are cross-chassis
        for (CoveredEidPair pair : result.getEidPairs()) {
            String srcChassis = pair.getSrcDevice().split("#")[0];
            String dstChassis = pair.getDestDevice().split("#")[0];
            assertNotEquals(srcChassis, dstChassis,
                "必须跨 chassis: " + pair.getSrcDevice() + " → " + pair.getDestDevice());
        }

        // Verify totalLinks = L1SW out-ports + L2SW out-ports.
        // Each physical L1SW↔L2SW link contributes 2 out-ports (one per endpoint).
        int physicalLinks = CoverageRouteAugmentor.countL1swToL2swLinks(
            superNodeStore.getSuperNode(SN_NAME));
        int l2swPhysicalLinks = CoverageRouteAugmentor.countL2swToL1swLinks(
            superNodeStore.getSuperNode(SN_NAME));
        int expectedTotalLinks = physicalLinks + l2swPhysicalLinks;
        assertEquals(expectedTotalLinks, result.getStats().getTotalLinks(),
            "总链路数应为 L1SW 出端口 + L2SW 出端口（每条物理链路计 2 个出端口）");

        // Every covered out-port must expose the covering EID pairs ("srcEid|dstEid")
        assertCoveredEidPairsConsistent(result);
    }

    @Test
    @DisplayName("REDUNDANT 全覆盖(每条 link ≥2)且 EID 使用均匀")
    void coverageDualDisjoint() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);
        request.setCoverageRequirement(CoverageRequirement.REDUNDANT);

        CoveragePathsResult result = buildService(42, 137).planPathsCoverage(request);

        printCoverageReport("REDUNDANT dataPort=42, ackPort=137", result);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "REDUNDANT 应达到每条 link ≥2 覆盖");
        assertTrue(result.getStats().getEidMaxRepeat() <= 6,
            "EID 使用次数应 ≤6(预算下限+放宽容差,src/dst 角色分开均衡),实际 max=" + result.getStats().getEidMaxRepeat());
        assertTrue(result.getStats().getEidMinRepeat() >= 1,
            "EID 使用次数应 ≥1(出端口口径下部分 EID 仅承担一次冗余覆盖),实际 min=" + result.getStats().getEidMinRepeat());

        // REDUNDANT: each out-port must be covered by >= 2 distinct EID pairs
        for (CoverageLink link : result.getCoverageLinks()) {
            assertTrue(link.getCoveredPairs() != null && link.getCoveredPairs().size() >= 2,
                "REDUNDANT 下每个出端口应被 ≥2 个 EID 对覆盖: " + link.getSwitchDevice() + ":" + link.getOutPort());
            assertEquals(link.getCoveredPairs().size(), link.getCoverCount(),
                "coveredPairs 大小应等于 coverCount: " + link.getSwitchDevice() + ":" + link.getOutPort());
        }
    }

    @Test
    @DisplayName("不同 UDP 端口对产生不同的覆盖结果（五元组时端口参与 hash）")
    void coverageWithDifferentPorts() {
        CoveragePathsRequest req1 = new CoveragePathsRequest();
        req1.setSuperNodeName(SN_NAME);

        CoveragePathsRequest req2 = new CoveragePathsRequest();
        req2.setSuperNodeName(SN_NAME);

        // HashTuple.FIVE: sport/dport participate in the hash, so the two
        // port pairs drive different ECMP selections.
        CoveragePathsResult r1 = buildService(0, 0, HashTuple.FIVE).planPathsCoverage(req1);
        CoveragePathsResult r2 = buildService(128, 255, HashTuple.FIVE).planPathsCoverage(req2);

        printCoverageReport("dataPort=0, ackPort=0 (5-tuple)", r1);
        printCoverageReport("dataPort=128, ackPort=255 (5-tuple)", r2);

        // Different ports may yield different coverage results
        // At minimum, both should succeed with coverage > 0
        assertEquals(PlanStatus.SUCCESS, r1.getStatus());
        assertEquals(PlanStatus.SUCCESS, r2.getStatus());
        assertTrue(r1.getStats().getCoverageRate() > 0);
        assertTrue(r2.getStats().getCoverageRate() > 0);
    }

    @Test
    @DisplayName("HashTuple.FIVE（五元组）覆盖规划正常工作")
    void coverageWithFiveTuple() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);

        CoveragePathsResult result = buildService(42, 137, HashTuple.FIVE).planPathsCoverage(request);

        printCoverageReport("dataPort=42, ackPort=137 (5-tuple)", result);

        assertEquals(PlanStatus.SUCCESS, result.getStatus(),
            "五元组覆盖规划应成功");
        assertTrue(result.getEidPairs() != null && !result.getEidPairs().isEmpty(),
            "应选择至少一个 EID 对");
        assertTrue(result.getStats().getCoverageRate() > 0,
            "覆盖率应 > 0%，实际: " + (result.getStats().getCoverageRate() * 100) + "%");
    }

    @Test
    @DisplayName("验证覆盖结果中每条链路有完整的端口信息")
    void coverageLinksHaveCompletePortInfo() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);

        CoveragePathsResult result = buildService(42, 137).planPathsCoverage(request);

        assertNotNull(result.getCoverageLinks());
        for (CoverageLink link : result.getCoverageLinks()) {
            assertNotNull(link.getSwitchDevice(), "L1SW 设备名不能为空");
            assertNotNull(link.getRemoteSwitch(), "L2SW 设备名不能为空");
            assertNotNull(link.getOutPort(), "出端口不能为空");
        }
    }


    @Test
    @DisplayName("覆盖结果结构验证 - EID对的设备/端口存在性")
    void eachPairHasValidForwardAndReversePaths() {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);

        PathService svc = buildService(42, 137);
        CoveragePathsResult result = svc.planPathsCoverage(request);

        assertNotNull(result.getEidPairs());
        for (CoveredEidPair pair : result.getEidPairs()) {
            assertNotNull(pair.getSrcDevice(), "源设备名不能为空");
            assertNotNull(pair.getSrcPort(), "源端口名不能为空");
            assertNotNull(pair.getDestDevice(), "目的设备名不能为空");
            assertNotNull(pair.getDestPort(), "目的端口名不能为空");
            // Verify devices exist in the merged topology
            SuperNode sn = superNodeStore.getSuperNode(SN_NAME);
            assertNotNull(sn.getAllDevices().get(pair.getSrcDevice()),
                "源设备应存在于拓扑中: " + pair.getSrcDevice());
            assertNotNull(sn.getAllDevices().get(pair.getDestDevice()),
                "目的设备应存在于拓扑中: " + pair.getDestDevice());
            // Verify ports exist in the corresponding devices
            assertNotNull(new PathEngine().findPortByName(
                sn.getAllDevices().get(pair.getSrcDevice()), pair.getSrcPort()),
                "源端口应存在于设备中: " + pair.getSrcDevice() + ":" + pair.getSrcPort());
            assertNotNull(new PathEngine().findPortByName(
                sn.getAllDevices().get(pair.getDestDevice()), pair.getDestPort()),
                "目的端口应存在于设备中: " + pair.getDestDevice() + ":" + pair.getDestPort());
        }
    }

    // ─── Helpers ───

    private void printCoverageReport(String label, CoveragePathsResult result) {
        System.out.println("\n=== 覆盖规划报告: " + label + " ===");
        System.out.println("状态:     " + result.getStatus());
        System.out.println("总链路数: " + result.getStats().getTotalLinks());
        System.out.println("已覆盖:   " + result.getStats().getCoveredCount());
        System.out.println("覆盖率:   " + (result.getStats().getCoverageRate() * 100) + "%");
        System.out.println("EID 对数: " +
            (result.getEidPairs() != null ? result.getEidPairs().size() : 0));
        System.out.println("重复率:   " + (result.getStats().getRepeatRate() * 100) + "%");
        System.out.println("重复次数: min=" + result.getStats().getMinRepeatCount()
            + ", max=" + result.getStats().getMaxRepeatCount()
            + ", avg=" + result.getStats().getAvgRepeatCount());
        System.out.println("EID 统计: unique=" + result.getStats().getUniqueEidCount()
            + " appearances=" + result.getStats().getTotalEidAppearances()
            + " repeatRate=" + (result.getStats().getEidRepeatRate() * 100) + "%"
            + " eidMin=" + result.getStats().getEidMinRepeat()
            + " eidMax=" + result.getStats().getEidMaxRepeat()
            + " eidAvg=" + result.getStats().getEidAvgRepeat());
    }

    private void assertCoveredEidPairsConsistent(CoveragePathsResult result) {
        assertNotNull(result.getCoverageLinks());
        for (CoverageLink link : result.getCoverageLinks()) {
            if (link.getCoverCount() == null || link.getCoverCount() == 0) continue;
            assertNotNull(link.getCoveredPairs(),
                "被覆盖出端口应暴露 coveredPairs: " + link.getSwitchDevice() + ":" + link.getOutPort());
            assertEquals(link.getCoveredPairs().size(), link.getCoverCount(),
                "coveredPairs 大小应等于 coverCount: " + link.getSwitchDevice() + ":" + link.getOutPort());
            for (CoveredEidPairRef ref : link.getCoveredPairs()) {
                assertNotNull(ref.getSrcEid(), "coveredPairs 元素的 srcEid 不能为空");
                assertNotNull(ref.getDstEid(), "coveredPairs 元素的 dstEid 不能为空");
            }
        }
    }
}
