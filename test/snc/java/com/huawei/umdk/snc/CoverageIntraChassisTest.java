/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: intra-chassis (框内) coverage test and report
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.huawei.umdk.snc.config.HashTuple;
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
import com.huawei.umdk.snc.engine.CoveragePlanEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutingTableKey;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.service.PathService;
import com.huawei.umdk.snc.store.SuperNodeStore;
import com.huawei.umdk.snc.util.AddressUtils;
import com.huawei.umdk.snc.util.HashUtils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Intra-chassis (框内) coverage: with a single-chassis topology there is no
 * inter-chassis pair at all, so every NPU↔L1SW out-port has to be covered by the
 * 2-hop {@code NPU -> L1SW -> NPU} path of phase 2.
 */
@DisplayName("框内通信覆盖：planPathsCoverageEx 第二阶段（NPU→L1SW→NPU）")
class CoverageIntraChassisTest {

    private static final String SN_NAME = "A5-superPod-rack";
    private static final int HASH_FUNC = 1;
    private static final String REPORT_PATH = "target/coverage-intra-chassis-report.md";

    private static SuperNode superNode;
    private static SuperNodeStore store;
    private static PathService pathService;
    private static CoveragePlanEngine engine;

    @BeforeAll
    static void setUp() throws Exception {
        SuperNode sn = RackTopologyLoader.loadRawTopology();

        // Keep a single chassis: rack1 NPUs + rack1 L1SWs, and drop every L2SW,
        // so that no inter-chassis (框间) path exists at all.
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
        superNode = sn;

        store = new SuperNodeStore();
        store.init();
        store.replace(sn);

        engine = new CoveragePlanEngine(store, HASH_FUNC, 0, 0, HashTuple.TWO);
        pathService = new PathService(store, new PathEngine(), new RouteLookupEngine(), engine);
    }

    @Test
    @Timeout(300)
    @DisplayName("单框拓扑：框间 0 对，NPU↔L1SW 覆盖率由框内 2 跳达成")
    void intraChassisCoverage() throws Exception {
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);
        request.setCoverageRequirement(CoverageRequirement.MIN_COVERAGE);

        CoveragePathsResult result = pathService.planPathsCoverageEx(request);

        assertTrue(result.getStatus() == PlanStatus.SUCCESS
                || result.getStatus() == PlanStatus.COVERAGE_INCOMPLETE,
            "status: " + result.getStatus());
        assertEquals(CoverageLinkScope.NPU_L1_L2, result.getScope());
        assertNotNull(result.getLayerStats());
        assertFalse(result.getEidPairs().isEmpty(), "intra-chassis pairs expected");

        // Single chassis: the L1SW↔L2SW layer has no link at all.
        CoverageLayerStats l1l2 = result.getLayerStats().get(CoverageLinkLayer.L1_L2);
        assertNotNull(l1l2);
        assertEquals(0, l1l2.getTotalLinks().intValue(),
            "no L1SW↔L2SW links exist in a single-chassis topology");

        CoverageLayerStats npuL1 = result.getLayerStats().get(CoverageLinkLayer.NPU_L1);
        assertNotNull(npuL1);
        assertTrue(npuL1.getTotalLinks() > 0);
        assertTrue(npuL1.getCoveredCount() > 0,
            "the intra-chassis phase must cover NPU↔L1SW out-ports");

        // every pair is an intra-chassis pair with 2 forward + 2 ACK links
        for (CoveredEidPair p : result.getEidPairs()) {
            assertEquals(CoveragePathType.LOCAL_L1, p.getType(),
                "single L1 domain => every pair is LOCAL_L1");
            assertEquals(4, p.getCoveredLinks().size(),
                "框内 pair = 2 forward + 2 ACK links");
            for (CoverageLink l : p.getCoveredLinks()) {
                assertEquals(CoverageLinkLayer.NPU_L1, l.getLayer(),
                    "框内 path must not touch the L1SW↔L2SW layer");
            }
        }

        // per-layer totals must add up to the aggregate ones
        int layerTotal = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getTotalLinks).sum();
        assertEquals(result.getStats().getTotalLinks().intValue(), layerTotal,
            "sum(layerStats.totalLinks) == stats.totalLinks");
        int layerCovered = result.getLayerStats().values().stream()
            .mapToInt(CoverageLayerStats::getCoveredCount).sum();
        assertEquals(result.getStats().getCoveredCount().intValue(), layerCovered,
            "sum(layerStats.coveredCount) == stats.coveredCount");

        // requirement 1/3: CRC8 NPU egress + SCNA chaining, verified end to end
        CoveredEidPair sample = result.getEidPairs().get(0);
        verifyForwardIntraChain(sample);
        verifyAckIntraChain(sample);

        writeReport(result);
    }

    // ------------------------------------------------------------------
    //  Verification of the 框内 2-hop chain (CRC8 + SCNA chaining)
    // ------------------------------------------------------------------

    private static PortEntity portOf(DeviceEntity dev, String portName) {
        if (dev == null || dev.getForwardingChips() == null) return null;
        for (ForwardingChip chip : dev.getForwardingChips().values()) {
            if (chip.getPorts() != null && chip.getPorts().containsKey(portName)) {
                return chip.getPorts().get(portName);
            }
        }
        return null;
    }

    private static Integer chipIndexOfPort(DeviceEntity dev, String portName) {
        if (dev == null || dev.getForwardingChips() == null) return null;
        for (ForwardingChip chip : dev.getForwardingChips().values()) {
            if (chip.getPorts() != null && chip.getPorts().containsKey(portName)) {
                return chip.getChipIndex();
            }
        }
        return null;
    }

    private static int jettyIdOf(DeviceEntity dev, String portName) {
        PortEntity p = portOf(dev, portName);
        if (p instanceof NpuPortEntity) {
            Integer jettyId = ((NpuPortEntity) p).getJettyId();
            if (jettyId != null && HashUtils.isValidJettyId(jettyId)) {
                return jettyId;
            }
        }
        return HashUtils.JETTY_ID_MIN + (p == null || p.getId() == null ? 0 : p.getId());
    }

    /** L1SW-facing out-ports of an NPU route, in route iteration order. */
    private static List<String> npuUplinkMembers(DeviceEntity npu, int chipIdx, String dstCna,
                                                 Map<String, DeviceEntity> devices,
                                                 SuperNodeStore store) {
        List<String> members = new ArrayList<>();
        RoutingEntry entry = lookupRoute(store, npu.getDeviceName(), chipIdx, dstCna);
        if (entry == null || entry.getOutPortInfos() == null) return members;
        ForwardingChip chip = npu.getForwardingChips().get(chipIdx);
        for (OutPortInfo opi : entry.getOutPortInfos().values()) {
            PortEntity p = chip.getPorts().get(opi.getPortName());
            if (p == null || p.getRemoteDevice() == null) continue;
            DeviceEntity remote = devices.get(p.getRemoteDevice());
            if (remote != null && remote.getDeviceType() == DeviceType.SW) {
                members.add(p.getPortName());
            }
        }
        return members;
    }

    /** L1SW out-ports towards {@code deviceName}, from a route. */
    private static List<String> l1PortsTowards(ForwardingChip chip, RoutingEntry route,
                                               String deviceName) {
        List<String> ports = new ArrayList<>();
        if (chip == null || chip.getPorts() == null || route == null
            || route.getOutPortInfos() == null) {
            return ports;
        }
        for (OutPortInfo opi : route.getOutPortInfos().values()) {
            PortEntity pe = chip.getPorts().get(opi.getPortName());
            if (pe != null && deviceName.equals(pe.getRemoteDevice())) {
                ports.add(opi.getPortName());
            }
        }
        return ports;
    }

    /** Same LPM lookup the engine uses: mask lengths descending, then default. */
    private static RoutingEntry lookupRoute(SuperNodeStore store, String deviceName,
                                            int chipIndex, String targetCna) {
        RoutingTable rt = store.getRoutingTable(
            new RoutingTableKey(SN_NAME, deviceName, chipIndex));
        if (rt == null || rt.getRoutes() == null) return null;
        if (rt.getMaskLengths() != null) {
            for (int maskLen : rt.getMaskLengths()) {
                String net = maskLen == 32 ? targetCna
                    : AddressUtils.applyMask(targetCna, maskLen);
                RoutingEntry e = rt.getRoutes().get(new RoutePrefix(net, maskLen));
                if (e != null) return e;
            }
        }
        return rt.getRoutes().get(new RoutePrefix("0.0.0.0", 0));
    }

    /**
     * Requirement 1/3 verification: the forward NPU egress equals the CRC8
     * {@code (DstCNA, jettyId)} selection and the CNA of that selected port
     * drives the L1SW→NPU hash of the second hop.
     */
    private void verifyForwardIntraChain(CoveredEidPair pair) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        DeviceEntity srcNpu = devices.get(pair.getSrcDevice());
        Integer srcChipIdx = chipIndexOfPort(srcNpu, pair.getSrcPort());
        assertNotNull(srcChipIdx, "source NPU chip must be resolvable");

        int jettyId = jettyIdOf(srcNpu, pair.getSrcPort());
        List<String> members = npuUplinkMembers(srcNpu, srcChipIdx, pair.getDstCna(),
            devices, store);
        assertFalse(members.isEmpty(), "NPU uplink members must not be empty");
        int idx = HashUtils.nativeHashDstCnaJetty(AddressUtils.ipToInt(pair.getDstCna()), jettyId,
            members.size(), HASH_FUNC, 1);

        CoverageLink hop1 = pair.getCoveredLinks().get(0);
        assertEquals(srcNpu.getDeviceName(), hop1.getSwitchDevice());
        assertEquals(members.get(idx), hop1.getOutPort(),
            "框内 forward NPU egress must equal the CRC8 (DstCNA, jettyId) selection");
        assertEquals("NPU", hop1.getDeviceType());
        assertEquals(CoverageLinkLayer.NPU_L1, hop1.getLayer());

        PortEntity selected = portOf(srcNpu, members.get(idx));
        assertNotNull(selected.getCna(), "selected NPU port must carry a CNA");
        String scna = selected.getCna();
        DeviceEntity l1 = devices.get(selected.getRemoteDevice());
        PortEntity l1In = portOf(l1, selected.getRemotePort());
        RoutingEntry route = lookupRoute(store, l1.getDeviceName(),
            l1In.getChipIndex(), pair.getDstCna());
        List<String> ports = l1PortsTowards(
            l1.getForwardingChips().get(l1In.getChipIndex()), route, pair.getDestDevice());
        assertFalse(ports.isEmpty(), "destination L1SW must have ports towards the NPU");
        int idx2 = HashUtils.nativeHash(pair.getDstCna(), scna, ports.size(), HASH_FUNC);

        CoverageLink hop2 = pair.getCoveredLinks().get(1);
        assertEquals(l1.getDeviceName(), hop2.getSwitchDevice());
        assertEquals(ports.get(idx2), hop2.getOutPort(),
            "框内 second hop must hash the selected NPU port CNA as SCNA");
    }

    /**
     * ACK direction: the destination NPU hashes (srcCna, source NPU port's
     * jettyId) — the jettyId is the source port's, not the destination port's.
     */
    private void verifyAckIntraChain(CoveredEidPair pair) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        DeviceEntity dstNpu = devices.get(pair.getDestDevice());
        Integer dstChipIdx = chipIndexOfPort(dstNpu, pair.getDestPort());
        assertNotNull(dstChipIdx, "destination NPU chip must be resolvable");

        // ACK egress uses the SOURCE NPU port's jettyId (same as forward).
        DeviceEntity srcNpuForJetty = devices.get(pair.getSrcDevice());
        assertNotNull(srcNpuForJetty, "source NPU must be resolvable for ACK jettyId");
        int jettyId = jettyIdOf(srcNpuForJetty, pair.getSrcPort());
        List<String> members = npuUplinkMembers(dstNpu, dstChipIdx, pair.getSrcCna(),
            devices, store);
        assertFalse(members.isEmpty());
        int idx = HashUtils.nativeHashDstCnaJetty(AddressUtils.ipToInt(pair.getSrcCna()), jettyId,
            members.size(), HASH_FUNC, 1);

        CoverageLink ackHop1 = pair.getCoveredLinks().get(2);
        assertEquals(dstNpu.getDeviceName(), ackHop1.getSwitchDevice());
        assertEquals(members.get(idx), ackHop1.getOutPort(),
            "框内 ACK NPU egress must equal CRC8 (srcCna, source jettyId)");

        // the ACK SCNA (CNA of the destination NPU selected port) drives the last hop
        PortEntity ackSelected = portOf(dstNpu, members.get(idx));
        String scnaRev = ackSelected.getCna();
        DeviceEntity srcNpu = devices.get(pair.getSrcDevice());
        PortEntity srcPort = portOf(srcNpu, pair.getSrcPort());
        DeviceEntity srcL1 = devices.get(srcPort.getRemoteDevice());
        PortEntity srcL1In = portOf(srcL1, srcPort.getRemotePort());
        RoutingEntry route = lookupRoute(store, srcL1.getDeviceName(),
            srcL1In.getChipIndex(), pair.getSrcCna());
        List<String> ports = l1PortsTowards(
            srcL1.getForwardingChips().get(srcL1In.getChipIndex()), route,
            pair.getSrcDevice());
        assertFalse(ports.isEmpty());
        int idx3 = HashUtils.nativeHash(pair.getSrcCna(), scnaRev, ports.size(), HASH_FUNC);

        CoverageLink ackLast = pair.getCoveredLinks().get(3);
        assertEquals(srcL1.getDeviceName(), ackLast.getSwitchDevice());
        assertEquals(ports.get(idx3), ackLast.getOutPort(),
            "框内 ACK last hop must hash the destination NPU selected port CNA as SCNA");
    }

    private void writeReport(CoveragePathsResult result) throws Exception {
        CoverageLayerStats npuL1 = result.getLayerStats().get(CoverageLinkLayer.NPU_L1);
        StringBuilder sb = new StringBuilder();
        sb.append("# SNC 框内（NPU→L1SW→NPU）覆盖率测试报告\n\n");
        sb.append("> 单框拓扑（rack1：4 NPU + 4 L1SW，无 L2SW）：框间阶段无可用 EID 对，")
          .append("全部 NPU↔L1SW 出端口由**框内 2 跳**覆盖；NPU→L1 选口使用 ")
          .append("CRC-8/ATM 的 `(DstCNA, jettyId)` 二元组 hash。\n\n");
        sb.append("| 项 | 值 |\n|:---|:---|\n");
        sb.append("| status | ").append(result.getStatus()).append(" |\n");
        sb.append("| EID 对数（框内） | ").append(result.getEidPairs().size()).append(" |\n");
        sb.append("| NPU_L1 链路 / 已覆盖 | ").append(npuL1.getTotalLinks())
          .append(" / ").append(npuL1.getCoveredCount()).append(" |\n");
        sb.append("| NPU_L1 覆盖率 | ")
          .append(String.format("%.2f%%", npuL1.getCoverageRate() * 100)).append(" |\n");
        sb.append("| L1_L2 链路 | ").append(result.getLayerStats()
            .get(CoverageLinkLayer.L1_L2).getTotalLinks()).append(" |\n\n");

        CoveredEidPair sample = result.getEidPairs().get(0);
        sb.append("## 框内流程示例（2 正向 + 2 ACK）\n\n");
        sb.append("- 源 NPU `").append(sample.getSrcDevice()).append("` 端口 `")
          .append(sample.getSrcPort()).append("`（EID `").append(sample.getSrcEid())
          .append("`，CNA `").append(sample.getSrcCna()).append("`）\n");
        sb.append("- 目的 NPU `").append(sample.getDestDevice()).append("` 端口 `")
          .append(sample.getDestPort()).append("`（EID `").append(sample.getDstEid())
          .append("`，CNA `").append(sample.getDstCna()).append("`）\n\n");
        sb.append("| # | 方向 | 设备 | 出端口 | 对端 | 对端端口 | layer | deviceType |\n");
        sb.append("|--:|:---|:---|:---|:---|:---|:---|:---|\n");
        List<CoverageLink> links = sample.getCoveredLinks();
        for (int i = 0; i < links.size(); i++) {
            CoverageLink l = links.get(i);
            sb.append("| ").append(i).append(" | ").append(i < 2 ? "forward" : "ACK")
              .append(" | ").append(l.getSwitchDevice())
              .append(" | ").append(l.getOutPort())
              .append(" | ").append(l.getRemoteSwitch())
              .append(" | ").append(l.getRemotePort())
              .append(" | ").append(l.getLayer())
              .append(" | ").append(l.getDeviceType()).append(" |\n");
        }
        sb.append("\n## 引擎诊断\n\n| 计数 | 值 |\n|:---|--:|\n");
        for (Map.Entry<String, Integer> e : engine.getExDiagnostics().entrySet()) {
            sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()).append(" |\n");
        }

        sb.append("\n## 选路 hash 校验证据（CRC8 + SCNA 链接）\n\n");
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        DeviceEntity srcNpu = devices.get(sample.getSrcDevice());
        int srcChip = chipIndexOfPort(srcNpu, sample.getSrcPort());
        int srcJetty = jettyIdOf(srcNpu, sample.getSrcPort());
        List<String> upMembers = npuUplinkMembers(srcNpu, srcChip, sample.getDstCna(),
            devices, store);
        int srcIdx = HashUtils.nativeHashDstCnaJetty(AddressUtils.ipToInt(sample.getDstCna()), srcJetty,
            upMembers.size(), HASH_FUNC, 1);
        sb.append("| 项 | 值 |\n|:---|:---|\n");
        sb.append("| 正向 NPU→L1 ECMP 成员集 | ").append(upMembers)
          .append("（size=").append(upMembers.size()).append("） |\n");
        sb.append("| 正向 jettyId / DstCNA | ").append(srcJetty).append(" / ")
          .append(sample.getDstCna()).append(" |\n");
        sb.append("| CRC8 选中索引 / 出端口 | ").append(srcIdx).append(" / ")
          .append(upMembers.get(srcIdx)).append(" |\n");
        sb.append("| 选中端口 CNA（→ SCNA） | ")
          .append(portOf(srcNpu, upMembers.get(srcIdx)).getCna()).append(" |\n");
        sb.append("| 实际报告的第 0 跳出端口 | ")
          .append(sample.getCoveredLinks().get(0).getOutPort()).append(" |\n");
        sb.append("\n> `coveredLinks[0].outPort`（真实出口）与 `srcPort`（端点身份）可以不同：")
          .append("EID/CNA 只标识端点身份，真实出口由 CRC8 `(DstCNA, jettyId)` 决定。\n");
        sb.append("\n> **ACK 方向**：NPU 选口的 jettyId = **源端口 jettyId**（与正向同一），")
          .append("DstCNA = 源 CNA。即正反向共享 jettyId 熵源。\n");

        String markdown = sb.toString();
        System.out.println(markdown);
        File report = new File(REPORT_PATH);
        File parent = report.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create report directory: " + parent);
        }
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(report), StandardCharsets.UTF_8)) {
            w.write(markdown);
        }
        System.out.println("[coverage-report] intra-chassis report written to "
            + report.getAbsolutePath());
    }
}
