/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: full 4-chassis rack coverage report for planPathsCoverageEx
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Map;

import com.huawei.umdk.snc.RackTopologyLoader;
import com.huawei.umdk.snc.config.HashTuple;
import com.huawei.umdk.snc.dto.CoverageLayerStats;
import com.huawei.umdk.snc.dto.CoverageLink;
import com.huawei.umdk.snc.dto.CoverageLinkLayer;
import com.huawei.umdk.snc.dto.CoveragePathType;
import com.huawei.umdk.snc.dto.CoveragePathsRequest;
import com.huawei.umdk.snc.dto.CoveragePathsResult;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.dto.CoveredEidPair;
import com.huawei.umdk.snc.engine.CoveragePlanEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.store.SuperNodeStore;

/**
 * Runs {@code planPathsCoverageEx} on the <b>full 4-chassis rack topology</b>
 * produced by {@link com.huawei.umdk.snc.FullRackTopologyGenerator} and writes a
 * Markdown coverage report.
 *
 * <pre>
 * mvn -o -DskipTests test-compile
 * java -Xmx6g -Djna.library.path=&lt;resources&gt; -cp &lt;cp&gt; \
 *      com.huawei.umdk.snc.service.CoverageExRackReport [MIN_COVERAGE|REDUNDANT] [out.md]
 * </pre>
 */
public final class CoverageExRackReport {

    private CoverageExRackReport() {
    }

    public static void main(String[] args) throws Exception {
        String requirementName = args.length >= 1 ? args[0] : "MIN_COVERAGE";
        String outPath = args.length >= 2 ? args[1] : "target/coverage-rack4-report.md";

        System.out.println("Loading full rack topology (4 chassis, 148 devices) ...");
        long tLoad = System.currentTimeMillis();
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        System.out.println("  topology ready in " + (System.currentTimeMillis() - tLoad) + " ms");

        SuperNodeStore store = new SuperNodeStore();
        store.init();
        store.replace(sn);

        CoveragePlanEngine engine = new CoveragePlanEngine(store, 1, 0, 0, HashTuple.TWO);
        PathService pathService = new PathService(store, new PathEngine(),
            new RouteLookupEngine(), engine);

        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(sn.getName());
        request.setCoverageRequirement(CoverageRequirement.valueOf(requirementName));

        System.out.println("Running planPathsCoverageEx (" + requirementName + ") ...");
        long t0 = System.currentTimeMillis();
        CoveragePathsResult result = pathService.planPathsCoverageEx(request);
        long elapsedMs = System.currentTimeMillis() - t0;
        System.out.println("  planning done in " + elapsedMs + " ms, status="
            + result.getStatus());

        String markdown = buildReport(sn, result, requirementName, elapsedMs, engine);
        System.out.println(markdown);

        File report = new File(outPath);
        File parent = report.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create report dir: " + parent);
        }
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(report), StandardCharsets.UTF_8)) {
            w.write(markdown);
        }
        System.out.println("[coverage-report] written to " + report.getAbsolutePath());
    }

    private static String buildReport(SuperNode sn, CoveragePathsResult result,
                                      String requirement, long elapsedMs,
                                      CoveragePlanEngine engine) {
        Map<String, DeviceEntity> devices = sn.getAllDevices();
        long npuCount = devices.values().stream()
            .filter(d -> d.getDeviceType() == DeviceType.NPU).count();
        long swCount = devices.values().stream()
            .filter(d -> d.getDeviceType() == DeviceType.SW).count();

        Map<CoveragePathType, Integer> pairsByType = new EnumMap<>(CoveragePathType.class);
        Map<CoveragePathType, Integer> linksByType = new EnumMap<>(CoveragePathType.class);
        for (CoveredEidPair p : result.getEidPairs()) {
            CoveragePathType t = p.getType() == null
                ? CoveragePathType.CROSS_L2 : p.getType();
            pairsByType.merge(t, 1, Integer::sum);
            linksByType.merge(t,
                p.getCoveredLinks() == null ? 0 : p.getCoveredLinks().size(), Integer::sum);
        }

        Map<CoverageLinkLayer, Integer> coveredByLayer =
            new EnumMap<>(CoverageLinkLayer.class);
        for (CoverageLink l : result.getCoverageLinks()) {
            if (l.getCoverCount() != null && l.getCoverCount() > 0) {
                coveredByLayer.merge(l.getLayer(), 1, Integer::sum);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# SNC planPathsCoverageEx 全机架（4 框）覆盖率测试报告\n\n");
        sb.append("> 拓扑：`FullRackTopologyGenerator` 生成的完整 4 框机架（")
          .append(devices.size()).append(" 设备 = ").append(npuCount).append(" NPU + ")
          .append(swCount).append(" SW）；覆盖要求 **").append(requirement)
          .append("**；NPU→L1 选口 CRC-8/ATM `(DstCNA, jettyId)`。\n\n");
        sb.append("| 项 | 值 |\n|:---|:---|\n");
        sb.append("| 规划耗时 | ").append(elapsedMs).append(" ms |\n");
        sb.append("| status | **").append(result.getStatus()).append("** |\n");
        sb.append("| coverageRate | **")
          .append(pct(result.getStats().getCoverageRate())).append("** |\n");
        sb.append("| totalLinks / coveredCount | ").append(result.getStats().getTotalLinks())
          .append(" / ").append(result.getStats().getCoveredCount()).append(" |\n");
        sb.append("| EID 对数 | ").append(result.getEidPairs().size())
          .append("（CROSS_L2 ").append(pairsByType.getOrDefault(CoveragePathType.CROSS_L2, 0))
          .append(" / LOCAL_L1 ").append(pairsByType.getOrDefault(CoveragePathType.LOCAL_L1, 0))
          .append("） |\n");
        sb.append("| 覆盖链路条目 | ").append(result.getCoverageLinks().size()).append(" |\n");
        sb.append("| 重复次数 min/max/avg | ").append(result.getStats().getMinRepeatCount())
          .append(" / ").append(result.getStats().getMaxRepeatCount())
          .append(" / ").append(result.getStats().getAvgRepeatCount()).append(" |\n");
        sb.append("| EID unique/appearances | ").append(result.getStats().getUniqueEidCount())
          .append(" / ").append(result.getStats().getTotalEidAppearances()).append(" |\n");
        if (result.getErrorMessage() != null) {
            sb.append("| errorMessage | ").append(result.getErrorMessage()).append(" |\n");
        }
        sb.append('\n');

        sb.append("## 1. 分层覆盖率\n\n");
        sb.append("| 层 | totalLinks | coveredCount | coverageRate | min | max | avg | repeatRate |\n");
        sb.append("|:---|--:|--:|--:|--:|--:|--:|--:|\n");
        for (CoverageLinkLayer layer : CoverageLinkLayer.values()) {
            CoverageLayerStats s = result.getLayerStats().get(layer);
            if (s == null) continue;
            sb.append("| ").append(layer).append(" | ").append(s.getTotalLinks())
              .append(" | ").append(s.getCoveredCount())
              .append(" | ").append(pct(s.getCoverageRate()))
              .append(" | ").append(s.getMinRepeatCount())
              .append(" | ").append(s.getMaxRepeatCount())
              .append(" | ").append(s.getAvgRepeatCount())
              .append(" | ").append(pct(s.getRepeatRate())).append(" |\n");
        }
        sb.append('\n');

        sb.append("## 2. 覆盖类型分布\n\n");
        sb.append("| 类型 | EID 对数 | 覆盖链路条目数 |\n|:---|--:|--:|\n");
        for (CoveragePathType t : CoveragePathType.values()) {
            sb.append("| ").append(t).append(" | ")
              .append(pairsByType.getOrDefault(t, 0)).append(" | ")
              .append(linksByType.getOrDefault(t, 0)).append(" |\n");
        }
        sb.append('\n');

        sb.append("## 3. 覆盖链路域\n\n| 项 | 值 |\n|:---|--:|\n");
        sb.append("| 已覆盖（按层） | ").append(coveredByLayer).append(" |\n\n");

        sb.append("## 4. 引擎诊断\n\n| 计数 | 值 |\n|:---|--:|\n");
        for (Map.Entry<String, Integer> e : engine.getExDiagnostics().entrySet()) {
            sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()).append(" |\n");
        }
        return sb.toString();
    }

    private static String pct(Double v) {
        return v == null ? "n/a" : String.format("%.2f%%", v * 100);
    }
}
