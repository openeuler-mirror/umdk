/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Records planPathsCoverage / planPathsCoverageEx input topology
 *              and output result as JSON files for the full 4-rack topology.
 * Create: 2026-09-21
 *
 * For each of the 4 combinations (2 interfaces x 2 requirements) the tool
 * writes two JSON files:
 *   - input  — the full 4-rack SuperNode topology saved BEFORE setSuperNode;
 *              the 4 input files are identical because the same topology is
 *              used every time.
 *   - output — the CoveragePathsResult returned by the call; the 4 output
 *              files generally differ across interfaces and requirements.
 */
package com.huawei.umdk.snc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.CoveragePathsRequest;
import com.huawei.umdk.snc.dto.CoveragePathsResult;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.entity.SuperNode;

/**
 * Standalone recorder that loads the full 4-rack topology produced by
 * {@link FullRackTopologyGenerator} (via {@link RackTopologyLoader}) and
 * invokes both northbound coverage interfaces ({@code planPathsCoverage} and
 * {@code planPathsCoverageEx}) with each of the two coverage requirements
 * ({@code MIN_COVERAGE} and {@code REDUNDANT}), writing the input topology
 * and the output result of every call as a JSON file.
 *
 * <p>Usage:
 * <pre>
 *   mvn -o -DskipTests test-compile
 *   java -Xmx6g -Djna.library.path=&lt;resources&gt; -cp &lt;cp&gt; \
 *        com.huawei.umdk.snc.CoverageRecordDumper [outputDir]
 *      outputDir - destination directory (default: current working directory)
 * </pre>
 *
 * <p>Output files (in {@code outputDir}, 8 in total):
 * <ul>
 *   <li>{@code input_planPathsCoverage_MIN_COVERAGE.json}</li>
 *   <li>{@code input_planPathsCoverage_REDUNDANT.json}</li>
 *   <li>{@code input_planPathsCoverageEx_MIN_COVERAGE.json}</li>
 *   <li>{@code input_planPathsCoverageEx_REDUNDANT.json}</li>
 *   <li>{@code output_planPathsCoverage_MIN_COVERAGE.json}</li>
 *   <li>{@code output_planPathsCoverage_REDUNDANT.json}</li>
 *   <li>{@code output_planPathsCoverageEx_MIN_COVERAGE.json}</li>
 *   <li>{@code output_planPathsCoverageEx_REDUNDANT.json}</li>
 * </ul>
 *
 * <p>The 4 {@code input_*.json} files are identical (same full 4-rack
 * topology). The 4 {@code output_*.json} files generally differ because they
 * come from different interfaces and coverage requirements.
 *
 * <p>NOTE: requires the snc module's test classpath (jackson-databind is
 * test scope).
 */
public class CoverageRecordDumper {

    private static final String SN_NAME = "A5-superPod-rack";

    /**
     * Jackson mixin that excludes the derived {@code getAllDevices()} view
     * (annotated {@code @JSONField(serialize = false)} for fastjson2 but not
     * recognized by Jackson) from {@link SuperNode} serialization.
     */
    @JsonIgnoreProperties("allDevices")
    private abstract static class SuperNodeMixin {
    }

    public static void main(String[] args) throws Exception {
        String outputDir = args.length >= 1 ? args[0] : ".";
        Path outDir = Paths.get(outputDir);
        Files.createDirectories(outDir);

        ObjectMapper topoMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
        topoMapper.addMixIn(SuperNode.class, SuperNodeMixin.class);

        ObjectMapper resultMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

        System.out.println("Loading full 4-rack topology (148 devices) ...");
        long tLoad = System.currentTimeMillis();
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        System.out.println("  topology ready in "
            + (System.currentTimeMillis() - tLoad) + " ms — "
            + sn.getNpuDevices().size() + " NPUs, "
            + sn.getSwDevices().size() + " SWs");

        CoverageRequirement[] requirements = {
            CoverageRequirement.MIN_COVERAGE,
            CoverageRequirement.REDUNDANT
        };

        for (CoverageRequirement req : requirements) {
            runOne(sn, "planPathsCoverage", req, false, outDir, topoMapper, resultMapper);
            runOne(sn, "planPathsCoverageEx", req, true, outDir, topoMapper, resultMapper);
        }

        System.out.println("\nDone. 8 JSON files written to " + outDir.toAbsolutePath());
    }

    /**
     * Runs one interface+requirement combination and writes the input topology
     * (before {@code setSuperNode}) and the output result as JSON files.
     *
     * @param sn            the full 4-rack topology (shared across all calls)
     * @param interfaceName {@code planPathsCoverage} or {@code planPathsCoverageEx}
     * @param requirement   {@code MIN_COVERAGE} or {@code REDUNDANT}
     * @param extended      {@code true} for {@code planPathsCoverageEx},
     *                      {@code false} for {@code planPathsCoverage}
     */
    private static void runOne(SuperNode sn, String interfaceName,
                                CoverageRequirement requirement, boolean extended,
                                Path outDir, ObjectMapper topoMapper,
                                ObjectMapper resultMapper) throws IOException {
        String tag = interfaceName + "_" + requirement;
        Path inputFile = outDir.resolve("input_" + tag + ".json");
        Path outputFile = outDir.resolve("output_" + tag + ".json");

        System.out.println("\n=== " + tag + " ===");

        // 1. Save input topology BEFORE setSuperNode.
        System.out.println("  writing input topology -> " + inputFile.getFileName());
        topoMapper.writeValue(inputFile.toFile(), sn);

        // 2. Fresh service per call so each invocation is independent.
        SncService service = new SncService();
        service.init(new SNCConfig());
        try {
            service.setSuperNode(sn);

            CoveragePathsRequest request = new CoveragePathsRequest();
            request.setSuperNodeName(SN_NAME);
            request.setCoverageRequirement(requirement);

            // 3. Call the interface.
            long t0 = System.currentTimeMillis();
            CoveragePathsResult result = extended
                ? service.planPathsCoverageEx(request)
                : service.planPathsCoverage(request);
            long elapsed = System.currentTimeMillis() - t0;

            // 4. Save output result.
            System.out.println("  writing output result  -> " + outputFile.getFileName());
            resultMapper.writeValue(outputFile.toFile(), result);

            System.out.println("  status=" + result.getStatus()
                + " pairs=" + (result.getEidPairs() == null ? 0 : result.getEidPairs().size())
                + " coverage=" + (result.getStats() == null ? "n/a"
                    : String.format("%.2f%%", result.getStats().getCoverageRate() * 100))
                + " in " + (elapsed / 1000.0) + "s");
        } finally {
            service.uninit();
        }
    }
}
