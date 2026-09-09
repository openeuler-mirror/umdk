/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage diagram generator
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.huawei.umdk.snc.CoverageRouteAugmentor;
import com.huawei.umdk.snc.RackTopologyLoader;
import com.huawei.umdk.snc.config.HashTuple;
import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.*;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.engine.*;
import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.util.HashUtils;
import com.huawei.umdk.snc.store.*;

public class CoverageDiagramGenerator {

    private static boolean isL1Sw(Map<String, DeviceEntity> devices, String deviceName) {
        DeviceEntity dev = devices.get(deviceName);
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L1;
    }

    private static boolean isL2Sw(Map<String, DeviceEntity> devices, String deviceName) {
        DeviceEntity dev = devices.get(deviceName);
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L2;
    }

    private static final String SN_NAME = "A5-superPod-rack";

    public static void main(String[] args) throws Exception {
        // === Step 1: Parse CLI args ===
        int dataPort = args.length >= 1 ? Integer.parseInt(args[0]) : 0;
        int ackPort  = args.length >= 2 ? Integer.parseInt(args[1]) : 0;
        String outputPath = args.length >= 3 ? args[2] : "coverage_diagram.html";
        String strategyName = args.length >= 4 ? args[3] : "MIN_COVERAGE";

        // hashFunc: from SNCConfig (default 1), optionally overridden by CLI arg #5.
        int hashFunc = new SNCConfig().getHashFunc();
        if (args.length >= 5) {
            hashFunc = Integer.parseInt(args[4]);
        }

        // hashTuple: from SNCConfig (default TWO = two-tuple dip,sip),
        // optionally overridden by CLI arg #6 (tuple count 2..5).
        HashTuple hashTuple = new SNCConfig().getHashTuple();
        if (args.length >= 6) {
            hashTuple = HashTuple.fromCount(Integer.parseInt(args[5]));
        }

        // === Step 2: Load & augment topology ===
        // 2a. Build the full 148-device rack topology as an in-memory SuperNode.
        System.out.println("Loading topology...");
        SuperNode rawSn = RackTopologyLoader.loadRawTopology();
        CoverageRouteAugmentor.augmentL1swRouting(rawSn);
        CoverageRouteAugmentor.augmentL2swRouting(rawSn);

        // === Step 3: Extract port mappings for HTML rendering ===
        //     Builds 8 lookup maps (npuPortToL1sw, l1swPortToNpu, l1swL2swPortToL1swPort,
        //     l1swL2swPortToL2swPort, l2swInToL1swOut, l2swInToL2swOut) by traversing
        //     all devices/ports in the SuperNode. These maps are used by generateHtml()
        //     to render human-readable hop-by-hop path information.
        TopoPortInfo topoPorts = buildTopoPortInfo(rawSn);

        // === Step 4: Init stores ===
        // 4a. SuperNodeStore holds the augmented SuperNode for runtime route-table lookups
        //     (used by CoveragePlanEngine.lookupRoute() during traceForward/Reverse).
        SuperNodeStore superNodeStore = new SuperNodeStore();
        superNodeStore.init();
        superNodeStore.replace(rawSn);

        // === Step 5: Build engines & PathService ===
        //     PathService orchestrates all engines. Although coverage does NOT call
        //     planPath() (see Step 7 comment), the constructor still requires all engines.
        //     CoveragePlanEngine is the core engine for the two-phase search algorithm.
        PathEngine pathEngine = new PathEngine();
        RouteLookupEngine routeLookupEngine = new RouteLookupEngine();
        CoveragePlanEngine coveragePlanEngine = new CoveragePlanEngine(
            superNodeStore, hashFunc, dataPort, ackPort);
        PathService service = new PathService(superNodeStore, pathEngine,
            routeLookupEngine, coveragePlanEngine);

        // === Step 6: Build coverage request ===
        //     CoveragePathsRequest carries user parameters into PathService.planPathsCoverage().
        //     The fixed UDP source ports (dataPort/ackPort) now come from SNCConfig and are
        //     baked into the CoveragePlanEngine above.
        CoveragePathsRequest request = new CoveragePathsRequest();
        request.setSuperNodeName(SN_NAME);
        request.setCoverageRequirement(CoverageRequirement.valueOf(strategyName));

        // === Step 7: Run coverage algorithm (Phase 1 + Phase 2) ===
        //     Internally calls CoveragePlanEngine.findCoverage() which:
        //       Phase 1 – enumerate all cross-chassis (src, dst) EID pairs, trace forward path
        //                 (traceForwardPath) and reverse path (traceReversePath) for each,
        //                 collect viable pairs that cover specific (device:outPort) out-ports.
        //       Phase 2 – greedy selection from viable pairs until all out-ports are covered,
        //                 then postProcessDedup() to reduce EID repetition.
        //     After findCoverage(), PathService.planPathsCoverage() converts the internal
        //     CoverageSearchResult into the public CoveragePathsResult DTO.
        //
        //     IMPORTANT: coverage does NOT call planPath(). The forwardPath/reversePath fields
        //     in CoveredEidPair are intentionally left null because generateHtml() only reads
        //     coveredLinks to render paths.
        //     Calling planPath(interDevices=null) would attempt a direct-NPU-connection check
        //     which always fails for cross-chassis pairs.
        System.out.println("Running coverage algorithm...");
        long t0 = System.currentTimeMillis();
        CoveragePathsResult result = service.planPathsCoverage(request);
        long t1 = System.currentTimeMillis();

        // === Step 8: Check status ===
        if (result.getStatus() != PlanStatus.SUCCESS) {
            System.err.println("Coverage failed: " + result.getStatus());
            System.err.println("  totalLinks=" + result.getStats().getTotalLinks()
                + " covered=" + result.getStats().getCoveredCount()
                + " rate=" + String.format("%.2f%%", result.getStats().getCoverageRate() * 100));
            if (result.getErrorMessage() != null) {
                System.err.println("  " + result.getErrorMessage());
            }
            System.exit(1);
        }

        // === Step 9: Print summary ===
        System.out.println("Done. " + result.getEidPairs().size() + " pairs, "
            + result.getStats().getCoveredCount() + "/" + result.getStats().getTotalLinks() + " covered, "
            + String.format("%.2f%%", result.getStats().getCoverageRate() * 100)
            + " link repeatRate=" + String.format("%.1f%%", result.getStats().getRepeatRate() * 100)
            + " eidRepeatRate=" + String.format("%.1f%%", result.getStats().getEidRepeatRate() * 100)
            + " in " + (t1 - t0) / 1000.0 + "s");

        // === Step 10: Generate HTML & write file ===
        String html = generateHtml(result, dataPort, ackPort, topoPorts, hashFunc, hashTuple, rawSn.getAllDevices());
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
            w.write(html);
        }
        System.out.println("Written to " + new File(outputPath).getAbsolutePath());
    }

    static TopoPortInfo buildTopoPortInfo(SuperNode sn) {
        Map<String, String> npuPortToL1sw = new HashMap<>();
        Map<String, String> npuPortToL1swPort = new HashMap<>();
        Map<String, String> l1swPortToNpu = new HashMap<>();
        Map<String, String> l1swPortToNpuPort = new HashMap<>();
        Map<String, String> l1swL2swPortToL1swPort = new HashMap<>();
        Map<String, String> l1swL2swPortToL2swPort = new HashMap<>();
        Map<String, String> l2swInToL1swOut = new HashMap<>();
        Map<String, String> l2swInToL2swOut = new HashMap<>();

        for (DeviceEntity dev : sn.getAllDevices().values()) {
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    String key = dev.getDeviceName() + ":" + port.getPortName();
                    String remoteDev = port.getRemoteDevice();
                    String remotePort = port.getRemotePort();
                    if (remoteDev == null) continue;

                    if (dev.getDeviceType() == DeviceType.NPU && port instanceof NpuPortEntity && port.getCna() != null) {
                        npuPortToL1sw.put(key, remoteDev);
                        npuPortToL1swPort.put(key, remotePort);
                        String l1Key = remoteDev + ":" + remotePort;
                        l1swPortToNpu.put(l1Key, dev.getDeviceName());
                        l1swPortToNpuPort.put(l1Key, port.getPortName());
                    } else if (dev.getDeviceType() == DeviceType.SW) {
                        SwDevice sw = (SwDevice) dev;
                        if (sw.getSwitchLevel() == SwitchLevel.L1 && isL2Sw(sn.getAllDevices(), remoteDev)) {
                            l1swL2swPortToL1swPort.put(key, port.getPortName());
                            l1swL2swPortToL2swPort.put(key, remotePort);
                        }
                    }
                }
            }
        }

        Map<String, List<PortEntity>> l2swPortsByDevice = new HashMap<>();
        for (DeviceEntity dev : sn.getAllDevices().values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L2) continue;
            if (dev.getForwardingChips() == null) continue;
            List<PortEntity> allPorts = new ArrayList<>();
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                allPorts.addAll(chip.getPorts().values());
            }
            l2swPortsByDevice.put(dev.getDeviceName(), allPorts);
        }

        for (Map.Entry<String, List<PortEntity>> entry : l2swPortsByDevice.entrySet()) {
            String l2swDevName = entry.getKey();
            List<PortEntity> ports = entry.getValue();
            Map<Integer, Map<String, PortEntity>> chipPortsByChassis = new HashMap<>();
            Map<Integer, Map<String, Integer>> chipBaseIdByChassis = new HashMap<>();
            for (PortEntity p : ports) {
                String remoteDev = p.getRemoteDevice();
                if (remoteDev == null || !isL1Sw(sn.getAllDevices(), remoteDev)) continue;
                String chassis = sn.getAllDevices().get(remoteDev).getRack();
                int chipIdx = p.getChipIndex();
                chipPortsByChassis.computeIfAbsent(chipIdx, k -> new HashMap<>())
                    .put(chassis, p);
            }
            for (int chipIdx : chipPortsByChassis.keySet()) {
                Map<String, PortEntity> chassisMap = chipPortsByChassis.get(chipIdx);
                for (Map.Entry<String, PortEntity> ce : chassisMap.entrySet()) {
                    int baseId = ce.getValue().getId();
                    chipBaseIdByChassis.computeIfAbsent(chipIdx, k -> new HashMap<>())
                        .put(ce.getKey(), baseId);
                }
            }
            for (PortEntity p : ports) {
                String remoteDev = p.getRemoteDevice();
                if (remoteDev == null || !isL1Sw(sn.getAllDevices(), remoteDev)) continue;
                String srcChassis = sn.getAllDevices().get(remoteDev).getRack();
                String l2swKey = l2swDevName + ":" + p.getPortName();
                int chipIdx = p.getChipIndex();
                Map<String, PortEntity> sameChipPorts = chipPortsByChassis.get(chipIdx);
                Map<String, Integer> sameChipBases = chipBaseIdByChassis.get(chipIdx);
                if (sameChipPorts == null || sameChipBases == null) continue;
                int srcOffset = p.getId() - sameChipBases.getOrDefault(srcChassis, 0);
                for (Map.Entry<String, PortEntity> chassisEntry : sameChipPorts.entrySet()) {
                    String dstCh = chassisEntry.getKey();
                    if (dstCh.equals(srcChassis)) continue;
                    int dstBase = sameChipBases.getOrDefault(dstCh, 0);
                    int targetId = dstBase + srcOffset;
                    PortEntity targetPort = null;
                    for (PortEntity pp : ports) {
                        if (pp.getChipIndex() == chipIdx && pp.getId() == targetId) {
                            targetPort = pp;
                            break;
                        }
                    }
                    if (targetPort != null) {
                        String dstChassisKey = l2swKey + ":" + dstCh;
                        l2swInToL1swOut.put(dstChassisKey, targetPort.getRemotePort());
                        l2swInToL2swOut.put(dstChassisKey, targetPort.getPortName());
                    }
                }
            }
        }

        return new TopoPortInfo(npuPortToL1sw, npuPortToL1swPort,
            l1swPortToNpu, l1swPortToNpuPort,
            l1swL2swPortToL1swPort, l1swL2swPortToL2swPort,
            l2swInToL1swOut, l2swInToL2swOut);
    }

    static class TopoPortInfo {
        final Map<String, String> npuPortToL1sw;
        final Map<String, String> npuPortToL1swPort;
        final Map<String, String> l1swPortToNpu;
        final Map<String, String> l1swPortToNpuPort;
        final Map<String, String> l1swL2swPortToL1swPort;
        final Map<String, String> l1swL2swPortToL2swPort;
        final Map<String, String> l2swInToL1swOut;
        final Map<String, String> l2swInToL2swOut;

        TopoPortInfo(Map<String, String> npuPortToL1sw, Map<String, String> npuPortToL1swPort,
                     Map<String, String> l1swPortToNpu, Map<String, String> l1swPortToNpuPort,
                     Map<String, String> l1swL2swPortToL1swPort, Map<String, String> l1swL2swPortToL2swPort,
                     Map<String, String> l2swInToL1swOut, Map<String, String> l2swInToL2swOut) {
            this.npuPortToL1sw = npuPortToL1sw;
            this.npuPortToL1swPort = npuPortToL1swPort;
            this.l1swPortToNpu = l1swPortToNpu;
            this.l1swPortToNpuPort = l1swPortToNpuPort;
            this.l1swL2swPortToL1swPort = l1swL2swPortToL1swPort;
            this.l1swL2swPortToL2swPort = l1swL2swPortToL2swPort;
            this.l2swInToL1swOut = l2swInToL1swOut;
            this.l2swInToL2swOut = l2swInToL2swOut;
        }
    }

    private static final int[] NUMERIC_TO_SORTED = buildNumericToSorted();
    private static int[] buildNumericToSorted() {
        String[] raw = new String[64];
        for (int i = 0; i < 64; i++) raw[i] = "400GUB 1/2/" + i;
        String[] sorted = raw.clone();
        Arrays.sort(sorted);
        int[] map = new int[64];
        for (int si = 0; si < 64; si++) {
            int ni = Integer.parseInt(sorted[si].substring(sorted[si].lastIndexOf('/') + 1));
            map[ni] = si;
        }
        return map;
    }

    static String generateHtml(CoveragePathsResult result, int dataPort, int ackPort,
                                TopoPortInfo topoPorts, int hashFunc, HashTuple hashTuple,
                                Map<String, DeviceEntity> devices) {
        // === Classify links into type1~type4 per pair ===
        // Each pair covers 4 out-ports, appended by PathService in a fixed order:
        //   [0] srcL1SW ECMP out (forward hop1), [1] L2SW out toward dst (forward hop2),
        //   [2] dstL1SW ECMP out (reverse hop1), [3] L2SW out toward src (reverse hop2).
        // Positional classification replaces the removed FORWARD/REVERSE direction tag.
        List<CoveredEidPair> pairs = result.getEidPairs();
        int totalPairs = pairs != null ? pairs.size() : 0;

        List<CoverageLink>[] type1 = new List[totalPairs];
        List<CoverageLink>[] type2 = new List[totalPairs];
        List<CoverageLink>[] type3 = new List[totalPairs];
        List<CoverageLink>[] type4 = new List[totalPairs];

        for (int i = 0; i < totalPairs; i++) {
            type1[i] = new ArrayList<>();
            type2[i] = new ArrayList<>();
            type3[i] = new ArrayList<>();
            type4[i] = new ArrayList<>();

            CoveredEidPair pair = pairs.get(i);

            if (pair.getCoveredLinks() == null) continue;
            for (int li = 0; li < pair.getCoveredLinks().size(); li++) {
                CoverageLink link = pair.getCoveredLinks().get(li);
                if (li == 0) type1[i].add(link);
                else if (li == 1) type2[i].add(link);
                else if (li == 2) type3[i].add(link);
                else type4[i].add(link);
            }
        }

        StringBuilder sb = new StringBuilder(512 * 1024);
        sb.append("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n");
        sb.append("<meta charset=\"UTF-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("<title>Coverage Diagram - dataPort=").append(dataPort).append(" ackPort=").append(ackPort).append("</title>\n");
        sb.append("<style>\n");
        sb.append("*{box-sizing:border-box;margin:0;padding:0}\n");
        sb.append("body{font-family:'Microsoft YaHei','Segoe UI',sans-serif;background:#f0f2f5;color:#222;padding:20px}\n");
        sb.append("h1{color:#1a1a2e;border-bottom:3px solid #4CAF50;padding-bottom:12px;margin-bottom:20px}\n");
        sb.append("h2{color:#16213e;margin:24px 0 12px}\n");
        sb.append(".card{background:#fff;border-radius:10px;padding:20px;margin:0 0 20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}\n");
        sb.append(".card h2:first-child{margin-top:0}\n");
        sb.append("table.stats{width:100%;border-collapse:collapse;margin-top:8px}\n");
        sb.append("table.stats td,table.stats th{padding:8px 12px;border:1px solid #e0e0e0;text-align:center}\n");
        sb.append("table.stats th{background:#4CAF50;color:#fff}\n");
        sb.append(".ok{color:#2e7d32;font-weight:bold}\n");
        sb.append("table.pairs{width:100%;border-collapse:collapse;font-size:12px}\n");
        sb.append("table.pairs th,table.pairs td{padding:4px 6px;border:1px solid #ddd;text-align:center}\n");
        sb.append("table.pairs th{background:#1976d2;color:#fff;position:sticky;top:0}\n");
        sb.append("table.pairs tr:nth-child(even){background:#f5f8ff}\n");
        sb.append("table.pairs tr:hover{background:#e3f2fd}\n");
        sb.append(".tag{display:inline-block;padding:1px 6px;border-radius:8px;font-size:10px;color:#fff;margin:1px}\n");
        sb.append(".t1{background:#e53935}.t2{background:#1e88e5}.t3{background:#43a047}.t4{background:#fb8c00}\n");
        sb.append(".path-box{font-family:monospace;background:#f5f5f5;padding:12px;border-radius:6px;line-height:1.8;font-size:13px}\n");
        sb.append(".path-box .hop{padding:2px 8px;margin:2px 0;border-left:3px solid #ccc}\n");
        sb.append(".path-box .hop.h1{border-color:#e53935}.path-box .hop.h2{border-color:#1e88e5}\n");
        sb.append(".path-box .hop.h3{border-color:#43a047}.path-box .hop.h4{border-color:#fb8c00}\n");
        sb.append(".param-form{background:#e8f5e9;border-radius:10px;padding:16px 20px;margin:0 0 20px;"
            + "box-shadow:0 2px 8px rgba(0,0,0,.06);display:flex;flex-wrap:wrap;gap:12px;"
            + "align-items:flex-end;border:2px solid #4CAF50}\n");
        sb.append(".param-form label{display:block;font-weight:bold;font-size:13px;color:#333;margin-bottom:3px}\n");
        sb.append(".param-form input,.param-form select{padding:6px 10px;border:1px solid #ccc;"
            + "border-radius:5px;font-size:14px;width:160px}\n");
        sb.append(".param-form button{padding:8px 20px;background:#4CAF50;color:#fff;border:none;"
            + "border-radius:6px;font-size:14px;font-weight:bold;cursor:pointer}\n");
        sb.append(".param-form button:hover{background:#388E3C}\n");
        sb.append(".param-form button:disabled{background:#aaa;cursor:not-allowed}\n");
        sb.append(".param-form .hint{font-size:12px;color:#666;margin-top:4px}\n");
        sb.append("@media print{.param-form{display:none}}\n");
        sb.append("@media print{body{padding:10px;background:#fff}.card{box-shadow:none;border:1px solid #ddd}}\n");
sb.append("table.trace td,table.trace th{padding:3px 6px;border:1px solid #ccc;font-size:11px;white-space:nowrap}\n");
sb.append("table.trace .v_ok{color:#2e7d32;font-weight:bold}.v_fail{color:#c62828;font-weight:bold}\n");
sb.append("table.trace .hop_direct{background:#e8f5e9}.table.trace .hop_ecmp{background:#e3f2fd}\n");
sb.append("table.trace .hop_host{background:#fff8e1}\n");
        sb.append(".filter-row td{background:#e3f2fd!important}\n");
        sb.append(".filter-row select{background:#fff}\n");
        sb.append("</style>\n</head>\n<body>\n");

        sb.append("<form class=\"param-form\" id=\"reRunForm\" action=\"http://127.0.0.1:8080/run\" method=\"POST\" target=\"_blank\">\n");
        sb.append("<div>\n<label>dataUdpSrcPort</label>\n")
          .append("<input type=\"number\" name=\"dataUdpSrcPort\" min=\"0\" max=\"255\" value=\"").append(dataPort)
          .append("\" id=\"formDataUdpSrcPort\"></div>\n");
        sb.append("<div>\n<label>ackUdpSrcPort</label>\n")
          .append("<input type=\"number\" name=\"ackUdpSrcPort\" min=\"0\" max=\"255\" value=\"").append(ackPort)
          .append("\" id=\"formAckUdpSrcPort\"></div>\n");
        sb.append("<div>\n<button type=\"submit\" id=\"formSubmit\">Re-Run</button></div>\n");
        sb.append("<div class=\"hint\">Requires backend server (CoverageWebServer). Takes 3~6 min.</div>\n");
        sb.append("</form>\n");

        sb.append("<script>\n");
        sb.append("var pairData=[\n");
        for (int i = 0; i < totalPairs; i++) {
            CoveredEidPair p = pairs.get(i);
            sb.append("{idx:").append(i + 1)
              .append(",srcNpu:\"").append(htmlEsc(shortName(p.getSrcDevice()))).append("\"")
              .append(",srcPort:\"").append(htmlEsc(p.getSrcPort())).append("\"")
              .append(",dstNpu:\"").append(htmlEsc(shortName(p.getDestDevice()))).append("\"")
              .append(",dstPort:\"").append(htmlEsc(p.getDestPort())).append("\"")
              .append(",srcEid:\"").append(htmlEsc(p.getSrcEid() != null ? p.getSrcEid() : "")).append("\"")
              .append(",dstEid:\"").append(htmlEsc(p.getDstEid() != null ? p.getDstEid() : "")).append("\"")
              .append(",links:[");
            if (p.getCoveredLinks() != null) {
                for (int li = 0; li < p.getCoveredLinks().size(); li++) {
                    CoverageLink link = p.getCoveredLinks().get(li);
                    int tType = li == 0 ? 1 : (li == 1 ? 2 : (li == 2 ? 3 : 4));
                    sb.append("{dev:\"").append(htmlEsc(link.getSwitchDevice() != null ? link.getSwitchDevice() : "")).append("\"")
                      .append(",outP:\"").append(htmlEsc(link.getOutPort() != null ? link.getOutPort() : "")).append("\"")
                      .append(",remDev:\"").append(htmlEsc(link.getRemoteSwitch() != null ? link.getRemoteSwitch() : "")).append("\"")
                      .append(",remP:\"").append(htmlEsc(link.getRemotePort() != null ? link.getRemotePort() : "")).append("\"")
                      .append(",type:").append(tType)
                      .append("},");
                }
            }
            sb.append("]},\n");
        }
        sb.append("];\n");

        sb.append("function shortDev(full){if(!full)return'';return full.replace('rack','r').replace('#l1sw','.').replace('#board','.').replace('#npu','.').replace('#l2sw','.');}\n");

        sb.append("function doVerify(){\n");
        sb.append("  var q=document.getElementById('verifyInput').value.trim().toLowerCase();\n");
        sb.append("  if(!q){document.getElementById('verifyResult').innerHTML='<p style=\"color:#999\">Please enter a link to search.</p>';return;}\n");
        sb.append("  var results=[];\n");
        sb.append("  for(var i=0;i<pairData.length;i++){\n");
        sb.append("    var p=pairData[i];var matched=[];\n");
        sb.append("    for(var j=0;j<p.links.length;j++){\n");
        sb.append("      var lk=p.links[j];\n");
        sb.append("      var sd=shortDev(lk.dev);var srd=shortDev(lk.remDev);\n");
        sb.append("      var fullDev=lk.dev;var fullRemDev=lk.remDev;\n");
        sb.append("      if(sd.toLowerCase().indexOf(q)>=0||srd.toLowerCase().indexOf(q)>=0||lk.outP.toLowerCase().indexOf(q)>=0||lk.remP.toLowerCase().indexOf(q)>=0||fullDev.toLowerCase().indexOf(q)>=0||fullRemDev.toLowerCase().indexOf(q)>=0){matched.push(lk);}\n");
        sb.append("    }\n");
        sb.append("    if(matched.length>0){results.push({pair:p,matched:matched});}\n");
        sb.append("  }\n");
        sb.append("  if(results.length==0){document.getElementById('verifyResult').innerHTML='<p style=\"color:#d32f2f\">No matching link found.</p>';return;}\n");
        sb.append("  var h='<p>Found <strong>'+results.length+'</strong> EID pairs covering this link:</p>';h+='<table class=\"pairs\"><tr><th>#</th><th>Src NPU:port</th><th>Dst NPU:port</th><th>Matched Path Segments</th></tr>';for(var r=0;r<results.length;r++){var rr=results[r];h+='<tr><td>'+rr.pair.idx+'</td><td>'+rr.pair.srcNpu+':'+rr.pair.srcPort+'</td><td>'+rr.pair.dstNpu+':'+rr.pair.dstPort+'</td><td>';for(var m=0;m<rr.matched.length;m++){var mk=rr.matched[m];var tc=mk.type;var cls='t'+tc;h+='<span class=\"tag '+cls+'\">'+String.fromCharCode(0x2460+tc-1)+' '+shortDev(mk.dev)+':'+mk.outP+' \\u2192 '+shortDev(mk.remDev)+':'+mk.remP+'</span> ';}h+='</td></tr>';}\n");
        sb.append("  h+='</table>';document.getElementById('verifyResult').innerHTML=h;\n");
        sb.append("}\n");

        sb.append("function addColFilters(tableId){\n");
        sb.append("  var tbl=document.getElementById(tableId);if(!tbl)return;\n");
        sb.append("  var rows=tbl.querySelectorAll('tr');if(rows.length<2)return;\n");
        sb.append("  var hdr=rows[0];var cols=hdr.querySelectorAll('th');\n");
        sb.append("  var filterRow=document.createElement('tr');filterRow.className='filter-row';\n");
        sb.append("  for(var c=0;c<cols.length;c++){\n");
        sb.append("    var td=document.createElement('td');td.style.padding='4px 2px';\n");
        sb.append("    var sel=document.createElement('select');sel.style.width='100%';sel.style.fontSize='11px';sel.style.padding='2px';\n");
        sb.append("    sel.innerHTML='<option value=\"\">All</option>';sel.dataset.col=c;sel.dataset.table=tableId;\n");
        sb.append("    var vals=new Set();for(var r=1;r<rows.length;r++){var cell=rows[r].querySelectorAll('td')[c];if(cell)vals.add(cell.textContent.trim());}\n");
        sb.append("    var sorted=Array.from(vals).sort();for(var v=0;v<sorted.length;v++){var opt=document.createElement('option');opt.value=sorted[v];opt.textContent=sorted[v].length>20?sorted[v].substring(0,20)+'...':sorted[v];sel.appendChild(opt);}\n");
        sb.append("    sel.addEventListener('change',applyFilters);td.appendChild(sel);filterRow.appendChild(td);\n");
        sb.append("  }\n");
        sb.append("  hdr.parentNode.insertBefore(filterRow,hdr.nextSibling);\n");
        sb.append("}\n");

        sb.append("function applyFilters(){\n");
        sb.append("  var activeTables={};\n");
        sb.append("  var allSelects=document.querySelectorAll('select[data-table]');\n");
        sb.append("  for(var s=0;s<allSelects.length;s++){var sl=allSelects[s];var tid=sl.dataset.table;var col=parseInt(sl.dataset.col);var val=sl.value;if(!activeTables[tid])activeTables[tid]={filters:{}};if(val)activeTables[tid].filters[col]=val;else delete activeTables[tid].filters[col];}\n");
        sb.append("  for(var tid in activeTables){\n");
        sb.append("    var tbl=document.getElementById(tid);if(!tbl)continue;\n");
        sb.append("    var rows=tbl.querySelectorAll('tr');var filters=activeTables[tid].filters;\n");
        sb.append("    for(var r=2;r<rows.length;r++){var cells=rows[r].querySelectorAll('td');var show=true;for(var col in filters){var ci=parseInt(col);if(cells[ci]&&cells[ci].textContent.trim()!==filters[col])show=false;}\n");
        sb.append("    rows[r].style.display=show?'':'none';}\n");
        sb.append("  }\n");
        sb.append("}\n");

        sb.append("window.addEventListener('DOMContentLoaded',function(){\n");
        sb.append("  addColFilters('pairsTable');\n");
        sb.append("  addColFilters('npuPortUsageTable');\n");
        sb.append("  addColFilters('npuTaskCountTable');\n");
        sb.append("});\n");
        sb.append("</script>\n");

        sb.append("<h1>L1SW\u2194L2SW Coverage Diagram</h1>\n");
        sb.append("<p style=\"color:#666;margin-bottom:16px\">")
          .append("Topology: <strong>").append(SN_NAME).append("</strong> | ")
          .append("dataPort=").append(dataPort).append(" | ackPort=").append(ackPort)
          .append(" | Pairs: ").append(totalPairs)
          .append(" | Coverage: 100% | ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()))
          .append("</p>\n");

        sb.append("<div class=\"card\">\n<h2>Summary</h2>\n<table class=\"stats\">\n");
        sb.append("<tr><th>Metric</th><th>Value</th><th>Check</th></tr>\n");
        int tl = result.getStats().getTotalLinks();
        sb.append("<tr><td>Total out-ports</td><td>").append(tl).append("</td>")
          .append("<td>L1SW " + (tl / 2) + " + L2SW " + (tl / 2) + "</td></tr>\n");
        sb.append("<tr><td>Covered</td><td class=\"ok\">").append(result.getStats().getCoveredCount()).append("</td><td>100%</td></tr>\n");
        sb.append("<tr><td>EID pairs</td><td class=\"ok\">").append(totalPairs).append("</td>")
          .append("<td>Each pair covers 4 out-ports (2 L1SW + 2 L2SW)</td></tr>\n");
        sb.append("<tr><td>Link repeat rate</td><td>").append(String.format("%.1f%%", result.getStats().getRepeatRate() * 100)).append("</td>")
          .append("<td>min=").append(result.getStats().getMinRepeatCount()).append(" max=").append(result.getStats().getMaxRepeatCount())
          .append(" avg=").append(String.format("%.1f", result.getStats().getAvgRepeatCount())).append("</td></tr>\n");
        sb.append("<tr><td>EID pair repeat rate</td><td>").append(String.format("%.1f%%", result.getStats().getEidRepeatRate() * 100)).append("</td>")
          .append("<td>unique EIDs=").append(result.getStats().getUniqueEidCount())
          .append(" / total appearances=").append(result.getStats().getTotalEidAppearances())
          .append(" | min=").append(result.getStats().getEidMinRepeat())
          .append(" max=").append(result.getStats().getEidMaxRepeat())
          .append(" avg=").append(String.format("%.1f", result.getStats().getEidAvgRepeat())).append("</td></tr>\n");

        if (result.getStats().getNpuUsageByChassis() != null && !result.getStats().getNpuUsageByChassis().isEmpty()) {
            sb.append("<tr><td>NPU distribution by chassis</td><td>");
            Map<String, Integer> npuMap = result.getStats().getNpuUsageByChassis();
            List<String> chassisOrder = new ArrayList<>(npuMap.keySet());
            Collections.sort(chassisOrder);
            for (String ch : chassisOrder) {
                sb.append(ch).append(":").append(npuMap.get(ch)).append(" ");
            }
            double mean = npuMap.values().stream().mapToInt(v -> v).average().orElse(0);
            double variance = npuMap.values().stream().mapToDouble(v -> (v - mean) * (v - mean)).average().orElse(0);
            double stdDev = Math.sqrt(variance);
            sb.append("</td><td>avg=").append(String.format("%.1f", mean))
              .append(" stddev=").append(String.format("%.1f", stdDev)).append("</td></tr>\n");
        }

        sb.append("</table>\n</div>\n");

        sb.append("<div class=\"card\">\n<h2>Per-Switch Hash Coverage</h2>\n");
        sb.append("<table class=\"stats\">\n");
        sb.append("<tr><th>Switch</th><th>Covered / Total</th><th>Status</th><th>Hash Range</th></tr>\n");
        List<CoverageLink> covLinks = result.getCoverageLinks();
        if (covLinks != null) {
            Map<String, Set<Integer>> dirSwitchPorts = new HashMap<>();
            Map<String, Integer> dirSwitchTotal = new HashMap<>();
            for (CoverageLink link : covLinks) {
                String key = link.getSwitchDevice();
                dirSwitchPorts.computeIfAbsent(key, k -> new HashSet<>()).add(link.getOutPortIndex());
                int total = link.getTotalOutPorts() != null ? link.getTotalOutPorts() : 0;
                if (total > dirSwitchTotal.getOrDefault(key, 0)) {
                    dirSwitchTotal.put(key, total);
                }
            }
            List<String> sortedKeys = new ArrayList<>(dirSwitchPorts.keySet());
            Collections.sort(sortedKeys);
            int fullCount = 0;
            for (String key : sortedKeys) {
                int expected = dirSwitchTotal.getOrDefault(key, 0);
                int actual = dirSwitchPorts.get(key).size();
                boolean full = actual == expected;
                if (full) fullCount++;
                String cls = full ? "ok" : "warn";
                String status = full ? "FULL" : "MISSING " + (expected - actual);
                String range = "0-" + (expected - 1);
                sb.append("<tr><td>").append(key)
                  .append("</td><td class=\"").append(cls).append("\">").append(actual).append("/").append(expected)
                  .append("</td><td>").append(status).append("</td><td>").append(range).append("</td></tr>\n");
            }
            sb.append("<tr class=\"total\"><td><strong>Summary</strong></td>")
              .append("<td colspan=\"3\"><strong>").append(fullCount).append("/").append(sortedKeys.size())
              .append(" switches have full out-port hash coverage</strong></td></tr>\n");
        }
        sb.append("</table>\n</div>\n");

        // === Detailed Path Trace Verification ===
        // For each pair, reconstruct the 4-hop path (NPU→L1SW→L2SW→L1SW→NPU) from
        // the coveredLinks, recompute the ECMP hash, and verify port selection.
        sb.append("<div class=\"card\">\n<h2>Detailed Path Trace (Hop-by-Hop)</h2>\n");
        sb.append("<p style=\"color:#666;font-size:13px;margin-bottom:8px\">"
            + "Reconstructs the full message flow for each EID pair: route lookup → hash computation → ECMP port selection. "
            + "The outPortIndex is <strong>recomputed</strong> via nativeHash (libUB5808) to verify correctness.</p>\n");
        for (int pi = 0; pi < totalPairs; pi++) {
            CoveredEidPair p = pairs.get(pi);
            String srcCna = p.getSrcCna();
            String dstCna = p.getDstCna();
            boolean hasCna = srcCna != null && dstCna != null;

            // Port indices recomputed via nativeHash (libUB5808). Parameter order:
            // nativeHash(dip, sip, dport, sport, ...) has dip=dst, sip=src, so the
            // forward (src→dst) tuple is (dip=dstCna, sip=srcCna). ecmpCnt is the
            // ECMP member count from route lookup (totalOutPorts), so nativeHash
            // already returns the port index — no further modulo is applied.
            String pairLabel = "Pair #" + (pi + 1) + ": " + shortName(p.getSrcDevice()) + ":" + p.getSrcPort()
                + " \u2192 " + shortName(p.getDestDevice()) + ":" + p.getDestPort();
            sb.append("<details").append(pi == 0 ? " open" : "").append(" style=\"margin-bottom:6px\">\n");
            sb.append("<summary style=\"cursor:pointer;font-weight:bold;font-size:13px;padding:4px 0\">")
              .append(pairLabel).append("</summary>\n");

            // Build hop data from type-classified links:
            // type1/type2 = forward hops (srcL1SW out, L2SW out toward dst);
            // type3/type4 = reverse hops (dstL1SW out, L2SW out toward src).
            List<CoverageLink> fwdLinks = new ArrayList<>();
            List<CoverageLink> revLinks = new ArrayList<>();
            fwdLinks.addAll(type1[pi]);
            fwdLinks.addAll(type2[pi]);
            revLinks.addAll(type3[pi]);
            revLinks.addAll(type4[pi]);
            // Sort forward: L1SW out first (ECMP), then L2SW out (chassis routing)
            // Link[0] = L1SW→L2SW (totalOutPorts=64), Link[1] = L2SW→L1SW (totalOutPorts=32)
            List<CoverageLink> sortedFwd = new ArrayList<>();
            List<CoverageLink> sortedRev = new ArrayList<>();
            for (CoverageLink l : fwdLinks) {
                if (isL2Sw(devices, l.getSwitchDevice())) sortedFwd.add(l);
                else sortedFwd.add(0, l);
            }
            for (CoverageLink l : revLinks) {
                if (isL2Sw(devices, l.getSwitchDevice())) sortedRev.add(l);
                else sortedRev.add(0, l);
            }

            CoverageLink hop1 = sortedFwd.size() > 0 ? sortedFwd.get(0) : null;
            CoverageLink hop2 = sortedFwd.size() > 1 ? sortedFwd.get(1) : null;
            CoverageLink hop1r = sortedRev.size() > 0 ? sortedRev.get(0) : null;
            CoverageLink hop2r = sortedRev.size() > 1 ? sortedRev.get(1) : null;

            int fwdIdx1 = -1, fwdIdx2 = -1, revIdx1 = -1, revIdx2 = -1;
            if (hasCna) {
                // Forward: sport=dataPort, dport=ackPort.
                fwdIdx1 = nativePortIdx(dstCna, srcCna, dataPort, ackPort, hop1, hashFunc, hashTuple);
                fwdIdx2 = nativePortIdx(dstCna, srcCna, dataPort, ackPort, hop2, hashFunc, hashTuple);
                // Reverse: sport=ackPort, dport=dataPort.
                revIdx1 = nativePortIdx(srcCna, dstCna, ackPort, dataPort, hop1r, hashFunc, hashTuple);
                revIdx2 = nativePortIdx(srcCna, dstCna, ackPort, dataPort, hop2r, hashFunc, hashTuple);
            }

            // Render forward path table
            sb.append("<table class=\"trace\" style=\"width:100%;border-collapse:collapse;font-size:12px;margin-top:6px\">\n");
            sb.append("<tr style=\"background:#e3f2fd\"><th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Hop</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Device</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Direction</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Route Lookup</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Hash Input</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Hash Value</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Port Select</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Out Port</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Next Hop</th>"
                + "<th style=\"padding:4px 8px;border:1px solid #bbb;text-align:left\">Verify</th></tr>\n");

            // Forward path: 4 hops
            // Hop 0: srcNPU → srcL1SW (direct)
            String srcKey = p.getSrcDevice() + ":" + p.getSrcPort();
            String srcL1swName = topoPorts.npuPortToL1sw.get(srcKey);
            String srcL1swInPort = topoPorts.npuPortToL1swPort.get(srcKey);
            traceHop(sb, p.getSrcDevice(), p.getSrcPort(), "NPU→L1SW",
                "Direct connect", "", 0, "-",
                srcL1swInPort != null ? srcL1swInPort : "(direct)", srcL1swName != null ? srcL1swName : "?",
                "DIRECT", fwdIdx1, -1, -1, true);

            // Hop 1: srcL1SW → L2SW (ECMP)
            if (hop1 != null) {
                int idx = hop1.getOutPortIndex() != null ? hop1.getOutPortIndex() : -1;
                int total = hop1.getTotalOutPorts() != null ? hop1.getTotalOutPorts() : 0;
                boolean valid = hasCna && total > 0 && fwdIdx1 == idx;
                String hashInput = hasCna ? srcCna + "|" + dstCna + "|" + dataPort : "-";
                traceHop(sb, hop1.getSwitchDevice(), hop1.getOutPort(), "FORWARD",
                    "dstCna=" + (hasCna ? dstCna : "?") + " /32, " + total + " candidates",
                    hashInput, fwdIdx1, "nativeHash(ecmpCnt=" + total + ") = " + fwdIdx1,
                    hop1.getOutPort(), hop1.getRemoteSwitch(),
                    "ECMP(" + idx + "/" + total + ")", fwdIdx1, idx, total, valid);
            }

            // Hop 2: L2SW → dstL1SW (ECMP)
            if (hop2 != null) {
                int idx = hop2.getOutPortIndex() != null ? hop2.getOutPortIndex() : -1;
                int total = hop2.getTotalOutPorts() != null ? hop2.getTotalOutPorts() : 0;
                boolean valid = hasCna && total > 0 && fwdIdx2 == idx;
                traceHop(sb, hop2.getSwitchDevice(), hop2.getOutPort(), "FORWARD",
                    "chassis=" + (hop2.getRemoteSwitch() != null ? hop2.getRemoteSwitch() : "?") + ", " + total + " candidates",
                    "(same forward tuple)", fwdIdx2, "nativeHash(ecmpCnt=" + total + ") = " + fwdIdx2,
                    hop2.getOutPort(), hop2.getRemoteSwitch(),
                    "ECMP(" + idx + "/" + total + ")", fwdIdx2, idx, total, valid);
            }

            // Hop 3: dstL1SW → dstNPU (host route)
            String dstKey = p.getDestDevice() + ":" + p.getDestPort();
            String dstL1swName = topoPorts.npuPortToL1sw.get(dstKey);
            String dstL1swOutPort = topoPorts.l1swPortToNpuPort.get(dstKey);
            String dstL1swInPort = topoPorts.l1swPortToNpu.get(dstKey) != null
                ? topoPorts.npuPortToL1swPort.get(dstKey) : null;
            traceHop(sb, p.getDestDevice(), p.getDestPort(), "L1SW→NPU",
                "Host route /32, 1 candidate", "", 0, "-",
                dstL1swOutPort != null ? dstL1swOutPort : "(direct)", p.getDestDevice(),
                "HOST_ROUTE", revIdx1, -1, -1, true);

            // Reverse path header
            sb.append("<tr style=\"background:#fff3e0\"><td colspan=\"10\" style=\"padding:4px 8px;border:1px solid #bbb;font-weight:bold\">"
                + "\u2B06 Reverse Path (REVERSE direction, revHash from nativeHash(dip=srcCna, sip=dstCna, ackPort))</td></tr>\n");

            // Reverse Hop 0: src(reverse)=dstNPU → dstL1SW
            traceHop(sb, p.getDestDevice(), p.getDestPort(), "NPU→L1SW",
                "Direct connect", "", 0, "-",
                dstL1swInPort != null ? dstL1swInPort : "(direct)", dstL1swName != null ? dstL1swName : "?",
                "DIRECT", revIdx1, -1, -1, true);

            // Reverse Hop 1: dstL1SW → L2SW (ECMP)
            if (hop1r != null) {
                int idx = hop1r.getOutPortIndex() != null ? hop1r.getOutPortIndex() : -1;
                int total = hop1r.getTotalOutPorts() != null ? hop1r.getTotalOutPorts() : 0;
                boolean valid = hasCna && total > 0 && revIdx1 == idx;
                String hashInput = hasCna ? dstCna + "|" + srcCna + "|" + ackPort : "-";
                traceHop(sb, hop1r.getSwitchDevice(), hop1r.getOutPort(), "REVERSE",
                    "dstCna=" + (hasCna ? srcCna : "?") + " /32, " + total + " candidates",
                    hashInput, revIdx1, "nativeHash(ecmpCnt=" + total + ") = " + revIdx1,
                    hop1r.getOutPort(), hop1r.getRemoteSwitch(),
                    "ECMP(" + idx + "/" + total + ")", revIdx1, idx, total, valid);
            }

            // Reverse Hop 2: L2SW → srcL1SW (ECMP)
            if (hop2r != null) {
                int idx = hop2r.getOutPortIndex() != null ? hop2r.getOutPortIndex() : -1;
                int total = hop2r.getTotalOutPorts() != null ? hop2r.getTotalOutPorts() : 0;
                boolean valid = hasCna && total > 0 && revIdx2 == idx;
                traceHop(sb, hop2r.getSwitchDevice(), hop2r.getOutPort(), "REVERSE",
                    "chassis=" + (hop2r.getRemoteSwitch() != null ? hop2r.getRemoteSwitch() : "?") + ", " + total + " candidates",
                    "(same reverse tuple)", revIdx2, "nativeHash(ecmpCnt=" + total + ") = " + revIdx2,
                    hop2r.getOutPort(), hop2r.getRemoteSwitch(),
                    "ECMP(" + idx + "/" + total + ")", revIdx2, idx, total, valid);
            }

            // Reverse Hop 3: srcL1SW → srcNPU (host route)
            String srcL1swOutPort = topoPorts.l1swPortToNpuPort.get(srcKey);
            traceHop(sb, p.getSrcDevice(), p.getSrcPort(), "L1SW→NPU",
                "Host route /32, 1 candidate", "", 0, "-",
                srcL1swOutPort != null ? srcL1swOutPort : "(direct)", p.getSrcDevice(),
                "HOST_ROUTE", revIdx2, -1, -1, true);

            sb.append("</table>\n</details>\n");
        }
        sb.append("</div>\n");
        if (totalPairs > 0) {
            CoveredEidPair ex = pairs.get(0);
            String srcKey = ex.getSrcDevice() + ":" + ex.getSrcPort();
            String dstKey = ex.getDestDevice() + ":" + ex.getDestPort();

            String srcNpu = ex.getSrcDevice();
            String srcNpuPort = ex.getSrcPort();
            String srcL1sw = topoPorts.npuPortToL1sw.get(srcKey);
            String srcL1swInPort = topoPorts.npuPortToL1swPort.get(srcKey);
            String dstNpu = ex.getDestDevice();
            String dstNpuPort = ex.getDestPort();
            String dstL1sw = topoPorts.npuPortToL1sw.get(dstKey);
            String dstL1swInPort = topoPorts.npuPortToL1swPort.get(dstKey);

            String[] portNames = getSortedPortNames();
            int fwdIdx = -1, revIdx = -1;
            if (!type1[0].isEmpty()) fwdIdx = type1[0].get(0).getOutPortIndex();
            if (!type3[0].isEmpty()) revIdx = type3[0].get(0).getOutPortIndex();

            String srcL1swOutPort = fwdIdx >= 0 ? portNames[fwdIdx] : "?";
            String dstL1swOutPort = revIdx >= 0 ? portNames[revIdx] : "?";

            String srcL1swKey = srcL1sw + ":" + srcL1swOutPort;
            String dstL1swKey = dstL1sw + ":" + dstL1swOutPort;

            String srcL2swInPort = topoPorts.l1swL2swPortToL2swPort.getOrDefault(srcL1swKey, "?");
            String dstL2swInPort = topoPorts.l1swL2swPortToL2swPort.getOrDefault(dstL1swKey, "?");

            String fwdL2swOutPortName = "?";
            String fwdL2swOutL1Port = "?";
            String revL2swOutPortName = "?";
            String revL2swOutL1Port = "?";
            String dstL1swIn2Port = "?";
            String srcL1swIn2Port = "?";

            String srcChassis = devices.get(srcNpu) != null ? devices.get(srcNpu).getRack() : null;
            String dstChassis = devices.get(dstNpu) != null ? devices.get(dstNpu).getRack() : null;

            CoverageLink fwdSrcLink = type1[0].isEmpty() ? null : type1[0].get(0);
            CoverageLink revDstLink = type3[0].isEmpty() ? null : type3[0].get(0);

            String exL2sw = (fwdSrcLink != null && fwdSrcLink.getRemoteSwitch() != null)
                ? fwdSrcLink.getRemoteSwitch() : "";

            String fwdL2swKey = (fwdSrcLink != null && fwdSrcLink.getRemoteSwitch() != null && fwdSrcLink.getRemotePort() != null)
                ? fwdSrcLink.getRemoteSwitch() + ":" + fwdSrcLink.getRemotePort() + ":" + dstChassis : null;
            String revL2swKey = (revDstLink != null && revDstLink.getRemoteSwitch() != null && revDstLink.getRemotePort() != null)
                ? revDstLink.getRemoteSwitch() + ":" + revDstLink.getRemotePort() + ":" + srcChassis : null;

            fwdL2swOutL1Port = fwdL2swKey != null ? topoPorts.l2swInToL1swOut.getOrDefault(fwdL2swKey, "?") : "?";
            fwdL2swOutPortName = fwdL2swKey != null ? topoPorts.l2swInToL2swOut.getOrDefault(fwdL2swKey, "?") : "?";
            revL2swOutL1Port = revL2swKey != null ? topoPorts.l2swInToL1swOut.getOrDefault(revL2swKey, "?") : "?";
            revL2swOutPortName = revL2swKey != null ? topoPorts.l2swInToL2swOut.getOrDefault(revL2swKey, "?") : "?";

            dstL1swIn2Port = fwdL2swOutL1Port;
            srcL1swIn2Port = revL2swOutL1Port;

            sb.append("<div class=\"card\">\n<h2>Example: Pair #1 ")
              .append(htmlEsc(shortName(srcNpu))).append(":").append(htmlEsc(srcNpuPort))
              .append(" \u2192 ").append(htmlEsc(shortName(dstNpu))).append(":").append(htmlEsc(dstNpuPort))
              .append("</h2>\n");

            sb.append("<h3>Forward (DATA, dataPort=").append(dataPort).append(")</h3>\n");
            sb.append("<div class=\"path-box\">\n");
            sb.append("<div class=\"hop h1\"><span class=\"tag t1\">\u2460 L1SW ECMP</span> ")
              .append(htmlEsc(shortName(srcNpu))).append(":").append(htmlEsc(srcNpuPort))
              .append(" \u2192 <strong>").append(htmlEsc(shortName(srcL1sw))).append("</strong>:").append(htmlEsc(srcL1swInPort))
              .append(" | hash % 64 = ").append(fwdIdx)
              .append(" \u2192 outPort ").append(htmlEsc(srcL1swOutPort))
              .append(" \u2192 ").append(htmlEsc(exL2sw)).append(":").append(htmlEsc(srcL2swInPort))
              .append(" \u2192 FORWARD</div>\n");
            sb.append("<div class=\"hop h2\"><span class=\"tag t2\">\u2461 L2SW forwarding</span> ")
              .append(htmlEsc(exL2sw)).append(":").append(htmlEsc(srcL2swInPort))
              .append(" \u2192 chassis routing \u2192 outPort ").append(htmlEsc(fwdL2swOutPortName))
              .append(" \u2192 <strong>").append(htmlEsc(shortName(dstL1sw))).append("</strong>:").append(htmlEsc(dstL1swIn2Port))
              .append(" \u2192 FORWARD</div>\n");
            sb.append("<div style=\"padding:2px 8px;margin:2px 0;border-left:3px solid #aaa;color:#888\">")
              .append("dstL1SW host route: ").append(htmlEsc(shortName(dstL1sw))).append(":").append(htmlEsc(dstL1swIn2Port))
              .append(" \u2192 ").append(htmlEsc(shortName(dstNpu))).append(":").append(htmlEsc(dstNpuPort))
              .append("</div>\n");
            sb.append("</div>\n");

            sb.append("<h3>Reverse (ACK, ackPort=").append(ackPort).append(")</h3>\n");
            sb.append("<div class=\"path-box\">\n");
            sb.append("<div class=\"hop h3\"><span class=\"tag t3\">\u2462 L1SW ECMP</span> ")
              .append(htmlEsc(shortName(dstNpu))).append(":").append(htmlEsc(dstNpuPort))
              .append(" \u2192 <strong>").append(htmlEsc(shortName(dstL1sw))).append("</strong>:").append(htmlEsc(dstL1swInPort))
              .append(" | hash % 64 = ").append(revIdx)
              .append(" \u2192 outPort ").append(htmlEsc(dstL1swOutPort))
              .append(" \u2192 ").append(htmlEsc(exL2sw)).append(":").append(htmlEsc(dstL2swInPort))
              .append(" \u2192 REVERSE</div>\n");
            sb.append("<div class=\"hop h4\"><span class=\"tag t4\">\u2463 L2SW forwarding</span> ")
              .append(htmlEsc(exL2sw)).append(":").append(htmlEsc(dstL2swInPort))
              .append(" \u2192 chassis routing \u2192 outPort ").append(htmlEsc(revL2swOutPortName))
              .append(" \u2192 <strong>").append(htmlEsc(shortName(srcL1sw))).append("</strong>:").append(htmlEsc(srcL1swIn2Port))
              .append(" \u2192 REVERSE</div>\n");
            sb.append("<div style=\"padding:2px 8px;margin:2px 0;border-left:3px solid #aaa;color:#888\">")
              .append("srcL1SW host route: ").append(htmlEsc(shortName(srcL1sw))).append(":").append(htmlEsc(srcL1swIn2Port))
              .append(" \u2192 ").append(htmlEsc(shortName(srcNpu))).append(":").append(htmlEsc(srcNpuPort))
              .append("</div>\n");
            sb.append("</div>\n");

            sb.append("<h3>Full Hop-by-Hop Path Diagram</h3>\n");
            sb.append("<div style=\"text-align:center\">\n");
            appendDetailedPathSvg(sb, srcNpu, srcNpuPort, srcL1sw, srcL1swInPort, srcL1swOutPort,
                exL2sw, srcL2swInPort, fwdL2swOutPortName, fwdL2swOutL1Port,
                dstL1sw, dstL1swIn2Port, dstL1swInPort, dstL1swOutPort,
                dstNpu, dstNpuPort,
                fwdIdx, revIdx, dataPort, ackPort,
                dstL2swInPort, revL2swOutPortName, revL2swOutL1Port);
            sb.append("</div>\n");
            sb.append("</div>\n");
        }

        sb.append("<div class=\"card\">\n<h2>All ").append(totalPairs).append(" Pairs and Their 4 Paths</h2>\n");
        sb.append("<div style=\"max-height:600px;overflow-y:auto\">\n");
        sb.append("<table class=\"pairs\" id=\"pairsTable\">\n");
        sb.append("<tr><th>#</th><th>Src NPU:port</th><th>Dst NPU:port</th>")
          .append("<th>\u2460 fwd: srcL1SW\u2192L2SW</th><th>\u2461 fwd: L2SW\u2192dstL1SW</th>")
          .append("<th>\u2462 rev: dstL1SW\u2192L2SW</th><th>\u2463 rev: L2SW\u2192srcL1SW</th></tr>\n");
        for (int i = 0; i < totalPairs; i++) {
            CoveredEidPair p = pairs.get(i);
            sb.append("<tr>");
            sb.append("<td><strong>").append(i + 1).append("</strong></td>");
            sb.append("<td style=\"font-size:11px\">").append(htmlEsc(shortName(p.getSrcDevice()))).append(":").append(htmlEsc(p.getSrcPort())).append("</td>");
            sb.append("<td style=\"font-size:11px\">").append(htmlEsc(shortName(p.getDestDevice()))).append(":").append(htmlEsc(p.getDestPort())).append("</td>");

            CoverageLink[][] types = {
                type1[i].isEmpty() ? null : new CoverageLink[]{type1[i].get(0)},
                type2[i].isEmpty() ? null : new CoverageLink[]{type2[i].get(0)},
                type3[i].isEmpty() ? null : new CoverageLink[]{type3[i].get(0)},
                type4[i].isEmpty() ? null : new CoverageLink[]{type4[i].get(0)}
            };
            String[] tags = {"t1", "t2", "t3", "t4"};
            for (int t = 0; t < 4; t++) {
                sb.append("<td>");
                if (types[t] != null) {
                    CoverageLink l = types[t][0];
                    String devName = l.getSwitchDevice() != null ? shortName(l.getSwitchDevice()) : "";
                    String outPName = l.getOutPort() != null ? l.getOutPort() : (l.getOutPortIndex() != null ? String.valueOf(l.getOutPortIndex()) : "?");
                    String remoteName = l.getRemoteSwitch() != null ? shortName(l.getRemoteSwitch()) : "";
                    String remotePName = l.getRemotePort() != null ? l.getRemotePort() : "?";
                    sb.append("<span class=\"tag ").append(tags[t]).append("\">")
                      .append(devName).append(":").append(htmlEsc(outPName))
                      .append(" \u2192 ").append(remoteName).append(":").append(htmlEsc(remotePName))
                      .append("</span>");
                }
                sb.append("</td>");
            }
            sb.append("</tr>\n");
        }
        sb.append("</table>\n</div>\n</div>\n");

        Map<String, Integer> npuPortUsage = new LinkedHashMap<>();
        Map<String, int[]> npuTaskCount = new LinkedHashMap<>();
        for (int i = 0; i < totalPairs; i++) {
            CoveredEidPair p = pairs.get(i);
            String sNpuKey = shortName(p.getSrcDevice()) + ":" + p.getSrcPort();
            String dNpuKey = shortName(p.getDestDevice()) + ":" + p.getDestPort();
            npuPortUsage.merge(sNpuKey, 1, Integer::sum);
            npuPortUsage.merge(dNpuKey, 1, Integer::sum);

            String srcNpuShort = shortName(p.getSrcDevice());
            String dstNpuShort = shortName(p.getDestDevice());
            npuTaskCount.computeIfAbsent(srcNpuShort, k -> new int[]{0, 0});
            npuTaskCount.get(srcNpuShort)[0]++;
            npuTaskCount.computeIfAbsent(dstNpuShort, k -> new int[]{0, 0});
            npuTaskCount.get(dstNpuShort)[1]++;
        }

        sb.append("<div class=\"card\">\n<h2>NPU Port Usage</h2>\n");
        sb.append("<p>Total NPU ports referenced: ").append(npuPortUsage.size())
          .append(" | min=").append(npuPortUsage.values().stream().min(Integer::compare).orElse(0))
          .append(" max=").append(npuPortUsage.values().stream().max(Integer::compare).orElse(0))
          .append(" avg=").append(String.format("%.1f", npuPortUsage.values().stream().mapToInt(v -> v).average().orElse(0)))
          .append("</p>\n");
        sb.append("<div style=\"max-height:300px;overflow-y:auto\">\n<table class=\"pairs\" id=\"npuPortUsageTable\">\n");
        sb.append("<tr><th>NPU Port</th><th>Usage Count</th></tr>\n");
        npuPortUsage.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .forEach(e -> sb.append("<tr><td>").append(htmlEsc(e.getKey())).append("</td><td>").append(e.getValue()).append("</td></tr>\n"));
        sb.append("</table>\n</div>\n");
        sb.append("</div>\n");

        sb.append("<div class=\"card\">\n<h2>NPU Task Count (Evaluation)</h2>\n");
        sb.append("<p>Number of EID pairs each NPU card is involved in (as source or destination).</p>\n");
        sb.append("<div style=\"max-height:400px;overflow-y:auto\">\n<table class=\"pairs\" id=\"npuTaskCountTable\">\n");
        sb.append("<tr><th>NPU Card</th><th>As Src (pairs)</th><th>As Dst (pairs)</th><th>Total Tasks</th></tr>\n");
        npuTaskCount.entrySet().stream()
            .sorted((a, b) -> (b.getValue()[0] + b.getValue()[1]) - (a.getValue()[0] + a.getValue()[1]))
            .forEach(e -> sb.append("<tr><td>").append(htmlEsc(e.getKey())).append("</td>")
                .append("<td>").append(e.getValue()[0]).append("</td>")
                .append("<td>").append(e.getValue()[1]).append("</td>")
                .append("<td><strong>").append(e.getValue()[0] + e.getValue()[1]).append("</strong></td></tr>\n"));
        sb.append("</table>\n</div>\n");
        sb.append("</div>\n");

        sb.append("<div class=\"card\">\n<h2>Verification</h2>\n");
        sb.append("<p>Total: ").append(tl).append(" out-ports, 100% covered by ")
          .append(totalPairs).append(" EID pairs (each covers 4 out-ports).</p>\n");
        sb.append("<p>Mode: DIFF_PATH (正反不同路，正反向路径各自独立规划)</p>\n");
        sb.append("<p>Algorithms:</p>\n<ul style=\"padding-left:20px;line-height:1.8\">\n");
        sb.append("<li>\u2460 L1SW ECMP: hash(CNA1,CNA2,dataPort) % 64 \u2192 srcL1SW outPort \u2192 <strong>FORWARD</strong></li>\n");
        sb.append("<li>\u2461 L2SW forwarding: chassis routing \u2192 dstL1SW inPort \u2192 <strong>FORWARD</strong></li>\n");
        sb.append("<li>\u2462 L1SW ECMP: hash(CNA2,CNA1,ackPort) % 64 \u2192 dstL1SW outPort \u2192 <strong>REVERSE</strong></li>\n");
        sb.append("<li>\u2463 L2SW forwarding: chassis routing \u2192 srcL1SW inPort \u2192 <strong>REVERSE</strong></li>\n");
        sb.append("</ul>\n");
        sb.append("<p>EID pair stats: unique=").append(result.getStats().getUniqueEidCount())
          .append(" EIDs, total appearances=").append(result.getStats().getTotalEidAppearances())
          .append(", repeat rate=").append(String.format("%.1f%%", result.getStats().getEidRepeatRate() * 100))
          .append(", per-EID min=").append(result.getStats().getEidMinRepeat())
          .append(" max=").append(result.getStats().getEidMaxRepeat())
          .append(" avg=").append(String.format("%.1f", result.getStats().getEidAvgRepeat())).append("</p>\n");
        int coveredLinks = result.getCoverageLinks() != null ? result.getCoverageLinks().size() : 0;
        sb.append("<p style=\"font-size:18px;color:#2e7d32;font-weight:bold\">Coverage: ")
          .append(coveredLinks).append(" out-ports / ").append(tl).append(" \u2714 100%</p>\n");
        sb.append("<p style=\"font-size:13px;color:#666\">说明：覆盖单元为交换机出端口——每条 L1SW↔L2SW 物理链路计 2 个出端口（L1SW 端 + L2SW 端），")
          .append(tl / 2).append(" 条物理链路 → ").append(tl).append(" 个出端口覆盖点（L1SW ").append(tl / 2)
          .append(" + L2SW ").append(tl / 2).append("）。</p>\n");
        sb.append("</div>\n");

        sb.append("<div class=\"card\">\n<h2>Link Verification Tool</h2>\n");
        sb.append("<p>Enter a link identifier (e.g. device short name like \"r1.1\" or port name like \"400GUB 1/2/27\") to find all EID pairs and their path segments that cover this link.</p>\n");
        sb.append("<div style=\"margin:12px 0;display:flex;gap:8px;align-items:center\">\n");
        sb.append("<input type=\"text\" id=\"verifyInput\" placeholder=\"e.g. r1.1 or 400GUB 1/2/27\" style=\"padding:8px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;width:300px\">\n");
        sb.append("<button onclick=\"doVerify()\" style=\"padding:8px 16px;background:#1976d2;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:bold;cursor:pointer\">Search</button>\n");
        sb.append("</div>\n");
        sb.append("<div id=\"verifyResult\"></div>\n");
        sb.append("</div>\n");

        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private static final int HASH_PROTOCOL = 17;

    /**
     * Computes the ECMP port index for one hop via {@code nativeHash}.
     * {@code ecmpCnt} is the ECMP member count from route lookup
     * ({@code totalOutPorts}), so the result is already the port index.
     *
     * @return port index in {@code [0, ecmpCnt)}, or {@code -1} when the link
     *         has no usable port count
     */
    private static int nativePortIdx(String dip, String sip, int sport, int dport,
                                     CoverageLink link, int hashFunc, HashTuple hashTuple) {
        if (link == null) return -1;
        int ecmpCnt = link.getTotalOutPorts() != null ? link.getTotalOutPorts() : 0;
        if (ecmpCnt <= 0) return -1;
        switch (hashTuple) {
            case THREE:
                return HashUtils.nativeHash(dip, sip, 0, sport, 0,
                                            ecmpCnt, hashFunc);
            case FOUR:
                return HashUtils.nativeHash(dip, sip, dport, sport, 0,
                                            ecmpCnt, hashFunc);
            case FIVE:
                return HashUtils.nativeHash(dip, sip, dport, sport, HASH_PROTOCOL,
                                            ecmpCnt, hashFunc);
            case TWO:
            default:
                return HashUtils.nativeHash(dip, sip, ecmpCnt, hashFunc);
        }
    }

    static String[] getSortedPortNames() {
        String[] raw = new String[64];
        for (int i = 0; i < 64; i++) raw[i] = "400GUB 1/2/" + i;
        Arrays.sort(raw);
        return raw;
    }

    static String shortName(String full) {
        if (full == null) return "";
        return full.replace("rack", "r").replace("#l1sw", ".").replace("#board", ".").replace("#npu", ".").replace("#l2sw", ".");
    }

    static void appendDetailedPathSvg(StringBuilder sb,
        String srcNpu, String srcNpuPort,
        String srcL1sw, String srcL1swInPort, String srcL1swOutPort,
        String l2sw,
        String l2swFwdInPort, String l2swFwdOutPortName, String l2swFwdOutL1Port,
        String dstL1sw, String dstL1swIn2Port, String dstL1swInPort, String dstL1swOutPort,
        String dstNpu, String dstNpuPort,
        int fwdIdx, int revIdx, int dataPort, int ackPort,
        String l2swRevInPort, String l2swRevOutPortName, String l2swRevOutL1Port) {

        int w = 1100, h = 520;
        String fwdColor = "#e53935";
        String revColor = "#1e88e5";

        sb.append("<svg viewBox=\"0 0 ").append(w).append(" ").append(h)
          .append("\" style=\"max-width:100%;height:auto;background:#fafafa;border-radius:8px\">\n");

        int npuW = 140, npuH = 70;
        int l1swW = 140, l1swH = 90;
        int l2swW = 160, l2swH = 90;
        int gapX = 70;

        int row1Y = 50;
        int srcNpuX = 30;
        int srcL1swX = srcNpuX + npuW + gapX;
        int l2swX = srcL1swX + l1swW + gapX;
        int dstL1swX = l2swX + l2swW + gapX;
        int dstNpuX = dstL1swX + l1swW + gapX;

        appendDeviceBox(sb, srcNpuX, row1Y, npuW, npuH, shortName(srcNpu), "NPU", srcNpuPort, null, "#e53935", 0.2);
        appendL1swBox(sb, srcL1swX, row1Y, l1swW, l1swH, shortName(srcL1sw), srcL1swInPort, srcL1swOutPort, fwdColor, "SRC");
        appendL2swBox(sb, l2swX, row1Y, l2swW, l2swH, l2sw, l2swFwdInPort, l2swFwdOutPortName, fwdColor, "DATA \u2192");
        appendL1swBox(sb, dstL1swX, row1Y, l1swW, l1swH, shortName(dstL1sw), dstL1swIn2Port, "?", revColor, "DST");
        appendDeviceBox(sb, dstNpuX, row1Y, npuW, npuH, shortName(dstNpu), "NPU", dstNpuPort, null, "#1e88e5", 0.2);

        int srcNpuR = srcNpuX + npuW;
        int srcL1swL = srcL1swX;
        int srcL1swR = srcL1swX + l1swW;
        int l2swL = l2swX;
        int l2swR = l2swX + l2swW;
        int dstL1swL = dstL1swX;
        int dstL1swR = dstL1swX + l1swW;
        int dstNpuL = dstNpuX;

        int row1MidY = row1Y + npuH / 2 - 10;

        appendLink(sb, srcNpuR, row1MidY, srcL1swL, row1MidY,
            srcNpuPort + " \u2192 " + srcL1swInPort, fwdColor, 2.5, "8,4");
        appendLink(sb, srcL1swR, row1MidY, l2swL, row1MidY,
            srcL1swOutPort + " \u2192 " + l2swFwdInPort + " (hash%64=" + fwdIdx + ")", fwdColor, 2.5, "8,4");
        appendLink(sb, l2swR, row1MidY, dstL1swL, row1MidY,
            l2swFwdOutPortName + " \u2192 " + dstL1swIn2Port, fwdColor, 2.5, "8,4");
        appendLink(sb, dstL1swR, row1MidY + 25, dstNpuL, row1MidY + 25,
            dstNpuPort + " (host route)", fwdColor, 1.5, "4,4");

        sb.append("<text x=\"").append(w / 2).append("\" y=\"").append(row1Y - 8)
          .append("\" text-anchor=\"middle\" font-size=\"12\" font-weight=\"bold\" fill=\"").append(fwdColor).append("\">")
          .append("Forward: \u2460\u2461 DATA (dataPort=").append(dataPort).append(")</text>\n");

        int row2Y = row1Y + npuH + 100;
        int row2MidY = row2Y + npuH / 2 - 10;

        appendDeviceBox(sb, srcNpuX, row2Y, npuW, npuH, shortName(dstNpu), "NPU", dstNpuPort, null, "#1e88e5", 0.2);
        appendL1swBox(sb, srcL1swX, row2Y, l1swW, l1swH, shortName(dstL1sw), dstL1swInPort, dstL1swOutPort, revColor, "DST");
        appendL2swBox(sb, l2swX, row2Y, l2swW, l2swH, l2sw, l2swRevInPort, l2swRevOutPortName, revColor, "ACK \u2192");
        appendL1swBox(sb, dstL1swX, row2Y, l1swW, l1swH, shortName(srcL1sw), l2swRevOutL1Port, "?", fwdColor, "SRC");
        appendDeviceBox(sb, dstNpuX, row2Y, npuW, npuH, shortName(srcNpu), "NPU", srcNpuPort, null, "#e53935", 0.2);

        appendLink(sb, srcNpuR, row2MidY, srcL1swL, row2MidY,
            dstNpuPort + " \u2192 " + dstL1swInPort, revColor, 2.5, "6,3");
        appendLink(sb, srcL1swR, row2MidY, l2swL, row2MidY,
            dstL1swOutPort + " \u2192 " + l2swRevInPort + " (hash%64=" + revIdx + ")", revColor, 2.5, "6,3");
        appendLink(sb, l2swR, row2MidY, dstL1swL, row2MidY,
            l2swRevOutPortName + " \u2192 " + l2swRevOutL1Port, revColor, 2.5, "6,3");
        appendLink(sb, dstL1swR, row2MidY + 25, dstNpuL, row2MidY + 25,
            srcNpuPort + " (host route)", revColor, 1.5, "3,3");

        sb.append("<text x=\"").append(w / 2).append("\" y=\"").append(row2Y - 8)
          .append("\" text-anchor=\"middle\" font-size=\"12\" font-weight=\"bold\" fill=\"").append(revColor).append("\">")
          .append("Reverse: \u2462\u2463 ACK (ackPort=").append(ackPort).append(")</text>\n");

        sb.append("</svg>\n");
    }

    static void appendDeviceBox(StringBuilder sb, int x, int y, int w, int h,
                                 String label, String type, String portName, String cna,
                                 String color, double opacity) {
        sb.append("<rect x=\"").append(x).append("\" y=\"").append(y)
          .append("\" width=\"").append(w).append("\" height=\"").append(h)
          .append("\" rx=\"8\" fill=\"").append(color).append("\" fill-opacity=\"").append(opacity)
          .append("\" stroke=\"").append(color).append("\" stroke-width=\"2\"/>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 18)
          .append("\" text-anchor=\"middle\" font-size=\"11\" font-weight=\"bold\" fill=\"#333\">")
          .append(htmlEsc(label)).append("</text>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 32)
          .append("\" text-anchor=\"middle\" font-size=\"9\" fill=\"#666\">").append(type).append("</text>\n");
        if (portName != null) {
            sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + h - 12)
              .append("\" text-anchor=\"middle\" font-size=\"9\" fill=\"#555\" font-family=\"monospace\">")
              .append(htmlEsc(portName)).append("</text>\n");
        }
        if (cna != null) {
            sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 45)
              .append("\" text-anchor=\"middle\" font-size=\"8\" fill=\"#999\" font-family=\"monospace\">")
              .append("CNA=").append(htmlEsc(cna)).append("</text>\n");
        }
    }

    static void appendL1swBox(StringBuilder sb, int x, int y, int w, int h,
                               String label, String npuFacingPort, String l2swFacingPort,
                               String color, String role) {
        sb.append("<rect x=\"").append(x).append("\" y=\"").append(y)
          .append("\" width=\"").append(w).append("\" height=\"").append(h)
          .append("\" rx=\"6\" fill=\"#fff\" stroke=\"").append(color).append("\" stroke-width=\"2.5\"/>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 14)
          .append("\" text-anchor=\"middle\" font-size=\"10\" font-weight=\"bold\" fill=\"#333\">")
          .append(htmlEsc(label)).append(" (").append(role).append(")</text>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 28)
          .append("\" text-anchor=\"middle\" font-size=\"8\" fill=\"#888\">L1SW</text>\n");

        if (npuFacingPort != null) {
            sb.append("<text x=\"").append(x + 6).append("\" y=\"").append(y + 42)
              .append("\" font-size=\"8\" fill=\"#555\" font-family=\"monospace\">in: ")
              .append(htmlEsc(npuFacingPort)).append("</text>\n");
        }
        if (l2swFacingPort != null) {
            sb.append("<text x=\"").append(x + 6).append("\" y=\"").append(y + 54)
              .append("\" font-size=\"8\" fill=\"#555\" font-family=\"monospace\">out: ")
              .append(htmlEsc(l2swFacingPort)).append("</text>\n");
        }

        sb.append("<line x1=\"").append(x).append("\" y1=\"").append(y + 60)
          .append("\" x2=\"").append(x + w).append("\" y2=\"").append(y + 60)
          .append("\" stroke=\"#ddd\" stroke-width=\"1\"/>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + h - 8)
          .append("\" text-anchor=\"middle\" font-size=\"7\" fill=\"#aaa\">ECMP 64 ports (1/2/0~1/2/63)</text>\n");
    }

    static void appendL2swBox(StringBuilder sb, int x, int y, int w, int h,
                               String label, String inPort, String outPort,
                               String color, String dirLabel) {
        sb.append("<rect x=\"").append(x).append("\" y=\"").append(y)
          .append("\" width=\"").append(w).append("\" height=\"").append(h)
          .append("\" rx=\"6\" fill=\"#fff3e0\" stroke=\"").append(color).append("\" stroke-width=\"2.5\"/>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 14)
          .append("\" text-anchor=\"middle\" font-size=\"10\" font-weight=\"bold\" fill=\"#333\">")
          .append(htmlEsc(label)).append("</text>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + 28)
          .append("\" text-anchor=\"middle\" font-size=\"8\" fill=\"#888\">L2SW (2 chips)</text>\n");

        if (inPort != null) {
            sb.append("<text x=\"").append(x + 6).append("\" y=\"").append(y + 42)
              .append("\" font-size=\"8\" fill=\"#555\" font-family=\"monospace\">in: ")
              .append(htmlEsc(inPort)).append("</text>\n");
        }
        if (outPort != null) {
            sb.append("<text x=\"").append(x + 6).append("\" y=\"").append(y + 54)
              .append("\" font-size=\"8\" fill=\"#555\" font-family=\"monospace\">out: ")
              .append(htmlEsc(outPort)).append("</text>\n");
        }

        sb.append("<line x1=\"").append(x).append("\" y1=\"").append(y + 60)
          .append("\" x2=\"").append(x + w).append("\" y2=\"").append(y + 60)
          .append("\" stroke=\"#ddd\" stroke-width=\"1\"/>\n");
        sb.append("<text x=\"").append(x + w / 2).append("\" y=\"").append(y + h - 8)
          .append("\" text-anchor=\"middle\" font-size=\"8\" font-weight=\"bold\" fill=\"").append(color).append("\">")
          .append(dirLabel).append("</text>\n");
    }

    static void appendLink(StringBuilder sb, int x1, int y1, int x2, int y2,
                            String label, String color, double width, String dash) {
        sb.append("<line x1=\"").append(x1).append("\" y1=\"").append(y1)
          .append("\" x2=\"").append(x2).append("\" y2=\"").append(y2)
          .append("\" stroke=\"").append(color).append("\" stroke-width=\"").append(width)
          .append("\" stroke-dasharray=\"").append(dash).append("\"/>\n");
        int midX = (x1 + x2) / 2;
        int midY = y1 - 8;
        sb.append("<text x=\"").append(midX).append("\" y=\"").append(midY)
          .append("\" text-anchor=\"middle\" font-size=\"8\" fill=\"#333\" font-family=\"monospace\">")
          .append(htmlEsc(label)).append("</text>\n");
    }

    static void traceHop(StringBuilder sb, String device, String port, String direction,
                          String routeInfo, String hashInput, long hashValue, String portSelect,
                          String outPort, String nextHop, String hopType,
                          long expectedHash, int expectedIdx, int totalPorts, boolean valid) {
        String bg;
        if (hopType.contains("DIRECT")) bg = "style=\"background:#e8f5e9\"";
        else if (hopType.contains("HOST")) bg = "style=\"background:#fff8e1\"";
        else bg = "style=\"background:#e3f2fd\"";
        sb.append("<tr").append(bg).append(">");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-weight:bold;font-size:10px\">").append(hopType).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:10px\">").append(htmlEsc(device)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-size:10px\">").append(htmlEsc(direction)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-size:10px\">").append(htmlEsc(routeInfo)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:9px\">").append(htmlEsc(hashInput)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:10px\">").append(hashValue > 0 ? String.valueOf(hashValue) : "-").append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:10px\">").append(htmlEsc(portSelect)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:10px\">").append(htmlEsc(outPort)).append("</td>");
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc;font-family:monospace;font-size:10px\">").append(htmlEsc(nextHop)).append("</td>");
        String vCls = valid ? "v_ok" : "v_fail";
        String vLabel;
        if (hopType.contains("DIRECT") || hopType.contains("HOST")) {
            vLabel = "\u2713";
        } else if (totalPorts > 0) {
            long computed = expectedHash % totalPorts;
            vLabel = valid ? ("\u2713 " + computed + "==" + expectedIdx) : ("\u2717 " + computed + "!=" + expectedIdx);
        } else {
            vLabel = "-";
        }
        sb.append("<td style=\"padding:3px 6px;border:1px solid #ccc\" class=\"").append(vCls).append("\">").append(vLabel).append("</td>");
        sb.append("</tr>\n");
    }

    static String htmlEsc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
