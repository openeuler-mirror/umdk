/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.dto.HopInfo;
import com.huawei.umdk.snc.dto.PathInfo;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.dto.CoverageLink;
import com.huawei.umdk.snc.dto.CoveragePathsRequest;
import com.huawei.umdk.snc.dto.CoveragePathsResult;
import com.huawei.umdk.snc.dto.CoverageStats;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.dto.CoveredEidPair;
import com.huawei.umdk.snc.dto.CoveredEidPairRef;
import com.huawei.umdk.snc.engine.CoveragePlanEngine;
import com.huawei.umdk.snc.engine.CoveragePlanEngine.CoveredLinkDetail;
import com.huawei.umdk.snc.engine.CoveragePlanEngine.CoverageSearchResult;
import com.huawei.umdk.snc.engine.CoveragePlanEngine.CoveredPair;
import com.huawei.umdk.snc.engine.CoveragePlanEngine.LinkInfo;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.InternalPathHop;
import com.huawei.umdk.snc.exception.PathPlanException;
import com.huawei.umdk.snc.entity.InternalPathInfo;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RouteSelectionRecord;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutingTableKey;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.store.SuperNodeStore;
import com.huawei.umdk.snc.util.AddressUtils;

public class PathService {
    private static final Logger LOG = new Logger(PathService.class);

    private final SuperNodeStore superNodeStore;
    private final PathEngine pathEngine;
    private final RouteLookupEngine routeLookupEngine;
    private final CoveragePlanEngine coveragePlanEngine;
    public PathService(SuperNodeStore superNodeStore,
                       PathEngine pathEngine, RouteLookupEngine routeLookupEngine,
                       CoveragePlanEngine coveragePlanEngine) {
        this.superNodeStore = superNodeStore;
        this.pathEngine = pathEngine;
        this.routeLookupEngine = routeLookupEngine;
        this.coveragePlanEngine = coveragePlanEngine;
    }

    public PathPlanResult planPath(PathPlanRequest request) {
        LOG.info("planPath: superNode=" + request.getSuperNodeName()
            + ", src=" + request.getSrcDevice() + "/" + request.getSrcPort()
            + ", dst=" + request.getDestDevice() + "/" + request.getDestPort());

        // Step 0: SuperNode lookup
        SuperNode superNode = superNodeStore.getSuperNode(request.getSuperNodeName());
        if (superNode == null) {
            LOG.error("planPath: error=SuperNode topology not found, superNode=%s", request.getSuperNodeName());
            return new PathPlanResult(PlanStatus.TOPO_NOT_FOUND,
                "SuperNode topology not found: " + request.getSuperNodeName());
        }

        LOG.debug("planPath: SuperNode found, superNode=" + request.getSuperNodeName());

        DeviceEntity srcDevice = superNode.getAllDevices().get(request.getSrcDevice());
        DeviceEntity destDevice = superNode.getAllDevices().get(request.getDestDevice());
        if (srcDevice == null || destDevice == null) {
            if (srcDevice == null) {
                LOG.error("planPath: error=Source device not found in topology, src=%s", request.getSrcDevice());
            }
            if (destDevice == null) {
                LOG.error("planPath: error=Destination device not found in topology, dst=%s", request.getDestDevice());
            }
            return new PathPlanResult(PlanStatus.TOPO_INCOMPLETE,
                "Source or destination device not found");
        }

        // Both must be NPU
        if (srcDevice.getDeviceType() != DeviceType.NPU
            || destDevice.getDeviceType() != DeviceType.NPU) {
            if (srcDevice.getDeviceType() != DeviceType.NPU) {
                LOG.error("planPath: error=Source must be NPU device, src=%s, deviceType=%s",
                    request.getSrcDevice(), srcDevice.getDeviceType());
            }
            if (destDevice.getDeviceType() != DeviceType.NPU) {
                LOG.error("planPath: error=Destination must be NPU device, dst=%s, deviceType=%s",
                    request.getDestDevice(), destDevice.getDeviceType());
            }
            return new PathPlanResult(PlanStatus.SRC_AND_DST_MUST_BE_NPU,
                "Both source and destination must be NPU");
        }
        NpuDevice srcNpuDevice = (NpuDevice) srcDevice;
        NpuDevice destNpuDevice = (NpuDevice) destDevice;
        LOG.debug("planPath: srcNpu=%s, dstNpu=%s",
            srcNpuDevice.getDeviceName(), destNpuDevice.getDeviceName());

        // Step 1: Find src port
        LOG.debug("planPath: finding source port, srcPort=" + request.getSrcPort());
        NpuPortEntity srcNpuPort = srcNpuDevice.findNpuPort(request.getSrcPort());
        if (srcNpuPort == null) {
            LOG.error("planPath: error=Source port not found or invalid, srcPort=" + request.getSrcPort());
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source port not found or invalid");
        }
        String srcEid = srcNpuPort.getEid();
        String srcCna = srcNpuPort.getCna();
        String srcRemoteDevice = srcNpuPort.getRemoteDevice();
        String srcRemotePort = srcNpuPort.getRemotePort();
        if (srcEid == null || srcCna == null) {
            LOG.error("planPath: error=Source EID or CNA missing, srcEid=" + srcEid + ", srcCna=" + srcCna);
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source EID or CNA missing");
        }
        if (!AddressUtils.isValidEid(srcEid)) {
            LOG.error("planPath: error=Source EID format invalid, srcEid=" + srcEid);
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source EID format invalid");
        }
        if (!AddressUtils.isValidCna(srcCna)) {
            LOG.error("planPath: error=Source CNA format invalid, srcCna=" + srcCna);
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source CNA format invalid");
        }
        LOG.debug("planPath: src port found, eid=" + srcEid + ", cna=" + srcCna);

        // Step 2: Find dest port
        LOG.debug("planPath: finding destination port, dstPort=" + request.getDestPort());
        NpuPortEntity destNpuPort = destNpuDevice.findNpuPort(request.getDestPort());
        if (destNpuPort == null) {
            LOG.error("planPath: error=Destination port not found or invalid, dstPort=" + request.getDestPort());
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination port not found or invalid");
        }
        String dstEid = destNpuPort.getEid();
        String destCna = destNpuPort.getCna();
        if (dstEid == null || destCna == null) {
            LOG.error("planPath: error=Destination EID or CNA missing, dstEid=" + dstEid + ", destCna=" + destCna);
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination EID or CNA missing");
        }
        if (!AddressUtils.isValidEid(dstEid)) {
            LOG.error("planPath: error=Destination EID format invalid, dstEid=" + dstEid);
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination EID format invalid");
        }
        if (!AddressUtils.isValidCna(destCna)) {
            LOG.error("planPath: error=Destination CNA format invalid, destCna=" + destCna);
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination CNA format invalid");
        }
        LOG.debug("planPath: dst port found, eid=" + dstEid + ", cna=" + destCna);

        // Check UPI consistency
        if (srcNpuPort.getUpi() != null && destNpuPort.getUpi() != null) {
            if (!srcNpuPort.getUpi().equals(destNpuPort.getUpi())) {
                LOG.error("planPath: error=UPI mismatch, srcUpi=" + srcNpuPort.getUpi()
                    + ", dstUpi=" + destNpuPort.getUpi());
                return new PathPlanResult(PlanStatus.UPI_MISMATCH,
                    "UPI mismatch between source and destination");
            }
            LOG.debug("planPath: upi=" + srcNpuPort.getUpi() + ", check=UPI consistency passed");
        }

        // Step 3: Direct or multi-hop
        Map<String, String> interDevices = request.getInterDevices();
        if (interDevices == null || interDevices.isEmpty()) {
            // Step 4: Direct path verification
            LOG.debug("planPath: Direct path mode");
            if (srcRemoteDevice == null
                || !srcRemoteDevice.equals(destNpuDevice.getDeviceName())
                || srcRemotePort == null
                || !srcRemotePort.equals(destNpuPort.getPortName())) {
                LOG.error("planPath: error=Direct connection not found, src=" + srcNpuDevice.getDeviceName()
                    + ", dst=" + destNpuDevice.getDeviceName());
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_ERROR,
                    "Direct connection not found between source and destination");
            }
            // Verify reverse direction too
            if (destNpuPort.getRemoteDevice() == null
                || !destNpuPort.getRemoteDevice().equals(srcNpuDevice.getDeviceName())
                || destNpuPort.getRemotePort() == null
                || !destNpuPort.getRemotePort().equals(srcNpuPort.getPortName())) {
                LOG.error("planPath: error=Reverse direct connection not found, src=" + destNpuDevice.getDeviceName()
                    + ", dst=" + srcNpuDevice.getDeviceName());
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_ERROR,
                    "Reverse direct connection not found");
            }

            InternalPathInfo directPath = pathEngine.resolveDirectPath(
                srcNpuDevice, srcNpuPort, destNpuDevice, destNpuPort);
            LOG.info("planPath: mode=direct, srcEid=" + directPath.getSrcEid() + ", dstEid=" + directPath.getDstEid());
            return buildResult(directPath);
        } else {
            // Step 5: Build multi-hop path
            LOG.debug("planPath: Multi-hop path mode, interDevicesCount=" + interDevices.size());
            InternalPathInfo multiHopPath;
            try {
                multiHopPath = pathEngine.resolveMultiHopPath(
                    srcNpuDevice, srcNpuPort,
                    destNpuDevice, destNpuPort, interDevices, superNode.getAllDevices());
                LOG.debug("planPath: multi-hop path built, hopCount=" + multiHopPath.getHops().size());
            } catch (Exception e) {
                LOG.error("planPath: error=Multi-hop path resolution failed, reason=" + e.getMessage());
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_NOT_FOUND,
                    "Multi-hop path resolution failed: " + e.getMessage());
            }

            // Step 6-8: Route lookup for intermediate devices (forward + reverse)
            String[] srcParts = srcCna.split("\\.");
            int refUdpPort = (Integer.parseInt(srcParts[2])
                ^ Integer.parseInt(srcParts[3])) & 0xFF;

            LOG.debug("planPath: Forward route phase, targetCna=%s", destCna);
            try {
                routePhase(multiHopPath,
                    destCna, request.getSuperNodeName(), srcCna, destCna,
                    RouteSelectionRecord.Direction.FORWARD, refUdpPort);
            } catch (PathPlanException e) {
                LOG.error("planPath: error=Forward route phase failed, reason=%s", e.getMessage());
                return new PathPlanResult(e.getStatus(), e.getMessage());
            }

            // Step 9: Reverse phase
            LOG.debug("planPath: Reverse route phase, targetCna=%s", srcCna);
            List<InternalPathHop> reversedHops = pathEngine.reverseHops(
                multiHopPath.getHops());
            InternalPathInfo reversedPath = new InternalPathInfo();
            reversedPath.setHops(reversedHops);
            reversedPath.setSrcEid(multiHopPath.getDstEid());
            reversedPath.setDstEid(multiHopPath.getSrcEid());
            reversedPath.setSourceCna(multiHopPath.getDestCna());
            reversedPath.setDestCna(multiHopPath.getSourceCna());

            try {
                routePhase(reversedPath,
                    srcCna, request.getSuperNodeName(), destCna, srcCna,
                    RouteSelectionRecord.Direction.REVERSE, refUdpPort);
            } catch (PathPlanException e) {
                LOG.error("planPath: error=Reverse route phase failed, reason=%s", e.getMessage());
                return new PathPlanResult(e.getStatus(), e.getMessage());
            }

            // Re-reverse back to forward order
            LOG.debug("planPath: Re-reversing hops back to forward order");
            List<InternalPathHop> restoredHops = pathEngine.reverseHops(reversedHops);
            multiHopPath.setHops(restoredHops);

            LOG.info("planPath: mode=multi-hop, srcEid=" + multiHopPath.getSrcEid()
                + ", dstEid=" + multiHopPath.getDstEid()
                + ", hopCount=" + (multiHopPath.getHops() != null ? multiHopPath.getHops().size() : 0));
            return buildResult(multiHopPath);
        }
    }

    private List<RouteSelectionRecord> routePhase(InternalPathInfo pathInfo, String targetCna,
                                                    String superNodeName, String scna, String dcna,
                                                    RouteSelectionRecord.Direction direction,
                                                    int refUdpPort) {
        LOG.debug("routePhase: targetCna=" + targetCna + ", superNode=" + superNodeName
            + ", hopCount=" + (pathInfo.getHops() != null ? pathInfo.getHops().size() : 0));
        List<InternalPathHop> hops = pathInfo.getHops();
        List<RouteSelectionRecord> records = new ArrayList<>();
        for (int i = 1; i < hops.size() - 1; i++) {
            InternalPathHop hop = hops.get(i);
            SuperNode sn = superNodeStore.getSuperNode(superNodeName);
            if (sn == null) {
                LOG.error("routePhase: error=TOPOLOGY_NOT_FOUND, superNode=%s", superNodeName);
                throw new PathPlanException(PlanStatus.TOPO_NOT_FOUND, "TOPOLOGY_NOT_FOUND: " + superNodeName);
            }
            DeviceEntity device = sn.getAllDevices().get(hop.getDeviceName());
            if (device == null) {
                LOG.error("routePhase: error=DEVICE_NOT_FOUND, device=%s, superNode=%s",
                    hop.getDeviceName(), superNodeName);
                throw new PathPlanException(PlanStatus.TOPO_CONNECTION_NOT_FOUND, "DEVICE_NOT_FOUND: " + hop.getDeviceName() + " in " + superNodeName);
            }

            RoutingEntry bestEntry = null;
            int bestMaskLen = -1;

            if (device.getForwardingChips() == null) {
                continue;
            }
            for (Integer chipIdx : device.getForwardingChips().keySet()) {
                RoutingTableKey rtKey = new RoutingTableKey(
                    superNodeName, hop.getDeviceName(), chipIdx);
                RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
                if (rt == null) {
                    continue;
                }
                RoutingEntry entry = routeLookupEngine.lookup(
                    targetCna, rt.getRoutes(), rt.getMaskLengths());
                if (entry != null && entry.getPrefix() != null
                    && entry.getPrefix().getMaskLength() > bestMaskLen) {
                    bestEntry = entry;
                    bestMaskLen = entry.getPrefix().getMaskLength();
                }
            }

            if (bestEntry == null) {
                LOG.error("routePhase: error=ROUTE_NOT_REACHABLE, device=%s, target=%s",
                    hop.getDeviceName(), targetCna);
                throw new PathPlanException(PlanStatus.ROUTE_NOT_REACHABLE, "ROUTE_NOT_REACHABLE: no route for device "
                    + hop.getDeviceName() + " to target " + targetCna);
            }

            List<OutPortInfo> outPortInfos = new ArrayList<>(bestEntry.getOutPortInfos().values());
            if (outPortInfos == null || outPortInfos.isEmpty()) {
                LOG.error("routePhase: error=ROUTE_NOT_REACHABLE, no outPort for device=%s",
                    hop.getDeviceName());
                throw new PathPlanException(PlanStatus.ROUTE_NOT_REACHABLE, "ROUTE_NOT_REACHABLE: no outPort for device "
                    + hop.getDeviceName());
            }

            // Candidate ports keep the received order for ECMP selection
            if (outPortInfos.size() > 1) {
                int selectedIndex = -1;
                String expectedPort = hop.getOutPort();
                for (int j = 0; j < outPortInfos.size(); j++) {
                    if (expectedPort.equals(outPortInfos.get(j).getPortName())) {
                        selectedIndex = j;
                        break;
                    }
                }
                if (direction == RouteSelectionRecord.Direction.FORWARD) {
                    if (selectedIndex < 0) {
                        throw new PathPlanException(PlanStatus.TOPO_CONNECTION_NOT_FOUND, "EXPECTED_PORT_NOT_FOUND: expected port "
                            + expectedPort + " not in route candidates for " + hop.getDeviceName()
                            + " route to " + targetCna);
                    }
                } else {
                    if (selectedIndex < 0) {
                        continue;
                    }
                }

                List<RouteSelectionRecord.CandidateOutPort> candidateOutPorts = new ArrayList<>();
                for (int j = 0; j < outPortInfos.size(); j++) {
                    OutPortInfo info = outPortInfos.get(j);
                    candidateOutPorts.add(new RouteSelectionRecord.CandidateOutPort(
                        info.getPortName(),
                        info.getNextHop(),
                        j == selectedIndex));
                }

                String hashInfo = scna + ":" + dcna;
                RouteSelectionRecord record = new RouteSelectionRecord(
                    hop.getDeviceName(),
                    bestEntry.getPrefix(),
                    candidateOutPorts,
                    scna, dcna, hashInfo, direction);
                records.add(record);
            } else {
                hop.setOutPort(outPortInfos.get(0).getPortName());
            }
            LOG.debug("routePhase: hopIndex=" + i + ", device=" + hop.getDeviceName()
                + ", outPort=" + hop.getOutPort() + ", mask=" + bestMaskLen);
        }
        return records.isEmpty() ? null : records;
    }

    public CoveragePathsResult planPathsCoverage(CoveragePathsRequest request) {
        if (request == null) {
            LOG.error("planPathsCoverage: error=CoveragePathsRequest must not be null");
            CoveragePathsResult result = new CoveragePathsResult();
            result.setStatus(PlanStatus.TOPO_NOT_FOUND);
            result.setErrorMessage("CoveragePathsRequest must not be null");
            return result;
        }
        if (request.getSuperNodeName() == null || request.getSuperNodeName().isEmpty()) {
            LOG.error("planPathsCoverage: error=superNodeName must not be null or empty");
            CoveragePathsResult result = new CoveragePathsResult();
            result.setStatus(PlanStatus.TOPO_NOT_FOUND);
            result.setErrorMessage("superNodeName is required for COVERAGE mode");
            return result;
        }
        LOG.info("planPathsCoverage: superNode=%s", request.getSuperNodeName());

        // Fixed UDP source ports come from SNCConfig (default 0), not the request.
        int dataUdpSrcPort = coveragePlanEngine.getFixedDataUdpPort();
        int ackUdpSrcPort = coveragePlanEngine.getFixedAckUdpPort();

        SuperNode superNode = superNodeStore.getSuperNode(request.getSuperNodeName());
        if (superNode == null) {
            LOG.error("planPathsCoverage: error=SuperNode not found, superNode=%s", request.getSuperNodeName());
            CoveragePathsResult result = new CoveragePathsResult();
            result.setStatus(PlanStatus.TOPO_NOT_FOUND);
            result.setErrorMessage("SuperNode not found: " + request.getSuperNodeName());
            return result;
        }

        CoverageRequirement requirement = request.getCoverageRequirement();
        CoverageSearchResult searchResult = coveragePlanEngine.findCoverage(
            superNode, dataUdpSrcPort, ackUdpSrcPort, requirement);
        LOG.debug("planPathsCoverage: coverage search done, fullCoverage=%s, coveredCount=%d, totalLinks=%d",
            searchResult.fullCoverage, searchResult.coveredCount, searchResult.totalLinks);

        // Build eidPairs from CoveragePlanEngine results
        // Note: generateHtml() only uses coveredLinks (fixed 4-per-pair order) to render paths.
        List<CoveredEidPair> eidPairs = new ArrayList<>();
        for (CoveredPair pair : searchResult.selectedPairs) {
            List<CoverageLink> pairLinks = new ArrayList<>();
            for (CoveragePlanEngine.CoveredLinkDetail d : pair.forwardLinkDetails) {
                pairLinks.add(toCoverageLinkFromDetail(d));
            }
            for (CoveragePlanEngine.CoveredLinkDetail d : pair.reverseLinkDetails) {
                pairLinks.add(toCoverageLinkFromDetail(d));
            }

            CoveredEidPair eidPair = new CoveredEidPair();
            eidPair.setSrcEid(pair.src.eid);
            eidPair.setDstEid(pair.dst.eid);
            eidPair.setSrcCna(pair.src.cna);
            eidPair.setDstCna(pair.dst.cna);
            eidPair.setSrcDevice(pair.src.deviceName);
            eidPair.setSrcPort(pair.src.portName);
            eidPair.setDestDevice(pair.dst.deviceName);
            eidPair.setDestPort(pair.dst.portName);
            eidPair.setCoveredLinks(pairLinks);
            eidPairs.add(eidPair);
        }

        LOG.debug("planPathsCoverage: eidPairs built, count=%d", eidPairs.size());

        // Build coverage links
        List<CoverageLink> coverageLinks = new ArrayList<>();
        for (LinkInfo link : searchResult.allLinkInfos) {
            coverageLinks.add(toCoverageLink(link));
        }

        LOG.debug("planPathsCoverage: coverageLinks built, count=%d", coverageLinks.size());

        // Reverse index: for each out-port, record which EID pairs cover it.
        Map<String, CoverageLink> linkByKey = new HashMap<>();
        for (CoverageLink cl : coverageLinks) {
            linkByKey.put(cl.getSwitchDevice() + ":" + cl.getOutPort(), cl);
        }
        for (CoveredPair pair : searchResult.selectedPairs) {
            CoveredEidPairRef pairRef = new CoveredEidPairRef(pair.src.eid, pair.dst.eid);
            List<String> keys = new ArrayList<>();
            for (CoveragePlanEngine.CoveredLinkDetail d : pair.forwardLinkDetails) {
                keys.add(d.getLinkKey());
            }
            for (CoveragePlanEngine.CoveredLinkDetail d : pair.reverseLinkDetails) {
                keys.add(d.getLinkKey());
            }
            for (String key : keys) {
                CoverageLink cl = linkByKey.get(key);
                if (cl != null) {
                    if (cl.getCoveredPairs() == null) {
                        cl.setCoveredPairs(new ArrayList<>());
                    }
                    cl.getCoveredPairs().add(pairRef);
                }
            }
        }

        CoveragePathsResult result = new CoveragePathsResult();
        result.setStatus(searchResult.fullCoverage ? PlanStatus.SUCCESS : PlanStatus.COVERAGE_INCOMPLETE);
        if (!searchResult.fullCoverage) {
            result.setErrorMessage("物理遍历覆盖率未达100%: "
                + String.format("%.2f%%", searchResult.coverageRate * 100)
                + " (" + searchResult.coveredCount + "/" + searchResult.totalLinks + " 出端口已覆盖)");
        }
        result.setEidPairs(eidPairs);
        result.setCoverageLinks(coverageLinks);
        CoverageStats stats = new CoverageStats();
        stats.setTotalLinks(searchResult.totalLinks);
        stats.setCoveredCount(searchResult.coveredCount);
        stats.setCoverageRate(searchResult.coverageRate);
        stats.setMinRepeatCount(searchResult.minRepeatCount);
        stats.setMaxRepeatCount(searchResult.maxRepeatCount);
        stats.setAvgRepeatCount(searchResult.avgRepeatCount);
        stats.setRepeatRate(searchResult.repeatRate);
        stats.setUniqueEidCount(searchResult.uniqueEidCount);
        stats.setTotalEidAppearances(searchResult.totalEidAppearances);
        stats.setEidRepeatRate(searchResult.eidRepeatRate);
        stats.setEidMinRepeat(searchResult.eidMinRepeat);
        stats.setEidMaxRepeat(searchResult.eidMaxRepeat);
        stats.setEidAvgRepeat(searchResult.eidAvgRepeat);
        stats.setSrcEidMinRepeat(searchResult.srcEidMinRepeat);
        stats.setSrcEidMaxRepeat(searchResult.srcEidMaxRepeat);
        stats.setSrcEidAvgRepeat(searchResult.srcEidAvgRepeat);
        stats.setDstEidMinRepeat(searchResult.dstEidMinRepeat);
        stats.setDstEidMaxRepeat(searchResult.dstEidMaxRepeat);
        stats.setDstEidAvgRepeat(searchResult.dstEidAvgRepeat);
        stats.setNpuUsageByChassis(searchResult.npuUsageByChassis);
        result.setStats(stats);
        LOG.info("planPathsCoverage: status=%s, pairCount=%d, linkCount=%d",
            result.getStatus(), eidPairs.size(), coverageLinks.size());
        return result;
    }

    private CoverageLink toCoverageLink(LinkInfo li) {
        CoverageLink cl = new CoverageLink();
        cl.setSwitchDevice(li.switchDevice);
        cl.setChipIndex(li.chipIndex);
        cl.setOutPort(li.outPortName);
        cl.setRemoteSwitch(li.remoteSwitch);
        cl.setRemotePort(li.remotePort);
        cl.setOutPortIndex(li.outPortIndex);
        cl.setTotalOutPorts(li.totalOutPorts);
        cl.setCoverCount(li.coverCount);
        return cl;
    }

    private CoverageLink toCoverageLinkFromDetail(CoveredLinkDetail d) {
        CoverageLink cl = new CoverageLink();
        cl.setSwitchDevice(d.switchDeviceName);
        cl.setChipIndex(d.chipIndex);
        cl.setOutPort(d.outPortName);
        cl.setRemoteSwitch(d.remoteDeviceName);
        cl.setRemotePort(d.remotePortName);
        cl.setOutPortIndex(d.outPortIndex);
        cl.setTotalOutPorts(d.totalOutPorts);
        return cl;
    }

    private PathPlanResult buildResult(InternalPathInfo pathInfo) {
        List<HopInfo> hopInfos = new ArrayList<>();
        if (pathInfo.getHops() != null) {
            for (InternalPathHop internalHop : pathInfo.getHops()) {
                HopInfo hopInfo = new HopInfo();
                hopInfo.setDeviceName(internalHop.getDeviceName());
                hopInfo.setInPort(internalHop.getInPort());
                hopInfo.setOutPort(internalHop.getOutPort());
                hopInfo.setDeviceType(internalHop.getDeviceType() != null
                    ? internalHop.getDeviceType().name() : null);
                hopInfo.setMultiPath(false);
                hopInfos.add(hopInfo);
            }
        }

        PathInfo path = new PathInfo();
        path.setHops(hopInfos);

        PathPlanResult result = new PathPlanResult();
        result.setStatus(PlanStatus.SUCCESS);
        result.setSrcEid(pathInfo.getSrcEid());
        result.setDstEid(pathInfo.getDstEid());
        result.setPath(path);
        return result;
    }
}
