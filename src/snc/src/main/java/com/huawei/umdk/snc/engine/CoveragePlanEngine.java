/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutingTableKey;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.config.HashTuple;
import com.huawei.umdk.snc.dto.CoverageRequirement;
import com.huawei.umdk.snc.store.SuperNodeStore;
import com.huawei.umdk.snc.util.AddressUtils;
import com.huawei.umdk.snc.util.HashUtils;

public class CoveragePlanEngine {


    private static final int HASH_PROTOCOL = 17;

    // === EID 均匀化参数 ===
    private static final double EID_FAIRNESS_WEIGHT = 6.0;
    private static final double NPU_FAIRNESS_WEIGHT = 2.0;
    private static final double REPEAT_WEIGHT = 0.5;
    private static final double COLD_EID_BONUS = 1.0;
    private static final double COLD_NPU_BONUS = 1.0;
    private static final int GREEDY_EID_BUDGET_START = 3;
    private static final int DUAL_EID_BUDGET_START = 5;
    private static final int RESTART_ATTEMPTS = 2;
    private static final int MAX_REBALANCE_ITERS = 8;

    private final SuperNodeStore superNodeStore;
    private final int hashFunc;
    private final int fixedDataUdpPort;
    private final int fixedAckUdpPort;
    private final HashTuple hashTuple;

    public CoveragePlanEngine(SuperNodeStore superNodeStore) {
        this(superNodeStore, 1, 0, 0, HashTuple.TWO);
    }

    public CoveragePlanEngine(SuperNodeStore superNodeStore, int hashFunc) {
        this(superNodeStore, hashFunc, 0, 0, HashTuple.TWO);
    }

    public CoveragePlanEngine(SuperNodeStore superNodeStore, int hashFunc,
                              int fixedDataUdpPort, int fixedAckUdpPort) {
        this(superNodeStore, hashFunc, fixedDataUdpPort, fixedAckUdpPort, HashTuple.TWO);
    }

    public CoveragePlanEngine(SuperNodeStore superNodeStore, int hashFunc,
                              int fixedDataUdpPort, int fixedAckUdpPort,
                              HashTuple hashTuple) {
        this.superNodeStore = superNodeStore;
        this.hashFunc = hashFunc;
        this.fixedDataUdpPort = fixedDataUdpPort;
        this.fixedAckUdpPort = fixedAckUdpPort;
        this.hashTuple = hashTuple;
    }

    public int getFixedDataUdpPort() {
        return fixedDataUdpPort;
    }

    public int getFixedAckUdpPort() {
        return fixedAckUdpPort;
    }

    public HashTuple getHashTuple() {
        return hashTuple;
    }

    /**
     * Computes the ECMP port index for one hop via {@code nativeHash}
     * (libUB5808). {@code ecmpCnt} is the ECMP member count from route lookup,
     * so the result is already the port index — no further modulo is applied.
     * Parameter order: nativeHash has dip=dst, sip=src, so the tuple for a
     * (scna→dcna) flow is (dip=dcna, sip=scna).
     *
     * <p>The tuple width comes from {@link #hashTuple}:
     * <ul>
     *   <li>{@link HashTuple#TWO}: {@code (dip, sip)} — other tuple members
     *       are {@code 0}</li>
     *   <li>{@link HashTuple#THREE}: {@code (dip, sip, sport)}</li>
     *   <li>{@link HashTuple#FOUR}: {@code (dip, sip, sport, dport)}</li>
     *   <li>{@link HashTuple#FIVE}: {@code (dip, sip, sport, dport,
     *       protocol=17)}</li>
     * </ul>
     */
    private int nativePortIdx(String scna, String dcna, int sport, int dport,
                              int ecmpCnt) {
        switch (hashTuple) {
            case THREE:
                return HashUtils.nativeHash(dcna, scna, 0, sport, 0,
                                            ecmpCnt, hashFunc);
            case FOUR:
                return HashUtils.nativeHash(dcna, scna, dport, sport, 0,
                                            ecmpCnt, hashFunc);
            case FIVE:
                return HashUtils.nativeHash(dcna, scna, dport, sport,
                                            HASH_PROTOCOL, ecmpCnt, hashFunc);
            case TWO:
            default:
                return HashUtils.nativeHash(dcna, scna, ecmpCnt, hashFunc);
        }
    }

    public static class NpuCandidate {
        public final String deviceName;
        public final String portName;
        public final String eid;
        public final String cna;
        public final String rack;
        public final String remoteL1sw;

        public NpuCandidate(String deviceName, String portName, String eid,
                            String cna, String rack, String remoteL1sw) {
            this.deviceName = deviceName;
            this.portName = portName;
            this.eid = eid;
            this.cna = cna;
            this.rack = rack;
            this.remoteL1sw = remoteL1sw;
        }
    }

    public static class LinkInfo {
        public final String switchDevice;
        public final Integer chipIndex;
        public final String outPortName;
        public final String remoteSwitch;
        public final String remotePort;
        public final int outPortIndex;
        public final int totalOutPorts;
        public final String dstChassis;
        public int coverCount;

        public LinkInfo(String switchDevice, Integer chipIndex, String outPortName,
                        String remoteSwitch, String remotePort,
                        int outPortIndex, int totalOutPorts) {
            this(switchDevice, chipIndex, outPortName, remoteSwitch, remotePort,
                 outPortIndex, totalOutPorts, null);
        }

        public LinkInfo(String switchDevice, Integer chipIndex, String outPortName,
                        String remoteSwitch, String remotePort,
                        int outPortIndex, int totalOutPorts, String dstChassis) {
            this.switchDevice = switchDevice;
            this.chipIndex = chipIndex;
            this.outPortName = outPortName;
            this.remoteSwitch = remoteSwitch;
            this.remotePort = remotePort;
            this.outPortIndex = outPortIndex;
            this.totalOutPorts = totalOutPorts;
            this.dstChassis = dstChassis;
        }

        public String getKey() {
            return switchDevice + ":" + outPortName;
        }
    }

    public static class CoveredLinkDetail {
        public final String switchDeviceName;
        public final Integer chipIndex;
        public final String outPortName;
        public final String remoteDeviceName;
        public final String remotePortName;
        public final int outPortIndex;
        public final int totalOutPorts;
        public final String dstChassis;

        public CoveredLinkDetail(String switchDeviceName, Integer chipIndex,
                                  String outPortName, String remoteDeviceName,
                                  String remotePortName, int outPortIndex,
                                  int totalOutPorts, String dstChassis) {
            this.switchDeviceName = switchDeviceName;
            this.chipIndex = chipIndex;
            this.outPortName = outPortName;
            this.remoteDeviceName = remoteDeviceName;
            this.remotePortName = remotePortName;
            this.outPortIndex = outPortIndex;
            this.totalOutPorts = totalOutPorts;
            this.dstChassis = dstChassis;
        }

        public String getLinkKey() {
            return switchDeviceName + ":" + outPortName;
        }
    }

    public static class CoveredPair {
        public final NpuCandidate src;
        public final NpuCandidate dst;
        public final List<String> forwardCoveredKeys;
        public final List<String> reverseCoveredKeys;
        public final List<CoveredLinkDetail> forwardLinkDetails;
        public final List<CoveredLinkDetail> reverseLinkDetails;
        public final String srcChassis;
        public final String dstChassis;

        public CoveredPair(NpuCandidate src, NpuCandidate dst,
                           List<String> forwardCoveredKeys,
                           List<String> reverseCoveredKeys,
                           List<CoveredLinkDetail> forwardLinkDetails,
                           List<CoveredLinkDetail> reverseLinkDetails,
                           String srcChassis, String dstChassis) {
            this.src = src;
            this.dst = dst;
            this.forwardCoveredKeys = forwardCoveredKeys;
            this.reverseCoveredKeys = reverseCoveredKeys;
            this.forwardLinkDetails = forwardLinkDetails;
            this.reverseLinkDetails = reverseLinkDetails;
            this.srcChassis = srcChassis;
            this.dstChassis = dstChassis;
        }
    }

    public static class CoverageSearchResult {
        public final List<CoveredPair> selectedPairs;
        public final List<LinkInfo> allLinkInfos;
        public final int totalLinks;
        public final int coveredCount;
        public final double coverageRate;
        public final int minRepeatCount;
        public final int maxRepeatCount;
        public final double avgRepeatCount;
        public final double repeatRate;
        public final boolean fullCoverage;
        public final Map<String, Integer> eidUsageMap;
        public final int uniqueEidCount;
        public final int totalEidAppearances;
        public final double eidRepeatRate;
        public final int eidMinRepeat;
        public final int eidMaxRepeat;
        public final double eidAvgRepeat;
        public final int srcEidMinRepeat;
        public final int srcEidMaxRepeat;
        public final double srcEidAvgRepeat;
        public final int dstEidMinRepeat;
        public final int dstEidMaxRepeat;
        public final double dstEidAvgRepeat;
        public final Map<String, Integer> npuUsageByChassis;

        public CoverageSearchResult(List<CoveredPair> selectedPairs,
                                    List<LinkInfo> allLinkInfos,
                                    int totalLinks, int coveredCount,
                                    double coverageRate,
                                    int minRepeatCount, int maxRepeatCount,
                                    double avgRepeatCount, double repeatRate,
                                    boolean fullCoverage,
                                    Map<String, Integer> eidUsageMap,
                                    Map<String, Integer> srcEidUsageMap,
                                    Map<String, Integer> dstEidUsageMap,
                                    Map<String, Integer> npuUsageByChassis) {
            this.selectedPairs = selectedPairs;
            this.allLinkInfos = allLinkInfos;
            this.totalLinks = totalLinks;
            this.coveredCount = coveredCount;
            this.coverageRate = coverageRate;
            this.minRepeatCount = minRepeatCount;
            this.maxRepeatCount = maxRepeatCount;
            this.avgRepeatCount = avgRepeatCount;
            this.repeatRate = repeatRate;
            this.fullCoverage = fullCoverage;
            this.eidUsageMap = eidUsageMap;
            this.uniqueEidCount = eidUsageMap.size();
            this.totalEidAppearances = selectedPairs.size() * 2;
            int eMin = Integer.MAX_VALUE, eMax = 0, eSum = 0;
            for (int cnt : eidUsageMap.values()) {
                eMin = Math.min(eMin, cnt);
                eMax = Math.max(eMax, cnt);
                eSum += cnt;
            }
            this.eidMinRepeat = eMin == Integer.MAX_VALUE ? 0 : eMin;
            this.eidMaxRepeat = eMax;
            this.eidAvgRepeat = this.uniqueEidCount > 0 ? (double) eSum / this.uniqueEidCount : 0.0;
            this.eidRepeatRate = this.totalEidAppearances > 0
                ? (double) (this.totalEidAppearances - this.uniqueEidCount) / this.totalEidAppearances : 0.0;
            this.srcEidMinRepeat = minUsage(srcEidUsageMap);
            this.srcEidMaxRepeat = maxUsage(srcEidUsageMap);
            this.srcEidAvgRepeat = srcEidUsageMap.isEmpty()
                ? 0.0 : (double) sumUsage(srcEidUsageMap) / srcEidUsageMap.size();
            this.dstEidMinRepeat = minUsage(dstEidUsageMap);
            this.dstEidMaxRepeat = maxUsage(dstEidUsageMap);
            this.dstEidAvgRepeat = dstEidUsageMap.isEmpty()
                ? 0.0 : (double) sumUsage(dstEidUsageMap) / dstEidUsageMap.size();
            this.npuUsageByChassis = npuUsageByChassis;
        }

        private static int minUsage(Map<String, Integer> usage) {
            if (usage == null || usage.isEmpty()) return 0;
            int min = Integer.MAX_VALUE;
            for (int c : usage.values()) min = Math.min(min, c);
            return min;
        }

        private static int maxUsage(Map<String, Integer> usage) {
            if (usage == null || usage.isEmpty()) return 0;
            int max = 0;
            for (int c : usage.values()) max = Math.max(max, c);
            return max;
        }

        private static int sumUsage(Map<String, Integer> usage) {
            int sum = 0;
            for (int c : usage.values()) sum += c;
            return sum;
        }
    }

    static class PrecomputedTopo {
        Map<String, NpuPortConn> npuPortConns = new HashMap<>();
        Map<String, Map<Integer, Map<String, List<String>>>> l2swChipRemotePorts = new HashMap<>();
        Map<String, DeviceEntity> devices;
        Set<String> l2swNames;
    }

    static class NpuPortConn {
        String l1swName;
        String l1swPortName;
        int l1swChipIdx;
        String l1swChassis;

        NpuPortConn(String l1swName, String l1swPortName, int l1swChipIdx, String l1swChassis) {
            this.l1swName = l1swName;
            this.l1swPortName = l1swPortName;
            this.l1swChipIdx = l1swChipIdx;
            this.l1swChassis = l1swChassis;
        }

        @Override public String toString() {
            return "NpuPortConn[l1sw=" + l1swName + ", port=" + l1swPortName
                + ", chip=" + l1swChipIdx + ", chassis=" + l1swChassis + "]";
        }
    }

    static class PathTrace {
        boolean viable;
        String srcL1swName;
        int srcL1swChipIdx;
        String srcL1swInPortName;
        String srcL1swOutPortName;
        int srcL1swOutPortIndex;
        int srcL1swTotalOutPorts;
        String srcL1swOutRemoteDev;
        String srcL1swOutRemotePort;
        String l2swName;
        int l2swChipIdx;
        String l2swInPortName;
        String l2swOutPortName;
        int l2swOutPortIndex;
        int l2swTotalOutPorts;
        String l2swOutRemoteDev;
        String l2swOutRemotePort;
        String dstL1swName;
        int dstL1swChipIdx;
        String dstL1swInPortName;
        String dstL1swOutPortName;
        String srcChassis;
        String dstChassis;
        List<CoveredLinkDetail> forwardLinkDetails = new ArrayList<>();
    }

    static class ReversePathTrace {
        boolean viable;
        String dstL1swOutPortName;
        int dstL1swOutPortIndex;
        int dstL1swTotalOutPorts;
        String dstL1swOutRemoteDev;
        String dstL1swOutRemotePort;
        String l2swRevName;
        int l2swRevChipIdx;
        String l2swRevInPortName;
        String l2swRevOutPortName;
        int l2swRevOutPortIndex;
        int l2swRevTotalOutPorts;
        String l2swRevOutRemoteDev;
        String l2swRevOutRemotePort;
        String srcL1swRevInPortName;
        String srcL1swRevOutPortName;
        List<CoveredLinkDetail> reverseLinkDetails = new ArrayList<>();
    }

    public CoverageSearchResult findCoverage(SuperNode superNode,
                                              int fixedDataUdpSrcPort,
                                              int fixedAckUdpSrcPort) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        if (devices == null || devices.isEmpty()) {
            return emptyResult();
        }

        List<NpuCandidate> npuCandidates = collectNpuCandidates(devices);
        if (npuCandidates.isEmpty()) {
            return emptyResult();
        }

        Set<String> l2swNames = collectL2swNames(devices);

        List<LinkInfo> links = new ArrayList<>();
        collectBidirectionalLinks(superNode, devices, l2swNames, links);

        if (links.isEmpty()) {
            return emptyResult();
        }

        Map<String, LinkInfo> linkMap = new HashMap<>();
        for (LinkInfo link : links) {
            linkMap.merge(link.getKey(), link, (a, b) ->
                a.totalOutPorts >= b.totalOutPorts ? a : b);
        }

        int totalLinks = linkMap.size();

        PrecomputedTopo topo = precomputeTopology(devices, l2swNames);

        return findCoverageDiffPath(superNode, linkMap,
            npuCandidates, totalLinks, fixedDataUdpSrcPort, fixedAckUdpSrcPort, topo);
    }

    public CoverageSearchResult findCoverage(SuperNode superNode,
                                              int fixedDataUdpSrcPort,
                                              int fixedAckUdpSrcPort,
                                              CoverageRequirement requirement) {
        if (requirement == null || requirement == CoverageRequirement.MIN_COVERAGE) {
            return findCoverage(superNode, fixedDataUdpSrcPort, fixedAckUdpSrcPort);
        }
        return findCoverageDualDisjoint(superNode, fixedDataUdpSrcPort, fixedAckUdpSrcPort);
    }

    private CoverageSearchResult findCoverageDualDisjoint(
            SuperNode superNode,
            int fixedDataUdpSrcPort,
            int fixedAckUdpSrcPort) {
        Map<String, DeviceEntity> devices = superNode.getAllDevices();
        if (devices == null || devices.isEmpty()) {
            return emptyResult();
        }

        List<NpuCandidate> npuCandidates = collectNpuCandidates(devices);
        if (npuCandidates.isEmpty()) {
            return emptyResult();
        }

        Set<String> l2swNames = collectL2swNames(devices);

        List<LinkInfo> links = new ArrayList<>();
        collectBidirectionalLinks(superNode, devices, l2swNames, links);

        if (links.isEmpty()) {
            return emptyResult();
        }

        Map<String, LinkInfo> linkMap = new HashMap<>();
        for (LinkInfo link : links) {
            linkMap.merge(link.getKey(), link, (a, b) ->
                a.totalOutPorts >= b.totalOutPorts ? a : b);
        }

        int totalLinks = linkMap.size();
        PrecomputedTopo topo = precomputeTopology(devices, l2swNames);

        List<NpuCandidate> crossRackSrc = new ArrayList<>();
        List<NpuCandidate> crossRackDst = new ArrayList<>();
        buildCrossChassisCandidates(npuCandidates, crossRackSrc, crossRackDst);

        if (crossRackSrc.isEmpty()) {
            return emptyResult();
        }

        List<PairCoverage> allPairs = new ArrayList<>();
        int fwdOk = 0, revOk = 0, checked = 0;
        for (NpuCandidate src : crossRackSrc) {
            for (NpuCandidate dst : crossRackDst) {
                if (src.rack.equals(dst.rack)) continue;
                checked++;

                PathTrace fwdTrace = traceForwardPath(superNode, src, dst,
                    fixedDataUdpSrcPort, fixedAckUdpSrcPort, topo);
                if (!fwdTrace.viable) continue;
                fwdOk++;

                ReversePathTrace revTrace = traceReversePath(superNode, src, dst,
                    fixedAckUdpSrcPort, fixedDataUdpSrcPort, fwdTrace, topo);
                if (!revTrace.viable) continue;
                revOk++;

                List<String> fwdKeys = new ArrayList<>();
                for (CoveredLinkDetail d : fwdTrace.forwardLinkDetails) fwdKeys.add(d.getLinkKey());
                List<String> revKeys = new ArrayList<>();
                for (CoveredLinkDetail d : revTrace.reverseLinkDetails) revKeys.add(d.getLinkKey());

                allPairs.add(new PairCoverage(src, dst, fwdKeys, revKeys,
                    fwdTrace.forwardLinkDetails, revTrace.reverseLinkDetails,
                    fwdTrace.srcChassis, fwdTrace.dstChassis));
            }
        }

        return runGreedyCoverageDualDisjoint(allPairs, linkMap,
            totalLinks, fixedDataUdpSrcPort, fixedAckUdpSrcPort);
    }

    private PrecomputedTopo precomputeTopology(Map<String, DeviceEntity> devices, Set<String> l2swNames) {
        PrecomputedTopo topo = new PrecomputedTopo();
        topo.devices = devices;
        topo.l2swNames = l2swNames;

        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.NPU) continue;
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (port instanceof NpuPortEntity && port.getCna() != null
                        && port.getRemoteDevice() != null && port.getRemotePort() != null) {
                        String npuKey = dev.getDeviceName() + ":" + port.getPortName();
                        DeviceEntity l1swDev = devices.get(port.getRemoteDevice());
                        if (l1swDev == null) continue;
                        PortEntity l1swPort = findPortInDevice(l1swDev, port.getRemotePort());
                        if (l1swPort == null) continue;
                        topo.npuPortConns.put(npuKey, new NpuPortConn(
                            port.getRemoteDevice(), port.getRemotePort(),
                            l1swPort.getChipIndex(),
                            l1swDev.getRack()));
                    }
                }
            }
        }

        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            SwDevice sw = (SwDevice) dev;
            if (sw.getSwitchLevel() != SwitchLevel.L2) continue;
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                Map<String, List<String>> remotePorts = new HashMap<>();
                for (PortEntity port : chip.getPorts().values()) {
                    if (isL1Sw(devices.get(port.getRemoteDevice()))) {
                        String remoteDev = port.getRemoteDevice();
                        remotePorts.computeIfAbsent(remoteDev, k -> new ArrayList<>())
                            .add(port.getPortName());
                    }
                }
                if (!remotePorts.isEmpty()) {
                    topo.l2swChipRemotePorts.computeIfAbsent(dev.getDeviceName(), k -> new HashMap<>())
                        .put(chip.getChipIndex(), remotePorts);
                }
            }
        }

        return topo;
    }

    private CoverageSearchResult findCoverageDiffPath(
            SuperNode superNode,
            Map<String, LinkInfo> linkMap,
            List<NpuCandidate> allNpuCandidates,
            int totalLinks,
            int fixedDataUdpSrcPort,
            int fixedAckUdpSrcPort,
            PrecomputedTopo topo) {

        List<NpuCandidate> crossRackSrc = new ArrayList<>();
        List<NpuCandidate> crossRackDst = new ArrayList<>();
        buildCrossChassisCandidates(allNpuCandidates, crossRackSrc, crossRackDst);

        if (crossRackSrc.isEmpty()) {
            return emptyResult();
        }

        System.out.println("DIFF_PATH: " + crossRackSrc.size() + " src x " + crossRackDst.size() + " dst candidates");

        List<PairCoverage> allPairs = new ArrayList<>();
        int fwdOk = 0, revOk = 0, checked = 0;
        String firstFailReason = null;
        for (NpuCandidate src : crossRackSrc) {
            for (NpuCandidate dst : crossRackDst) {
                if (src.rack.equals(dst.rack)) continue;
                checked++;
                if (checked % 50000 == 0) {
                    System.out.println("  progress: checked=" + checked + " fwdOk=" + fwdOk + " revOk=" + revOk);
                }

                PathTrace fwdTrace = traceForwardPath(superNode, src, dst,
                    fixedDataUdpSrcPort, fixedAckUdpSrcPort, topo);
                if (!fwdTrace.viable) continue;
                fwdOk++;

                ReversePathTrace revTrace = traceReversePath(superNode, src, dst,
                    fixedAckUdpSrcPort, fixedDataUdpSrcPort, fwdTrace, topo);
                if (!revTrace.viable) {
                    if (firstFailReason == null) {
                        String dstNpuKey = dst.deviceName + ":" + dst.portName;
                        NpuPortConn dstConn = topo.npuPortConns.get(dstNpuKey);
                        firstFailReason = "dstConn=" + dstConn
                            + " fwdDstL1sw=" + fwdTrace.dstL1swName
                            + " fwdDstL1swOutPort=" + fwdTrace.dstL1swOutPortName;
                    }
                    continue;
                }
                revOk++;

                List<String> fwdKeys = new ArrayList<>();
                for (CoveredLinkDetail d : fwdTrace.forwardLinkDetails) fwdKeys.add(d.getLinkKey());
                List<String> revKeys = new ArrayList<>();
                for (CoveredLinkDetail d : revTrace.reverseLinkDetails) revKeys.add(d.getLinkKey());

                allPairs.add(new PairCoverage(src, dst, fwdKeys, revKeys,
                    fwdTrace.forwardLinkDetails, revTrace.reverseLinkDetails,
                    fwdTrace.srcChassis, fwdTrace.dstChassis));
            }
        }

        System.out.println("DIFF_PATH candidates: " + allPairs.size()
            + " fwdOk=" + fwdOk + " revOk=" + revOk);
        if (firstFailReason != null) {
            System.out.println("  First revFail: " + firstFailReason);
        }

        return runGreedyCoverage(allPairs, linkMap,
                                 totalLinks, fixedDataUdpSrcPort, fixedAckUdpSrcPort);
    }

    private static int fwdFail1 = 0, fwdFail2 = 0, fwdFail3a = 0, fwdFail3b = 0,
                       fwdFail3c = 0, fwdFail4 = 0, fwdFail5 = 0, fwdFail6 = 0,
                       fwdFail7 = 0, fwdFail8 = 0, fwdFail9 = 0, fwdFail10 = 0,
                       fwdFail11 = 0, fwdFail12 = 0;
    private static int fwdFailLogCount = 0;
    private static int revFailA = 0, revFailB = 0, revFailC = 0, revFailD = 0,
                       revFailE = 0, revFailF = 0, revFailG = 0, revFailH = 0;
    private static int revFailLogCount = 0;

    private PathTrace traceForwardPath(SuperNode superNode, NpuCandidate src,
                                        NpuCandidate dst, int dataUdpSrcPort,
                                        int ackUdpSrcPort, PrecomputedTopo topo) {
        PathTrace result = new PathTrace();
        result.viable = false;

        String srcNpuKey = src.deviceName + ":" + src.portName;
        NpuPortConn srcConn = topo.npuPortConns.get(srcNpuKey);
        if (srcConn == null) { fwdFail1++; logFwdFail(); return result; }

        String srcL1swName = srcConn.l1swName;
        String srcL1swInPortName = srcConn.l1swPortName;
        int srcL1swChipIdx = srcConn.l1swChipIdx;
        DeviceEntity srcL1swDev = topo.devices.get(srcL1swName);

        RoutingEntry srcL1swRoute = lookupRoute(superNode, srcL1swName,
            srcL1swChipIdx, dst.cna);
        if (srcL1swRoute == null || srcL1swRoute.getOutPortInfos() == null) { fwdFail2++; logFwdFail(); return result; }

        List<String> srcL1swL2swPorts = new ArrayList<>();
        for (OutPortInfo opi : srcL1swRoute.getOutPortInfos().values()) {
            String pn = opi.getPortName();
            PortEntity pe = srcL1swDev.getForwardingChips().get(srcL1swChipIdx).getPorts().get(pn);
            if (pe != null && isL2Sw(topo.devices.get(pe.getRemoteDevice()))) {
                srcL1swL2swPorts.add(pn);
            }
        }
        if (srcL1swL2swPorts.isEmpty()) { fwdFail2++; logFwdFail(); return result; }

        int srcL1swPortIdx = nativePortIdx(src.cna, dst.cna, dataUdpSrcPort,
            ackUdpSrcPort, srcL1swL2swPorts.size());
        String srcL1swOutPortName = srcL1swL2swPorts.get(srcL1swPortIdx);
        ForwardingChip srcL1swChip = srcL1swDev.getForwardingChips().get(srcL1swChipIdx);
        PortEntity srcL1swOutPort = srcL1swChip.getPorts().get(srcL1swOutPortName);
        if (srcL1swOutPort == null) {
            fwdFail3a++;
            logFwdFail();
            if (fwdFail3a <= 3) {
                System.out.println("  DEBUG 3a: portName=" + srcL1swOutPortName
                    + " not in chip " + srcL1swChipIdx + " ports of " + srcL1swName
                    + " (chipPortsKeys=" + srcL1swChip.getPorts().keySet().stream().limit(5).reduce((a,b)->a+","+b).orElse("") + ")");
            }
            return result;
        }
        if (srcL1swOutPort.getRemoteDevice() == null) { fwdFail3b++; logFwdFail(); return result; }

        String l2swName = srcL1swOutPort.getRemoteDevice();
        String l2swInPortName = srcL1swOutPort.getRemotePort();

        DeviceEntity l2swDev = topo.devices.get(l2swName);
        if (l2swDev == null) { fwdFail4++; logFwdFail(); return result; }
        PortEntity l2swInPort = findPortInDevice(l2swDev, l2swInPortName);
        if (l2swInPort == null) { fwdFail5++; logFwdFail(); return result; }
        int l2swChipIdx = l2swInPort.getChipIndex();

        String dstL1swTarget = dst.remoteL1sw;
        ForwardingChip l2swChip = l2swDev.getForwardingChips().get(l2swChipIdx);
        Map<String, List<String>> fwdChipRemote = topo.l2swChipRemotePorts
            .getOrDefault(l2swName, Collections.emptyMap())
            .get(l2swChipIdx);
        List<String> l2swDstPorts = fwdChipRemote != null
            ? fwdChipRemote.get(dstL1swTarget) : null;
        if (l2swDstPorts == null || l2swDstPorts.isEmpty()) { fwdFail8++; logFwdFail(); return result; }

        int l2swPortIdx = nativePortIdx(src.cna, dst.cna, dataUdpSrcPort,
            ackUdpSrcPort, l2swDstPorts.size());
        String l2swOutPortName = l2swDstPorts.get(l2swPortIdx);

        PortEntity l2swOutPort = l2swChip.getPorts().get(l2swOutPortName);
        if (l2swOutPort == null) { fwdFail9++; logFwdFail(); return result; }
        String dstL1swName = l2swOutPort.getRemoteDevice();
        String dstL1swInPortName = l2swOutPort.getRemotePort();

        DeviceEntity dstL1swDev = topo.devices.get(dstL1swName);
        if (dstL1swDev == null) { fwdFail10++; logFwdFail(); return result; }
        PortEntity dstL1swInPort = findPortInDevice(dstL1swDev, dstL1swInPortName);
        if (dstL1swInPort == null) { fwdFail11++; logFwdFail(); return result; }
        int dstL1swChipIdx = dstL1swInPort.getChipIndex();

        RoutingEntry dstL1swRoute = lookupRoute(superNode, dstL1swName, dstL1swChipIdx, dst.cna);
        if (dstL1swRoute == null || dstL1swRoute.getOutPortInfos() == null) { fwdFail12++; logFwdFail(); return result; }
        List<OutPortInfo> dstL1swOutPorts = new ArrayList<>(dstL1swRoute.getOutPortInfos().values());
        String dstL1swOutPortName = dstL1swOutPorts.get(0).getPortName();
        ForwardingChip dstL1swChip = dstL1swDev.getForwardingChips().get(dstL1swChipIdx);
        PortEntity dstL1swOutPort = dstL1swChip.getPorts().get(dstL1swOutPortName);
        if (dstL1swOutPort == null) {
            fwdFail3c++;
            logFwdFail();
            if (fwdFail3c <= 3) {
                System.out.println("  DEBUG 3c: dstL1swOutPortName=" + dstL1swOutPortName
                    + " not in chip " + dstL1swChipIdx + " ports of " + dstL1swName);
            }
            return result;
        }
        if (!dstL1swOutPort.getRemoteDevice().equals(dst.deviceName)) {
            fwdFail3c++;
            logFwdFail();
            if (fwdFail3c <= 3) {
                System.out.println("  DEBUG 3c-mismatch: dstL1swOutPort.remoteDevice="
                    + dstL1swOutPort.getRemoteDevice() + " vs dst.deviceName=" + dst.deviceName);
            }
            return result;
        }

        result.viable = true;
        result.srcL1swName = srcL1swName;
        result.srcL1swChipIdx = srcL1swChipIdx;
        result.srcL1swInPortName = srcL1swInPortName;
        result.srcL1swOutPortName = srcL1swOutPortName;
        result.srcL1swOutPortIndex = srcL1swPortIdx;
        result.srcL1swTotalOutPorts = srcL1swL2swPorts.size();
        result.srcL1swOutRemoteDev = l2swName;
        result.srcL1swOutRemotePort = l2swInPortName;
        result.l2swName = l2swName;
        result.l2swChipIdx = l2swChipIdx;
        result.l2swInPortName = l2swInPortName;
        result.l2swOutPortName = l2swOutPortName;
        result.l2swOutPortIndex = l2swPortIdx;
        result.l2swTotalOutPorts = l2swDstPorts.size();
        result.l2swOutRemoteDev = dstL1swName;
        result.l2swOutRemotePort = dstL1swInPortName;
        result.dstL1swName = dstL1swName;
        result.dstL1swChipIdx = dstL1swChipIdx;
        result.dstL1swInPortName = dstL1swInPortName;
        result.dstL1swOutPortName = dstL1swOutPortName;
        result.srcChassis = srcConn.l1swChassis;
        DeviceEntity dstChassisDev = topo.devices.get(dst.remoteL1sw);
        String dstChassis = dstChassisDev != null ? dstChassisDev.getRack() : null;
        result.dstChassis = dstChassis;

        result.forwardLinkDetails.add(new CoveredLinkDetail(
            srcL1swName, srcL1swChipIdx, srcL1swOutPortName,
            l2swName, l2swInPortName,
            srcL1swPortIdx, srcL1swL2swPorts.size(), null));

        result.forwardLinkDetails.add(new CoveredLinkDetail(
            l2swName, l2swChipIdx, l2swOutPortName,
            dstL1swName, dstL1swInPortName,
            l2swPortIdx, l2swDstPorts.size(), dstChassis));

        return result;
    }

    private ReversePathTrace traceReversePath(SuperNode superNode, NpuCandidate src,
                                               NpuCandidate dst, int ackUdpSrcPort,
                                               int dataUdpSrcPort, PathTrace fwdTrace,
                                               PrecomputedTopo topo) {
        ReversePathTrace result = new ReversePathTrace();
        result.viable = false;

        String dstNpuKey = dst.deviceName + ":" + dst.portName;
        NpuPortConn dstConn = topo.npuPortConns.get(dstNpuKey);
        if (dstConn == null) {
            System.out.println("DEBUG: dstConn null for " + dstNpuKey);
            return result;
        }

        boolean l1swMatch = dstConn.l1swName.equals(fwdTrace.dstL1swName);
        boolean portMatch = dstConn.l1swPortName.equals(fwdTrace.dstL1swOutPortName);
        if (!l1swMatch || !portMatch) {
            revFailA++;
            if (revFailA <= 2) {
                System.out.println("  DEBUG revA: l1swMatch=" + l1swMatch + " portMatch=" + portMatch
                    + " dstConn.l1swPortName=" + dstConn.l1swPortName
                    + " fwdTrace.dstL1swOutPortName=" + fwdTrace.dstL1swOutPortName);
            }
            logRevFail();
            return result;
        }

        int dstL1swRevChipIdx = dstConn.l1swChipIdx;

        RoutingEntry dstL1swRevRoute = lookupRoute(superNode, fwdTrace.dstL1swName,
            dstL1swRevChipIdx, src.cna);
        if (dstL1swRevRoute == null || dstL1swRevRoute.getOutPortInfos() == null) { revFailB++; logRevFail(); return result; }

        DeviceEntity dstL1swDev = topo.devices.get(fwdTrace.dstL1swName);
        ForwardingChip dstL1swRevChip = dstL1swDev.getForwardingChips().get(dstL1swRevChipIdx);
        List<String> dstL1swRevL2swPorts = new ArrayList<>();
        for (OutPortInfo opi : dstL1swRevRoute.getOutPortInfos().values()) {
            String pn = opi.getPortName();
            PortEntity pe = dstL1swRevChip.getPorts().get(pn);
            if (pe != null && isL2Sw(topo.devices.get(pe.getRemoteDevice()))) {
                dstL1swRevL2swPorts.add(pn);
            }
        }
        if (dstL1swRevL2swPorts.isEmpty()) { revFailB++; logRevFail(); return result; }

        int dstL1swRevPortIdx = nativePortIdx(dst.cna, src.cna, ackUdpSrcPort,
            dataUdpSrcPort, dstL1swRevL2swPorts.size());
        String dstL1swRevOutPortName = dstL1swRevL2swPorts.get(dstL1swRevPortIdx);

        PortEntity dstL1swRevOutPort = dstL1swRevChip.getPorts().get(dstL1swRevOutPortName);
        if (dstL1swRevOutPort == null || dstL1swRevOutPort.getRemoteDevice() == null) { revFailC++; logRevFail(); return result; }

        String l2swRevName = dstL1swRevOutPort.getRemoteDevice();
        String l2swRevInPortName = dstL1swRevOutPort.getRemotePort();

        DeviceEntity l2swRevDev = topo.devices.get(l2swRevName);
        if (l2swRevDev == null) { revFailD++; logRevFail(); return result; }
        PortEntity l2swRevInPort = findPortInDevice(l2swRevDev, l2swRevInPortName);
        if (l2swRevInPort == null) return result;
        int l2swRevChipIdx = l2swRevInPort.getChipIndex();

        String srcL1swTarget = src.remoteL1sw;
        ForwardingChip l2swRevChip = l2swRevDev.getForwardingChips().get(l2swRevChipIdx);
        Map<String, List<String>> revChipRemote = topo.l2swChipRemotePorts
            .getOrDefault(l2swRevName, Collections.emptyMap())
            .get(l2swRevChipIdx);
        List<String> l2swRevSrcPorts = revChipRemote != null
            ? revChipRemote.get(srcL1swTarget) : null;
        if (l2swRevSrcPorts == null || l2swRevSrcPorts.isEmpty()) { revFailE++; logRevFail(); return result; }

        int l2swRevPortIdx = nativePortIdx(dst.cna, src.cna, ackUdpSrcPort,
            dataUdpSrcPort, l2swRevSrcPorts.size());
        String l2swRevOutPortName = l2swRevSrcPorts.get(l2swRevPortIdx);

        PortEntity l2swRevOutPort = l2swRevChip.getPorts().get(l2swRevOutPortName);
        if (l2swRevOutPort == null) return result;
        String srcL1swRevName = l2swRevOutPort.getRemoteDevice();
        String srcL1swRevInPortName = l2swRevOutPort.getRemotePort();

        DeviceEntity srcL1swRevDev = topo.devices.get(srcL1swRevName);
        PortEntity srcL1swRevInPort = findPortInDevice(srcL1swRevDev, srcL1swRevInPortName);
        if (srcL1swRevInPort == null) { revFailH++; logRevFail(); return result; }
        int srcL1swRevChipIdx = srcL1swRevInPort.getChipIndex();

        RoutingEntry srcL1swRevRoute = lookupRoute(superNode, srcL1swRevName,
            srcL1swRevChipIdx, src.cna);
        if (srcL1swRevRoute == null || srcL1swRevRoute.getOutPortInfos() == null) { revFailF++; logRevFail(); return result; }

        ForwardingChip srcL1swRevChip = srcL1swRevDev.getForwardingChips().get(srcL1swRevChipIdx);
        List<OutPortInfo> srcL1swRevOutPorts = new ArrayList<>(srcL1swRevRoute.getOutPortInfos().values());
        String srcL1swRevOutPortName = srcL1swRevOutPorts.get(0).getPortName();
        PortEntity srcL1swRevOutPort = srcL1swRevChip.getPorts().get(srcL1swRevOutPortName);
        if (srcL1swRevOutPort == null) return result;

        if (!srcL1swRevOutPort.getRemoteDevice().equals(src.deviceName)) {
            revFailG++;
            logRevFail();
            return result;
        }

        result.viable = true;
        result.dstL1swOutPortName = dstL1swRevOutPortName;
        result.dstL1swOutPortIndex = dstL1swRevPortIdx;
        result.dstL1swTotalOutPorts = dstL1swRevL2swPorts.size();
        result.dstL1swOutRemoteDev = l2swRevName;
        result.dstL1swOutRemotePort = l2swRevInPortName;
        result.l2swRevName = l2swRevName;
        result.l2swRevChipIdx = l2swRevChipIdx;
        result.l2swRevInPortName = l2swRevInPortName;
        result.l2swRevOutPortName = l2swRevOutPortName;
        result.l2swRevOutPortIndex = l2swRevPortIdx;
        result.l2swRevTotalOutPorts = l2swRevSrcPorts.size();
        result.l2swRevOutRemoteDev = srcL1swRevName;
        result.l2swRevOutRemotePort = srcL1swRevInPortName;
        result.srcL1swRevInPortName = srcL1swRevInPortName;
        result.srcL1swRevOutPortName = srcL1swRevOutPortName;

        result.reverseLinkDetails.add(new CoveredLinkDetail(
            fwdTrace.dstL1swName, dstL1swRevChipIdx, dstL1swRevOutPortName,
            l2swRevName, l2swRevInPortName,
            dstL1swRevPortIdx, dstL1swRevL2swPorts.size(), null));

        result.reverseLinkDetails.add(new CoveredLinkDetail(
            l2swRevName, l2swRevChipIdx, l2swRevOutPortName,
            srcL1swRevName, srcL1swRevInPortName,
            l2swRevPortIdx, l2swRevSrcPorts.size(), fwdTrace.srcChassis));

        return result;
    }

    private RoutingEntry lookupRoute(SuperNode superNode, String deviceName,
                                      int chipIndex, String targetCna) {
        RoutingTableKey rtKey = new RoutingTableKey(superNode.getName(), deviceName, chipIndex);
        RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
        if (rt == null || rt.getRoutes() == null) return null;

        if (rt.getMaskLengths() != null) {
            for (int maskLen : rt.getMaskLengths()) {
                String networkAddr;
                if (maskLen == 32) {
                    networkAddr = targetCna;
                } else {
                    networkAddr = AddressUtils.applyMask(targetCna, maskLen);
                }
                RoutePrefix prefix = new RoutePrefix(networkAddr, maskLen);
                RoutingEntry entry = rt.getRoutes().get(prefix);
                if (entry != null) {
                    if (revFailG > 0 && revFailG <= 500) {
                        System.out.println("  DEBUG lookupRoute: dev=" + deviceName + " chip=" + chipIndex
                            + " target=" + targetCna + " found mask=" + maskLen
                            + " outPortCount=" + entry.getOutPortInfos().size()
                            + " firstOutPort=" + (entry.getOutPortInfos().isEmpty()
                                ? "null" : entry.getOutPortInfos().values().iterator().next().getPortName())
                            + " rtRoutesKeys=" + rt.getRoutes().keySet().stream()
                                .filter(p -> p.getMaskLength() == 32 && targetCna.equals(p.getDstAddress()))
                                .map(p -> p.getDstAddress() + "/" + p.getMaskLength()
                                    + "->" + rt.getRoutes().get(p).getOutPortInfos().size() + "ports")
                                .collect(java.util.stream.Collectors.joining(", ")));
                    }
                    return entry;
                }
            }
        }

        RoutePrefix defaultPrefix = new RoutePrefix("0.0.0.0", 0);
        RoutingEntry de = rt.getRoutes().get(defaultPrefix);
        if (revFailG > 0 && revFailG <= 500) {
            System.out.println("  DEBUG lookupRoute FALLBACK: dev=" + deviceName + " chip=" + chipIndex
                + " target=" + targetCna + " allRoutes=" + rt.getRoutes().keySet().stream()
                    .filter(p -> p.getMaskLength() == 32 && targetCna.equals(p.getDstAddress()))
                    .map(p -> p.getDstAddress() + "/" + p.getMaskLength()
                        + "->" + rt.getRoutes().get(p).getOutPortInfos().size() + "ports")
                    .collect(java.util.stream.Collectors.joining(", ")));
        }
        return de;
    }

    private static PortEntity findPortInDevice(DeviceEntity device, String portName) {
        if (device == null || device.getForwardingChips() == null) return null;
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip.getPorts() != null) {
                PortEntity port = chip.getPorts().get(portName);
                if (port != null) return port;
            }
        }
        return null;
    }

    private CoverageSearchResult buildResult(
            Map<String, LinkInfo> linkMap,
            List<CoveredPair> selected,
            int totalLinks,
            int fixedDataUdpSrcPort,
            int fixedAckUdpSrcPort,
            boolean fullCoverage,
            Map<String, Integer> eidUsageMap,
            Map<String, Integer> npuUsageByChassis) {

        List<LinkInfo> allLinkInfos = new ArrayList<>(linkMap.values());

        computeRepeatCounts(allLinkInfos, selected);

        int coveredCount = 0;
        int minRepeat = Integer.MAX_VALUE;
        int maxRepeat = 0;
        double totalRepeat = 0;
        for (LinkInfo link : allLinkInfos) {
            if (link.coverCount > 0) {
                coveredCount++;
                minRepeat = Math.min(minRepeat, link.coverCount);
                maxRepeat = Math.max(maxRepeat, link.coverCount);
                totalRepeat += link.coverCount;
            }
        }
        if (minRepeat == Integer.MAX_VALUE) {
            minRepeat = 0;
        }
        double avgRepeat = coveredCount > 0 ? totalRepeat / coveredCount : 0.0;
        double coverageRate = totalLinks > 0 ? (double) coveredCount / totalLinks : 0.0;
        double repeatRate = totalLinks > 0 ? (totalRepeat - coveredCount) / totalLinks : 0.0;

        System.out.println();
        System.out.println("=== Per-Switch Hash Coverage (all ports covered?) ===");
        Map<String, Set<Integer>> dirSwitchPorts = new HashMap<>();
        Map<String, Integer> dirSwitchTotal = new HashMap<>();
        for (LinkInfo link : allLinkInfos) {
            String key = link.switchDevice;
            dirSwitchPorts.computeIfAbsent(key, k -> new HashSet<>()).add(link.outPortIndex);
            if (link.totalOutPorts > dirSwitchTotal.getOrDefault(key, 0)) {
                dirSwitchTotal.put(key, link.totalOutPorts);
            }
        }
        int totalDirSwitches = 0;
        int fullCoveredSwitches = 0;
        for (Map.Entry<String, Set<Integer>> e : dirSwitchPorts.entrySet()) {
            totalDirSwitches++;
            String key = e.getKey();
            int expectedTotal = dirSwitchTotal.get(key);
            int actualCovered = e.getValue().size();
            String status = actualCovered == expectedTotal
                ? "FULL" : "MISSING " + (expectedTotal - actualCovered);
            if (actualCovered == expectedTotal) fullCoveredSwitches++;
            System.out.println("  " + key + " ports=" + actualCovered + "/" + expectedTotal + " " + status);
        }
        System.out.println("  Summary: " + fullCoveredSwitches + "/" + totalDirSwitches
            + " switches have full out-port hash coverage");

        // src/dst 角色使用分布（正式指标，随 CoverageSearchResult 输出）
        Map<String, Integer> srcEidUsageMap = new HashMap<>();
        Map<String, Integer> dstEidUsageMap = new HashMap<>();
        for (CoveredPair p : selected) {
            srcEidUsageMap.merge(p.src.eid, 1, Integer::sum);
            dstEidUsageMap.merge(p.dst.eid, 1, Integer::sum);
        }

        return new CoverageSearchResult(selected, allLinkInfos, totalLinks, coveredCount,
                                        coverageRate, minRepeat, maxRepeat, avgRepeat, repeatRate,
                                        fullCoverage, eidUsageMap, srcEidUsageMap, dstEidUsageMap,
                                        npuUsageByChassis);
    }

    private List<NpuCandidate> collectNpuCandidates(Map<String, DeviceEntity> devices) {
        List<NpuCandidate> candidates = new ArrayList<>();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.NPU) continue;
            if (dev.getForwardingChips() == null) continue;
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity port : chip.getPorts().values()) {
                    if (port instanceof NpuPortEntity) {
                        NpuPortEntity npuPort = (NpuPortEntity) port;
                        if (npuPort.getEid() != null && port.getCna() != null) {
                            candidates.add(new NpuCandidate(
                                dev.getDeviceName(),
                                port.getPortName(),
                                npuPort.getEid(),
                                port.getCna(),
                                dev.getRack(),
                                port.getRemoteDevice()));
                        }
                    }
                }
            }
        }
        return candidates;
    }

    private Set<String> collectL2swNames(Map<String, DeviceEntity> devices) {
        Set<String> l2swNames = new HashSet<>();
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() == DeviceType.SW && dev instanceof SwDevice) {
                SwDevice sw = (SwDevice) dev;
                if (sw.getSwitchLevel() == SwitchLevel.L2) {
                    l2swNames.add(dev.getDeviceName());
                }
            }
        }
        return l2swNames;
    }

    private void collectBidirectionalLinks(SuperNode superNode,
                                            Map<String, DeviceEntity> devices,
                                            Set<String> l2swNames,
                                            List<LinkInfo> links) {
        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            if (dev.getForwardingChips() == null) continue;
            if (!(dev instanceof SwDevice) || ((SwDevice) dev).getSwitchLevel() != SwitchLevel.L1) continue;

            for (Map.Entry<Integer, ? extends ForwardingChip> chipEntry : dev.getForwardingChips().entrySet()) {
                Integer chipIdx = chipEntry.getKey();
                ForwardingChip chip = chipEntry.getValue();

                RoutingTableKey rtKey = new RoutingTableKey(
                    superNode.getName(), dev.getDeviceName(), chipIdx);
                RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
                if (rt == null || rt.getRoutes() == null) continue;

                for (Map.Entry<RoutePrefix, RoutingEntry> routeEntry : rt.getRoutes().entrySet()) {
                    RoutingEntry routingEntry = routeEntry.getValue();
                    if (routingEntry.getOutPortInfos() == null) continue;

                    List<OutPortInfo> ports = new ArrayList<>(routingEntry.getOutPortInfos().values());

                    for (int idx = 0; idx < ports.size(); idx++) {
                        String portName = ports.get(idx).getPortName();

                        PortEntity port = chip.getPorts() != null
                            ? chip.getPorts().get(portName) : null;
                        if (port == null || port.getRemoteDevice() == null) continue;
                        if (!l2swNames.contains(port.getRemoteDevice())) continue;

                        links.add(new LinkInfo(
                            dev.getDeviceName(), chipIdx, portName,
                            port.getRemoteDevice(), port.getRemotePort(),
                            idx, ports.size()));
                    }
                }
            }
        }

        for (DeviceEntity dev : devices.values()) {
            if (dev.getDeviceType() != DeviceType.SW) continue;
            if (!(dev instanceof SwDevice) || ((SwDevice) dev).getSwitchLevel() != SwitchLevel.L2) continue;
            if (dev.getForwardingChips() == null) continue;

            for (Map.Entry<Integer, ? extends ForwardingChip> chipEntry : dev.getForwardingChips().entrySet()) {
                Integer chipIdx = chipEntry.getKey();
                ForwardingChip chip = chipEntry.getValue();

                RoutingTableKey rtKey = new RoutingTableKey(
                    superNode.getName(), dev.getDeviceName(), chipIdx);
                RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
                if (rt == null || rt.getRoutes() == null) continue;

                for (Map.Entry<RoutePrefix, RoutingEntry> routeEntry : rt.getRoutes().entrySet()) {
                    if (routeEntry.getKey().getMaskLength() == 0) continue;

                    RoutingEntry routingEntry = routeEntry.getValue();
                    if (routingEntry.getOutPortInfos() == null) continue;

                    List<OutPortInfo> ports = new ArrayList<>(routingEntry.getOutPortInfos().values());
                    if (ports.size() <= 1) continue;

                    for (int idx = 0; idx < ports.size(); idx++) {
                        String portName = ports.get(idx).getPortName();

                        PortEntity port = chip.getPorts() != null
                            ? chip.getPorts().get(portName) : null;
                        if (port == null || port.getRemoteDevice() == null) continue;
                        DeviceEntity remoteDev = devices.get(port.getRemoteDevice());
                        if (!isL1Sw(remoteDev)) continue;

                        String dstChassis = remoteDev.getRack();

                        links.add(new LinkInfo(
                            dev.getDeviceName(), chipIdx, portName,
                            port.getRemoteDevice(), port.getRemotePort(),
                            idx, ports.size(), dstChassis));
                    }
                }
            }
        }
    }

    private void buildCrossChassisCandidates(List<NpuCandidate> allNpus,
                                              List<NpuCandidate> srcList,
                                              List<NpuCandidate> dstList) {
        srcList.addAll(allNpus);
        dstList.addAll(allNpus);
    }

    private static boolean isL1Sw(DeviceEntity dev) {
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L1;
    }

    private static boolean isL2Sw(DeviceEntity dev) {
        return dev != null && dev.getDeviceType() == DeviceType.SW
            && dev instanceof SwDevice && ((SwDevice) dev).getSwitchLevel() == SwitchLevel.L2;
    }

    private static void logFwdFail() {
        fwdFailLogCount++;
        if (fwdFailLogCount % 50000 == 1) {
            System.out.println("  fwdFail stats: fail1(srcConn)=" + fwdFail1
                + " fail2(route)=" + fwdFail2
                + " fail3a(srcL1swOutPort_null)=" + fwdFail3a
                + " fail3b(srcL1swOutPort_remoteDev_null)=" + fwdFail3b
                + " fail3c(dstL1swOutPort_null/mismatch)=" + fwdFail3c
                + " fail4(l2swDev)=" + fwdFail4
                + " fail5(l2swInPort)=" + fwdFail5
                + " fail6(l2swChips)=" + fwdFail6
                + " fail7(l2swChipChassis)=" + fwdFail7
                + " fail8(l2swDstPorts)=" + fwdFail8
                + " fail9(l2swOutPort)=" + fwdFail9
                + " fail10(dstL1swDev)=" + fwdFail10
                + " fail11(dstL1swInPort)=" + fwdFail11
                + " fail12(dstL1swRoute)=" + fwdFail12);
        }
    }

    private static void logRevFail() {
        revFailLogCount++;
        if (revFailLogCount % 5000 == 1) {
            System.out.println("  revFail stats: A(match)=" + revFailA
                + " B(dstL1swRoute)=" + revFailB
                + " C(dstL1swRevOutPort)=" + revFailC
                + " D(l2swRevDev)=" + revFailD
                + " E(l2swRevSrcPorts_empty)=" + revFailE
                + " F(srcL1swRevRoute)=" + revFailF
                + " G(srcL1swRevOutPort_mismatch)=" + revFailG
                + " H(srcL1swRevInPort_null)=" + revFailH);
        }
    }

    private static class PairCoverage {
        final NpuCandidate src;
        final NpuCandidate dst;
        final List<String> fwdKeys;
        final List<String> revKeys;
        final List<CoveredLinkDetail> forwardLinkDetails;
        final List<CoveredLinkDetail> reverseLinkDetails;
        final String srcChassis;
        final String dstChassis;

        PairCoverage(NpuCandidate src, NpuCandidate dst, List<String> fwdKeys,
                     List<String> revKeys, List<CoveredLinkDetail> forwardLinkDetails,
                     List<CoveredLinkDetail> reverseLinkDetails,
                     String srcChassis, String dstChassis) {
            this.src = src;
            this.dst = dst;
            this.fwdKeys = fwdKeys;
            this.revKeys = revKeys;
            this.forwardLinkDetails = forwardLinkDetails;
            this.reverseLinkDetails = reverseLinkDetails;
            this.srcChassis = srcChassis;
            this.dstChassis = dstChassis;
        }
    }

    /** 一次贪心运行的产出,用于多轮随机重启后按 EID 均匀度择优。 */
    private static class GreedyRun {
        List<CoveredPair> selected;
        boolean[] pairUsed;
        List<PairCoverage> candidateOrder;
        int maxEidUsage;
        long eidSumSquares;
        int pairCount;
        boolean fullCoverage;

        boolean betterThan(GreedyRun o) {
            if (o == null) return true;
            if (fullCoverage != o.fullCoverage) return fullCoverage;
            if (maxEidUsage != o.maxEidUsage) return maxEidUsage < o.maxEidUsage;
            if (eidSumSquares != o.eidSumSquares) return eidSumSquares < o.eidSumSquares;
            return pairCount < o.pairCount;
        }
    }

    private CoverageSearchResult runGreedyCoverageDualDisjoint(
            List<PairCoverage> candidates,
            Map<String, LinkInfo> linkMap,
            int totalLinks,
            int fixedDataUdpSrcPort,
            int fixedAckUdpSrcPort) {

        // 多轮随机重启:打乱候选顺序重跑单轮双覆盖,按「覆盖率 > max(EID使用) > EID平方和 > pair数」择优;
        // 一旦某轮 max(EID使用) 达到预算下限(不可能再优),提前终止,避免无谓的多轮开销。
        GreedyRun best = null;
        Random rnd = new Random(0x5eed);
        for (int attempt = 0; attempt < RESTART_ATTEMPTS; attempt++) {
            if (attempt > 0) Collections.shuffle(candidates, rnd);
            GreedyRun run = dualSelect(candidates, linkMap);
            if (best == null || run.betterThan(best)) best = run;
            if (run.maxEidUsage <= DUAL_EID_BUDGET_START) break;
        }

        List<CoveredPair> selected = best.selected;
        trimRedundantPairs(selected, 2);
        rebalanceEidUsage(selected, best.candidateOrder, best.pairUsed, 2);
        trimRedundantPairs(selected, 2);

        Map<String, Integer> eidUsage = new HashMap<>();
        Map<String, Integer> npuUsageByChassis = new HashMap<>();
        Map<String, Integer> npuUsage = new HashMap<>();
        recomputeUsage(selected, eidUsage, npuUsageByChassis, npuUsage);

        boolean fullCoverage = best.fullCoverage;
        Map<String, Integer> linkCounts = computeLinkCounts(selected);
        for (String k : linkMap.keySet()) {
            if (linkCounts.getOrDefault(k, 0) < 2) { fullCoverage = false; break; }
        }

        return buildResult(linkMap, selected,
            totalLinks, fixedDataUdpSrcPort, fixedAckUdpSrcPort, fullCoverage,
            eidUsage, npuUsageByChassis);
    }

    private GreedyRun dualSelect(
            List<PairCoverage> candidates,
            Map<String, LinkInfo> linkMap) {

        Map<String, Integer> linkCoverCount = new HashMap<>();
        for (String k : linkMap.keySet()) linkCoverCount.put(k, 0);

        List<CoveredPair> selected = new ArrayList<>();
        boolean[] pairUsed = new boolean[candidates.size()];
        Map<String, Integer> srcEidUsage = new HashMap<>();
        Map<String, Integer> dstEidUsage = new HashMap<>();
        Map<String, Integer> npuUsageByChassis = new HashMap<>();
        Map<String, Integer> npuUsage = new HashMap<>();
        int budget = DUAL_EID_BUDGET_START;

        // 单轮双覆盖:直接以 "每条 link 覆盖 ≥2" 为目标贪心,
        // 打分沿用 EID(非线性)/机框公平惩罚与链路重复惩罚,叠加冷 EID/冷 NPU 奖励与硬上限。
        singlePassDoubleCover(candidates, pairUsed, selected, linkCoverCount,
            srcEidUsage, dstEidUsage, npuUsageByChassis, npuUsage, budget);
        trimRedundantPairs(selected, 2);

        boolean fullCoverage = true;
        Map<String, Integer> linkCounts = computeLinkCounts(selected);
        for (String k : linkMap.keySet()) {
            if (linkCounts.getOrDefault(k, 0) < 2) { fullCoverage = false; break; }
        }

        GreedyRun run = new GreedyRun();
        run.selected = selected;
        run.pairUsed = pairUsed;
        run.candidateOrder = new ArrayList<>(candidates);
        run.fullCoverage = fullCoverage;
        computeMetric(run);
        return run;
    }

    private void singlePassDoubleCover(
            List<PairCoverage> candidates, boolean[] pairUsed,
            List<CoveredPair> selected, Map<String, Integer> linkCoverCount,
            Map<String, Integer> srcEidUsage, Map<String, Integer> dstEidUsage,
            Map<String, Integer> npuUsageByChassis,
            Map<String, Integer> npuUsage, int budget) {

        // 所有 coverCount < 2 的 link 都是待覆盖目标
        Set<String> underCovered = new HashSet<>();
        for (Map.Entry<String, Integer> e : linkCoverCount.entrySet()) {
            if (e.getValue() < 2) underCovered.add(e.getKey());
        }

        // 反向索引 + 每候选「覆盖的 underCovered link 数」(增量维护),采用与 MIN_COVERAGE 相同的按候选全量扫描
        Map<String, List<Integer>> linkToPairs = new HashMap<>();
        int[] raw = new int[candidates.size()];
        for (int pi = 0; pi < candidates.size(); pi++) {
            PairCoverage pc = candidates.get(pi);
            int r = 0;
            for (String k : pc.fwdKeys) {
                if (underCovered.contains(k)) r++;
                linkToPairs.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
            }
            for (String k : pc.revKeys) {
                if (underCovered.contains(k)) r++;
                linkToPairs.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
            }
            raw[pi] = r;
        }

        while (!underCovered.isEmpty()) {
            int bestIdx = -1;
            double bestScore = Double.NEGATIVE_INFINITY;
            int bestMax = Integer.MAX_VALUE;
            int budgetSkipped = 0;

            for (int pi = 0; pi < candidates.size(); pi++) {
                if (pairUsed[pi] || raw[pi] <= 0) continue;
                PairCoverage pc = candidates.get(pi);

                // 预算仍按 EID 总量（src+dst）限制；惩罚按角色分开（在 scorePair 内）。
                int srcSide = srcEidUsage.getOrDefault(pc.src.eid, 0);
                int dstSide = dstEidUsage.getOrDefault(pc.dst.eid, 0);
                int srcTotal = srcSide + dstEidUsage.getOrDefault(pc.src.eid, 0);
                int dstTotal = srcEidUsage.getOrDefault(pc.dst.eid, 0) + dstSide;
                if (srcTotal >= budget || dstTotal >= budget) { budgetSkipped++; continue; }

                double score = scorePair(pc, raw[pi], srcEidUsage, dstEidUsage,
                    npuUsageByChassis, npuUsage, linkCoverCount,
                    EID_FAIRNESS_WEIGHT, NPU_FAIRNESS_WEIGHT, REPEAT_WEIGHT);

                int curMax = Math.max(srcSide, dstSide);
                if (score > bestScore
                    || (score == bestScore && bestIdx >= 0 && curMax < bestMax)) {
                    bestScore = score; bestIdx = pi; bestMax = curMax;
                }
            }

            if (bestIdx < 0) {
                if (budgetSkipped == 0) break;   // 无候选可覆盖剩余 link → 真正卡住
                budget++;                        // 放宽硬性 EID 上限后重扫
                continue;
            }

            PairCoverage winner = candidates.get(bestIdx);
            pairUsed[bestIdx] = true;
            addPairToSelected(winner, selected, linkCoverCount, srcEidUsage,
                dstEidUsage, npuUsageByChassis, npuUsage);

            Set<String> newlyCovered = new HashSet<>();
            for (String k : winner.fwdKeys) {
                if (linkCoverCount.getOrDefault(k, 0) >= 2 && underCovered.remove(k)) {
                    newlyCovered.add(k);
                }
            }
            for (String k : winner.revKeys) {
                if (linkCoverCount.getOrDefault(k, 0) >= 2 && underCovered.remove(k)) {
                    newlyCovered.add(k);
                }
            }
            for (String k : newlyCovered) {
                List<Integer> pis = linkToPairs.get(k);
                if (pis != null) {
                    for (int pi : pis) { if (!pairUsed[pi]) raw[pi]--; }
                }
            }
        }
    }

    private void trimRedundantPairs(
            List<CoveredPair> selected,
            int coverThreshold) {

        if (selected == null || selected.size() < 2) return;

        // 自维护的「活计数」:删除后仍 ≥ coverThreshold 才允许删,保证覆盖不破坏
        Map<String, Integer> linkCnt = new HashMap<>();
        for (CoveredPair p : selected) {
            for (String k : p.forwardCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
            for (String k : p.reverseCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
        }

        for (int pass = 0; pass < 3; pass++) {
            boolean removed = false;
            for (int si = selected.size() - 1; si >= 0; si--) {
                CoveredPair p = selected.get(si);

                boolean redundant = true;
                for (String k : p.forwardCoveredKeys) {
                    if (linkCnt.getOrDefault(k, 0) <= coverThreshold) { redundant = false; break; }
                }
                if (redundant) {
                    for (String k : p.reverseCoveredKeys) {
                        if (linkCnt.getOrDefault(k, 0) <= coverThreshold) { redundant = false; break; }
                    }
                }
                if (!redundant) continue;

                for (String k : p.forwardCoveredKeys) linkCnt.merge(k, -1, Integer::sum);
                for (String k : p.reverseCoveredKeys) linkCnt.merge(k, -1, Integer::sum);
                selected.remove(si);
                removed = true;
            }
            if (!removed) break;
        }
    }

    private double scorePair(PairCoverage pc, int raw,
                              Map<String, Integer> srcEidUsage,
                              Map<String, Integer> dstEidUsage,
                              Map<String, Integer> npuUsageByChassis,
                              Map<String, Integer> npuUsage,
                              Map<String, Integer> linkCoverCount,
                              double eidFairnessWeight,
                              double npuFairnessWeight, double repeatWeight) {
        // 源侧 EID 按"作为源的次数"、目的侧 EID 按"作为目的的次数"分别惩罚，
        // 避免 total 均衡但 src/dst 各自失衡。
        int srcUsage = srcEidUsage.getOrDefault(pc.src.eid, 0);
        int dstUsage = dstEidUsage.getOrDefault(pc.dst.eid, 0);

        int srcNpuPenalty = npuUsageByChassis.getOrDefault(pc.srcChassis, 0);
        int dstNpuPenalty = npuUsageByChassis.getOrDefault(pc.dstChassis, 0);

        // 单 NPU 设备级使用次数（区分于机框级 npuUsageByChassis）
        int srcNpuUsage = npuUsage.getOrDefault(pc.src.deviceName, 0);
        int dstNpuUsage = npuUsage.getOrDefault(pc.dst.deviceName, 0);

        double repeatPenalty = 0;
        for (String k : pc.fwdKeys) repeatPenalty += linkCoverCount.getOrDefault(k, 0);
        for (String k : pc.revKeys) repeatPenalty += linkCoverCount.getOrDefault(k, 0);

        int coldEid = (srcUsage == 0 ? 1 : 0) + (dstUsage == 0 ? 1 : 0);
        int coldNpu = (srcNpuUsage == 0 ? 1 : 0) + (dstNpuUsage == 0 ? 1 : 0);
        return raw
            - eidFairnessWeight * (srcUsage * srcUsage + dstUsage * dstUsage)
            - npuFairnessWeight * (srcNpuPenalty + dstNpuPenalty)
            - repeatWeight * repeatPenalty
            + COLD_EID_BONUS * coldEid
            + COLD_NPU_BONUS * coldNpu;
    }

    private void addPairToSelected(PairCoverage pc, List<CoveredPair> selected,
                                    Map<String, Integer> linkCoverCount,
                                    Map<String, Integer> srcEidUsage,
                                    Map<String, Integer> dstEidUsage,
                                    Map<String, Integer> npuUsageByChassis,
                                    Map<String, Integer> npuUsage) {
        selected.add(new CoveredPair(pc.src, pc.dst,
            new ArrayList<>(pc.fwdKeys), new ArrayList<>(pc.revKeys),
            pc.forwardLinkDetails, pc.reverseLinkDetails,
            pc.srcChassis, pc.dstChassis));

        srcEidUsage.merge(pc.src.eid, 1, Integer::sum);
        dstEidUsage.merge(pc.dst.eid, 1, Integer::sum);

        String srcChassis = pc.srcChassis;
        String dstChassis = pc.dstChassis;
        npuUsageByChassis.merge(srcChassis, 1, Integer::sum);
        npuUsageByChassis.merge(dstChassis, 1, Integer::sum);

        npuUsage.merge(pc.src.deviceName, 1, Integer::sum);
        npuUsage.merge(pc.dst.deviceName, 1, Integer::sum);

        for (String k : pc.fwdKeys) linkCoverCount.merge(k, 1, Integer::sum);
        for (String k : pc.revKeys) linkCoverCount.merge(k, 1, Integer::sum);
    }

    private CoverageSearchResult runGreedyCoverage(
            List<PairCoverage> candidates,
            Map<String, LinkInfo> linkMap,
            int totalLinks,
            int fixedDataUdpSrcPort,
            int fixedAckUdpSrcPort) {

        // 多轮随机重启:打乱候选顺序重跑贪心,按「覆盖率 > max(EID使用) > EID平方和 > pair数」择优
        GreedyRun best = null;
        Random rnd = new Random(0x6ee9);
        for (int attempt = 0; attempt < RESTART_ATTEMPTS; attempt++) {
            if (attempt > 0) Collections.shuffle(candidates, rnd);
            GreedyRun run = greedySelect(candidates, linkMap);
            if (best == null || run.betterThan(best)) best = run;
            if (run.maxEidUsage <= GREEDY_EID_BUDGET_START) break;
        }

        List<CoveredPair> selected = best.selected;
        trimRedundantPairs(selected, 1);
        rebalanceEidUsage(selected, best.candidateOrder, best.pairUsed, 1);
        trimRedundantPairs(selected, 1);

        Map<String, Integer> eidUsage = new HashMap<>();
        Map<String, Integer> npuUsageByChassis = new HashMap<>();
        Map<String, Integer> npuUsage = new HashMap<>();
        recomputeUsage(selected, eidUsage, npuUsageByChassis, npuUsage);

        boolean fullCoverage = best.fullCoverage;
        Map<String, Integer> linkCounts = computeLinkCounts(selected);
        for (String k : linkMap.keySet()) {
            if (linkCounts.getOrDefault(k, 0) < 1) { fullCoverage = false; break; }
        }

        return buildResult(linkMap, selected,
                           totalLinks, fixedDataUdpSrcPort, fixedAckUdpSrcPort, fullCoverage,
                           eidUsage, npuUsageByChassis);
    }

    private GreedyRun greedySelect(
            List<PairCoverage> candidates,
            Map<String, LinkInfo> linkMap) {

        Set<String> uncovered = new HashSet<>(linkMap.keySet());
        List<CoveredPair> selected = new ArrayList<>();
        boolean[] pairUsed = new boolean[candidates.size()];

        Map<String, Integer> srcEidUsage = new HashMap<>();
        Map<String, Integer> dstEidUsage = new HashMap<>();
        Map<String, Integer> npuUsageByChassis = new HashMap<>();
        Map<String, Integer> npuUsage = new HashMap<>();
        int budget = GREEDY_EID_BUDGET_START;

        Map<String, Integer> linkCoverCountSoFar = new HashMap<>();
        for (String k : linkMap.keySet()) linkCoverCountSoFar.put(k, 0);

        Map<String, List<Integer>> linkToPairIdx = new HashMap<>();
        int[] pairRawScore = new int[candidates.size()];
        for (int pi = 0; pi < candidates.size(); pi++) {
            PairCoverage pc = candidates.get(pi);
            int score = 0;
            for (String k : pc.fwdKeys) {
                if (uncovered.contains(k)) score++;
                linkToPairIdx.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
            }
            for (String k : pc.revKeys) {
                if (uncovered.contains(k)) score++;
                linkToPairIdx.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
            }
            pairRawScore[pi] = score;
        }

        while (!uncovered.isEmpty()) {
            int bestIdx = -1, bestScore = Integer.MIN_VALUE;
            int bestMax = Integer.MAX_VALUE;
            int budgetSkipped = 0;

            for (int pi = 0; pi < candidates.size(); pi++) {
                if (pairUsed[pi] || pairRawScore[pi] <= 0) continue;
                PairCoverage pc = candidates.get(pi);

                // 源侧 EID 按"作为源的次数"、目的侧 EID 按"作为目的的次数"分别惩罚；
                // 预算仍按 EID 总量（src+dst）限制，避免放宽硬上限。
                int srcSide = srcEidUsage.getOrDefault(pc.src.eid, 0);
                int dstSide = dstEidUsage.getOrDefault(pc.dst.eid, 0);
                int srcTotal = srcSide + dstEidUsage.getOrDefault(pc.src.eid, 0);
                int dstTotal = srcEidUsage.getOrDefault(pc.dst.eid, 0) + dstSide;
                if (srcTotal >= budget || dstTotal >= budget) { budgetSkipped++; continue; }

                int srcNpuPenalty = npuUsageByChassis.getOrDefault(pc.srcChassis, 0);
                int dstNpuPenalty = npuUsageByChassis.getOrDefault(pc.dstChassis, 0);

                // 单 NPU 设备级使用次数（区分于机框级 npuUsageByChassis）
                int srcNpuUsage = npuUsage.getOrDefault(pc.src.deviceName, 0);
                int dstNpuUsage = npuUsage.getOrDefault(pc.dst.deviceName, 0);

                double repeatPenalty = 0;
                for (String k : pc.fwdKeys) { repeatPenalty += linkCoverCountSoFar.getOrDefault(k, 0); }
                for (String k : pc.revKeys) { repeatPenalty += linkCoverCountSoFar.getOrDefault(k, 0); }

                int coldEid = (srcSide == 0 ? 1 : 0) + (dstSide == 0 ? 1 : 0);
                int coldNpu = (srcNpuUsage == 0 ? 1 : 0) + (dstNpuUsage == 0 ? 1 : 0);
                int score = pairRawScore[pi]
                    - (int)Math.round(EID_FAIRNESS_WEIGHT
                        * (srcSide * srcSide + dstSide * dstSide))
                    - (int)Math.round(NPU_FAIRNESS_WEIGHT * (srcNpuPenalty + dstNpuPenalty))
                    - (int)Math.round(REPEAT_WEIGHT * repeatPenalty)
                    + (int)Math.round(COLD_EID_BONUS * coldEid)
                    + (int)Math.round(COLD_NPU_BONUS * coldNpu);

                int curMax = Math.max(srcSide, dstSide);
                if (score > bestScore
                    || (score == bestScore && bestIdx >= 0 && curMax < bestMax)) {
                    bestScore = score; bestIdx = pi; bestMax = curMax;
                }
            }

            if (bestIdx < 0) {
                if (budgetSkipped == 0) break;   // 无候选可覆盖剩余 link → 真正卡住
                budget++;                        // 放宽硬性 EID 上限后重扫
                continue;
            }

            PairCoverage winner = candidates.get(bestIdx);
            CoveredPair bestPair = new CoveredPair(winner.src, winner.dst,
                new ArrayList<>(winner.fwdKeys), new ArrayList<>(winner.revKeys),
                winner.forwardLinkDetails, winner.reverseLinkDetails,
                winner.srcChassis, winner.dstChassis);

            srcEidUsage.merge(bestPair.src.eid, 1, Integer::sum);
            dstEidUsage.merge(bestPair.dst.eid, 1, Integer::sum);

            String srcChassis = winner.srcChassis;
            String dstChassis = winner.dstChassis;
            npuUsageByChassis.merge(srcChassis, 1, Integer::sum);
            npuUsageByChassis.merge(dstChassis, 1, Integer::sum);

            npuUsage.merge(bestPair.src.deviceName, 1, Integer::sum);
            npuUsage.merge(bestPair.dst.deviceName, 1, Integer::sum);

            selected.add(bestPair);
            pairUsed[bestIdx] = true;

            for (String key : winner.fwdKeys) {
                linkCoverCountSoFar.merge(key, 1, Integer::sum);
            }
            for (String key : winner.revKeys) {
                linkCoverCountSoFar.merge(key, 1, Integer::sum);
            }

            List<String> coveredNow = new ArrayList<>();
            for (String key : winner.fwdKeys) { if (uncovered.remove(key)) coveredNow.add(key); }
            for (String key : winner.revKeys) { if (uncovered.remove(key)) coveredNow.add(key); }
            for (String key : coveredNow) {
                List<Integer> pis = linkToPairIdx.get(key);
                if (pis != null) {
                    for (int pi : pis) { if (!pairUsed[pi]) pairRawScore[pi]--; }
                }
            }
        }

        boolean fullCoverage = uncovered.isEmpty();

        GreedyRun run = new GreedyRun();
        run.selected = selected;
        run.pairUsed = pairUsed;
        run.candidateOrder = new ArrayList<>(candidates);
        run.fullCoverage = fullCoverage;
        computeMetric(run);
        return run;
    }

    private void rebalanceEidUsage(
            List<CoveredPair> selected,
            List<PairCoverage> candidates,
            boolean[] pairUsed,
            int coverThreshold) {
        if (selected == null || selected.size() < 2) return;

        // link → 候选 pair 索引(供按关键链路快速找替换候选)
        Map<String, List<Integer>> linkToPairs = new HashMap<>();
        for (int pi = 0; pi < candidates.size(); pi++) {
            PairCoverage pc = candidates.get(pi);
            for (String k : pc.fwdKeys) linkToPairs.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
            for (String k : pc.revKeys) linkToPairs.computeIfAbsent(k, x -> new ArrayList<>()).add(pi);
        }

        // 每轮只做一次「改善性交换」并重算,保证覆盖不被破坏(交换必须保住全部关键链路)
        for (int iter = 0; iter < MAX_REBALANCE_ITERS; iter++) {
            Map<String, Integer> linkCnt = new HashMap<>();
            Map<String, Integer> srcEidUsage = new HashMap<>();
            Map<String, Integer> dstEidUsage = new HashMap<>();
            for (CoveredPair p : selected) {
                srcEidUsage.merge(p.src.eid, 1, Integer::sum);
                dstEidUsage.merge(p.dst.eid, 1, Integer::sum);
                for (String k : p.forwardCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
                for (String k : p.reverseCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
            }

            int bestSi = -1, bestPi = -1;
            int bestGain = 0;
            int bestMax = Integer.MAX_VALUE;

            for (int si = 0; si < selected.size(); si++) {
                CoveredPair p = selected.get(si);
                // 源侧 EID 按"作为源"、目的侧 EID 按"作为目的"分别计使用代价
                int curUsage = srcEidUsage.getOrDefault(p.src.eid, 0)
                             + dstEidUsage.getOrDefault(p.dst.eid, 0);

                // 关键链路 = 移除本 pair 后会跌破覆盖阈值的链路
                Set<String> critical = new HashSet<>();
                for (String k : p.forwardCoveredKeys) {
                    if (linkCnt.getOrDefault(k, 0) <= coverThreshold) critical.add(k);
                }
                for (String k : p.reverseCoveredKeys) {
                    if (linkCnt.getOrDefault(k, 0) <= coverThreshold) critical.add(k);
                }
                if (critical.isEmpty()) continue;   // 完全冗余 → 已由 trimRedundantPairs 处理

                Set<Integer> seen = new HashSet<>();
                for (String k : critical) {
                    List<Integer> pis = linkToPairs.get(k);
                    if (pis == null) continue;
                    for (int pi : pis) {
                        if (pairUsed[pi] || !seen.add(pi)) continue;
                        PairCoverage pc = candidates.get(pi);
                        if (pc.src.eid.equals(p.src.eid) || pc.dst.eid.equals(p.dst.eid)
                            || pc.src.eid.equals(p.dst.eid) || pc.dst.eid.equals(p.src.eid)) continue;
                        int match = 0;
                        for (String kk : pc.fwdKeys) { if (critical.contains(kk)) match++; }
                        for (String kk : pc.revKeys) { if (critical.contains(kk)) match++; }
                        if (match < critical.size()) continue;

                        int su = srcEidUsage.getOrDefault(pc.src.eid, 0);
                        int du = dstEidUsage.getOrDefault(pc.dst.eid, 0);
                        int gain = curUsage - (su + du);
                        int cm = Math.max(su, du);
                        if (gain > bestGain
                            || (gain == bestGain && bestPi >= 0 && cm < bestMax)) {
                            bestGain = gain; bestPi = pi; bestSi = si; bestMax = cm;
                        }
                    }
                }
            }

            if (bestSi < 0 || bestGain <= 0) break;

            PairCoverage rep = candidates.get(bestPi);
            pairUsed[bestPi] = true;
            selected.set(bestSi, new CoveredPair(rep.src, rep.dst,
                new ArrayList<>(rep.fwdKeys), new ArrayList<>(rep.revKeys),
                rep.forwardLinkDetails, rep.reverseLinkDetails,
                rep.srcChassis, rep.dstChassis));
        }
    }

    private Map<String, Integer> computeLinkCounts(List<CoveredPair> selected) {
        Map<String, Integer> linkCnt = new HashMap<>();
        for (CoveredPair p : selected) {
            for (String k : p.forwardCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
            for (String k : p.reverseCoveredKeys) linkCnt.merge(k, 1, Integer::sum);
        }
        return linkCnt;
    }

    private void recomputeUsage(List<CoveredPair> selected,
                                Map<String, Integer> eidUsage,
                                Map<String, Integer> npuUsageByChassis,
                                Map<String, Integer> npuUsage) {
        for (CoveredPair p : selected) {
            eidUsage.merge(p.src.eid, 1, Integer::sum);
            eidUsage.merge(p.dst.eid, 1, Integer::sum);
            String srcChassis = p.srcChassis;
            String dstChassis = p.dstChassis;
            npuUsageByChassis.merge(srcChassis, 1, Integer::sum);
            npuUsageByChassis.merge(dstChassis, 1, Integer::sum);
            npuUsage.merge(p.src.deviceName, 1, Integer::sum);
            npuUsage.merge(p.dst.deviceName, 1, Integer::sum);
        }
    }

    private void computeMetric(GreedyRun run) {
        run.pairCount = run.selected.size();
        Map<String, Integer> eidUsage = new HashMap<>();
        for (CoveredPair p : run.selected) {
            eidUsage.merge(p.src.eid, 1, Integer::sum);
            eidUsage.merge(p.dst.eid, 1, Integer::sum);
        }
        run.maxEidUsage = 0;
        run.eidSumSquares = 0;
        for (int c : eidUsage.values()) {
            run.maxEidUsage = Math.max(run.maxEidUsage, c);
            run.eidSumSquares += (long) c * c;
        }
    }

    private void computeRepeatCounts(List<LinkInfo> allLinks,
                                      List<CoveredPair> selected) {
        Map<String, LinkInfo> linkMap = new HashMap<>();
        for (LinkInfo link : allLinks) {
            linkMap.put(link.getKey(), link);
            link.coverCount = 0;
        }

        for (CoveredPair pair : selected) {
            for (String key : pair.forwardCoveredKeys) {
                LinkInfo li = linkMap.get(key);
                if (li != null) li.coverCount++;
            }
            for (String key : pair.reverseCoveredKeys) {
                LinkInfo li = linkMap.get(key);
                if (li != null) li.coverCount++;
            }
        }
    }

    private CoverageSearchResult emptyResult() {
        return new CoverageSearchResult(
            new ArrayList<>(), new ArrayList<>(), 0, 0, 0.0, 0, 0, 0.0, 0.0, false,
            new HashMap<>(), new HashMap<>(), new HashMap<>(), new HashMap<>());
    }
}
