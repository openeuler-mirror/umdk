/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.dto.HopInfo;
import com.huawei.umdk.snc.dto.PathInfo;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;
import com.huawei.umdk.snc.engine.AclCheckEngine;
import com.huawei.umdk.snc.engine.PathEngine;
import com.huawei.umdk.snc.engine.RouteLookupEngine;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.InternalPathHop;
import com.huawei.umdk.snc.entity.InternalPathInfo;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.RoutingTableKey;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.store.AclStore;
import com.huawei.umdk.snc.store.SuperNodeStore;
import com.huawei.umdk.snc.util.AddressUtils;

public class PathService {
    private final SuperNodeStore superNodeStore;
    private final AclStore aclStore;
    private final PathEngine pathEngine;
    private final RouteLookupEngine routeLookupEngine;
    private final AclCheckEngine aclCheckEngine;

    public PathService(SuperNodeStore superNodeStore, AclStore aclStore,
                       PathEngine pathEngine, RouteLookupEngine routeLookupEngine,
                       AclCheckEngine aclCheckEngine) {
        this.superNodeStore = superNodeStore;
        this.aclStore = aclStore;
        this.pathEngine = pathEngine;
        this.routeLookupEngine = routeLookupEngine;
        this.aclCheckEngine = aclCheckEngine;
    }

    public PathPlanResult planPath(PathPlanRequest request) {
        // Step 0: SuperNode lookup
        SuperNode superNode = superNodeStore.getSuperNode(request.getSuperNodeName());
        if (superNode == null) {
            return new PathPlanResult(PlanStatus.TOPO_NOT_FOUND,
                "SuperNode topology not found: " + request.getSuperNodeName());
        }

        NpuDevice srcNpuDevice = null;
        NpuDevice destNpuDevice = null;
        if (superNode.getNpuDevices() != null) {
            srcNpuDevice = superNode.getNpuDevices().get(request.getSrcDevice());
            destNpuDevice = superNode.getNpuDevices().get(request.getDestDevice());
        }
        if (srcNpuDevice == null || destNpuDevice == null) {
            return new PathPlanResult(PlanStatus.TOPO_INCOMPLETE,
                "Source or destination NPU device not found");
        }

        // Step 1: Find src port
        NpuPortEntity srcNpuPort = srcNpuDevice.findNpuPort(request.getSrcPort());
        if (srcNpuPort == null) {
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source port not found or invalid");
        }
        String srcEid = srcNpuPort.getEid();
        String srcCna = srcNpuPort.getCna();
        String srcRemoteDevice = srcNpuPort.getRemoteDevice();
        String srcRemotePort = srcNpuPort.getRemotePort();
        if (srcEid == null || srcCna == null) {
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source EID or CNA missing");
        }
        if (!AddressUtils.isValidEid(srcEid)) {
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source EID format invalid");
        }
        if (!AddressUtils.isValidCna(srcCna)) {
            return new PathPlanResult(PlanStatus.SRC_INFO_ERR,
                "Source CNA format invalid");
        }

        // Step 2: Find dest port
        NpuPortEntity destNpuPort = destNpuDevice.findNpuPort(request.getDestPort());
        if (destNpuPort == null) {
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination port not found or invalid");
        }
        String dstEid = destNpuPort.getEid();
        String destCna = destNpuPort.getCna();
        if (dstEid == null || destCna == null) {
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination EID or CNA missing");
        }
        if (!AddressUtils.isValidEid(dstEid)) {
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination EID format invalid");
        }
        if (!AddressUtils.isValidCna(destCna)) {
            return new PathPlanResult(PlanStatus.DST_INFO_ERR,
                "Destination CNA format invalid");
        }

        // Check UPI consistency
        if (srcNpuPort.getUpi() != null && destNpuPort.getUpi() != null) {
            if (!srcNpuPort.getUpi().equals(destNpuPort.getUpi())) {
                return new PathPlanResult(PlanStatus.UPI_MISMATCH,
                    "UPI mismatch between source and destination");
            }
        }

        // Step 3-4: ACL bidirectional check
        AclData aclData = aclStore.getAclData(request.getSuperNodeName());
        if (aclData == null) {
            return new PathPlanResult(PlanStatus.ACL_NOT_FOUND,
                "ACL data not found for superNode: " + request.getSuperNodeName());
        }
        if (!aclCheckEngine.checkBothDirection(aclData, srcEid, dstEid, srcCna, destCna)) {
            return new PathPlanResult(PlanStatus.ACL_CHECK_FAILED,
                "ACL check failed");
        }

        // Step 5: Direct or multi-hop
        Map<String, String> interDevices = request.getInterDevices();
        if (interDevices == null || interDevices.isEmpty()) {
            // Step 6: Direct path verification
            if (srcRemoteDevice == null
                || !srcRemoteDevice.equals(destNpuDevice.getDeviceName())
                || srcRemotePort == null
                || !srcRemotePort.equals(destNpuPort.getPortName())) {
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_ERROR,
                    "Direct connection not found between source and destination");
            }
            // Verify reverse direction too
            if (destNpuPort.getRemoteDevice() == null
                || !destNpuPort.getRemoteDevice().equals(srcNpuDevice.getDeviceName())
                || destNpuPort.getRemotePort() == null
                || !destNpuPort.getRemotePort().equals(srcNpuPort.getPortName())) {
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_ERROR,
                    "Reverse direct connection not found");
            }

            InternalPathInfo directPath = pathEngine.resolveDirectPath(
                srcNpuDevice, srcNpuPort, destNpuDevice, destNpuPort);
            return buildResult(directPath);
        } else {
            // Step 7: Build multi-hop path
            InternalPathInfo multiHopPath;
            try {
                multiHopPath = pathEngine.resolveMultiHopPath(
                    srcNpuDevice, srcNpuPort,
                    destNpuDevice, destNpuPort, interDevices, superNode.getAllDevices());
            } catch (Exception e) {
                return new PathPlanResult(PlanStatus.TOPO_CONNECTION_NOT_FOUND,
                    "Multi-hop path resolution failed: " + e.getMessage());
            }

            // Step 8-12: Route lookup for intermediate devices (forward + reverse)
            String forwardTarget = destCna;
            routePhase(multiHopPath, forwardTarget, request.getSuperNodeName());

            // Step 9: Reverse phase
            List<InternalPathHop> reversedHops = pathEngine.reverseHops(
                multiHopPath.getHops());
            InternalPathInfo reversedPath = new InternalPathInfo();
            reversedPath.setHops(reversedHops);
            reversedPath.setSrcEid(multiHopPath.getDstEid());
            reversedPath.setDstEid(multiHopPath.getSrcEid());
            reversedPath.setSourceCna(multiHopPath.getDestCna());
            reversedPath.setDestCna(multiHopPath.getSourceCna());

            String reverseTarget = srcCna;
            routePhase(reversedPath, reverseTarget, request.getSuperNodeName());

            // Re-reverse back to forward order
            List<InternalPathHop> restoredHops = pathEngine.reverseHops(reversedHops);
            multiHopPath.setHops(restoredHops);

            // Step 13-15: Build result
            return buildResult(multiHopPath);
        }
    }

    private void routePhase(InternalPathInfo pathInfo, String targetCna, String superNodeName) {
        List<InternalPathHop> hops = pathInfo.getHops();
        SuperNode sn = superNodeStore.getSuperNode(superNodeName);
        if (sn == null) {
            throw new RuntimeException("TOPOLOGY_NOT_FOUND: " + superNodeName);
        }
        Map<String, DeviceEntity> devices = sn.getAllDevices();
        for (int i = 1; i < hops.size() - 1; i++) {
            InternalPathHop hop = hops.get(i);
            DeviceEntity device = devices.get(hop.getDeviceName());
            if (device == null) {
                throw new RuntimeException("DEVICE_NOT_FOUND: " + hop.getDeviceName() + " in " + superNodeName);
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
                throw new RuntimeException("ROUTE_NOT_REACHABLE: no route for device "
                    + hop.getDeviceName() + " to target " + targetCna);
            }

            Map<String, OutPortInfo> outPortInfos = bestEntry.getOutPortInfos();
            if (outPortInfos == null || outPortInfos.isEmpty()) {
                throw new RuntimeException("ROUTE_NOT_REACHABLE: no outPort for device "
                    + hop.getDeviceName());
            }

            // Set the first outPort on the hop (ECMP handling in V2)
            String outPort = outPortInfos.keySet().iterator().next();
            hop.setOutPort(outPort);

            // Set multiPath flag
            if (outPortInfos.size() > 1) {
                // V1: multi-path detected, but not fully supported
                // Would check device capability here
            }
        }
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
