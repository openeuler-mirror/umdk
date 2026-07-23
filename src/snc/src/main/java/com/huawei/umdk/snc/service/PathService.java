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
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.log.Logger;
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
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.InternalPathHop;
import com.huawei.umdk.snc.exception.PathPlanException;
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
    private static final Logger LOG = new Logger(PathService.class);

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

        Map<String, DeviceEntity> allDevices = superNode.getAllDevices();

        DeviceEntity srcDevice = allDevices.get(request.getSrcDevice());
        if (srcDevice == null) {
            LOG.error("planPath: error=Source device not found in topology, src=%s", request.getSrcDevice());
            return new PathPlanResult(PlanStatus.TOPO_INCOMPLETE,
                "Source device not found in topology: " + request.getSrcDevice());
        }
        if (srcDevice.getDeviceType() != DeviceType.NPU) {
            LOG.error("planPath: error=Source must be NPU device, src=%s, deviceType=%s",
                request.getSrcDevice(), srcDevice.getDeviceType());
            return new PathPlanResult(PlanStatus.SRC_AND_DST_MUST_BE_NPU,
                "Source must be NPU device: " + request.getSrcDevice() + " is " + srcDevice.getDeviceType());
        }

        DeviceEntity destDevice = allDevices.get(request.getDestDevice());
        if (destDevice == null) {
            LOG.error("planPath: error=Destination device not found in topology, dst=%s", request.getDestDevice());
            return new PathPlanResult(PlanStatus.TOPO_INCOMPLETE,
                "Destination device not found in topology: " + request.getDestDevice());
        }
        if (destDevice.getDeviceType() != DeviceType.NPU) {
            LOG.error("planPath: error=Destination must be NPU device, dst=%s, deviceType=%s",
                request.getDestDevice(), destDevice.getDeviceType());
            return new PathPlanResult(PlanStatus.SRC_AND_DST_MUST_BE_NPU,
                "Destination must be NPU device: " + request.getDestDevice() + " is " + destDevice.getDeviceType());
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

        // Step 3-4: ACL bidirectional check
        LOG.debug("planPath: ACL bidirectional check, srcEid=" + srcEid
            + ", dstEid=" + dstEid + ", srcCna=" + srcCna + ", destCna=" + destCna);
        AclData aclData = aclStore.getAclData(request.getSuperNodeName());
        if (aclData == null) {
            LOG.error("planPath: error=ACL data not found, superNode=" + request.getSuperNodeName());
            return new PathPlanResult(PlanStatus.ACL_NOT_FOUND,
                "ACL data not found for superNode: " + request.getSuperNodeName());
        }
        if (!aclCheckEngine.checkBothDirection(aclData, srcEid, dstEid, srcCna, destCna)) {
            LOG.error("planPath: error=ACL check failed, srcEid=" + srcEid + ", dstEid=" + dstEid);
            return new PathPlanResult(PlanStatus.ACL_CHECK_FAILED,
                "ACL check failed");
        }
        LOG.debug("planPath: ACL bidirectional check passed");

        // Step 5: Direct or multi-hop
        Map<String, String> interDevices = request.getInterDevices();
        if (interDevices == null || interDevices.isEmpty()) {
            // Step 6: Direct path verification
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
            // Step 7: Build multi-hop path
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

            // Step 8-12: Route lookup for intermediate devices (forward + reverse)
            LOG.debug("planPath: Forward route phase, targetCna=%s", destCna);
            String forwardTarget = destCna;
            try {
                routePhase(multiHopPath, forwardTarget, request.getSuperNodeName());
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

            String reverseTarget = srcCna;
            try {
                routePhase(reversedPath, reverseTarget, request.getSuperNodeName());
            } catch (PathPlanException e) {
                LOG.error("planPath: error=Reverse route phase failed, reason=%s", e.getMessage());
                return new PathPlanResult(e.getStatus(), e.getMessage());
            }

            // Re-reverse back to forward order
            LOG.debug("planPath: Re-reversing hops back to forward order");
            List<InternalPathHop> restoredHops = pathEngine.reverseHops(reversedHops);
            multiHopPath.setHops(restoredHops);

            // Step 13-15: Build result
            LOG.info("planPath: mode=multi-hop, srcEid=" + multiHopPath.getSrcEid()
                + ", dstEid=" + multiHopPath.getDstEid()
                + ", hopCount=" + (multiHopPath.getHops() != null ? multiHopPath.getHops().size() : 0));
            return buildResult(multiHopPath);
        }
    }

    private void routePhase(InternalPathInfo pathInfo, String targetCna, String superNodeName) {
        LOG.debug("routePhase: targetCna=" + targetCna + ", superNode=" + superNodeName
            + ", hopCount=" + (pathInfo.getHops() != null ? pathInfo.getHops().size() : 0));
        List<InternalPathHop> hops = pathInfo.getHops();
        SuperNode sn = superNodeStore.getSuperNode(superNodeName);
        if (sn == null) {
            LOG.error("routePhase: error=TOPOLOGY_NOT_FOUND, superNode=%s", superNodeName);
            throw new PathPlanException(PlanStatus.TOPO_NOT_FOUND,
                "SuperNode topology not found: " + superNodeName);
        }
        Map<String, DeviceEntity> devices = sn.getAllDevices();
        for (int i = 1; i < hops.size() - 1; i++) {
            InternalPathHop hop = hops.get(i);
            DeviceEntity device = devices.get(hop.getDeviceName());
            if (device == null) {
                LOG.error("routePhase: error=DEVICE_NOT_FOUND, device=%s, superNode=%s",
                    hop.getDeviceName(), superNodeName);
                throw new PathPlanException(PlanStatus.TOPO_CONNECTION_NOT_FOUND,
                    "Device not found: " + hop.getDeviceName() + " in " + superNodeName);
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
                throw new PathPlanException(PlanStatus.ROUTE_NOT_REACHABLE,
                    "ROUTE_NOT_REACHABLE: no route for device " + hop.getDeviceName() + " to target " + targetCna);
            }

            Map<String, OutPortInfo> outPortInfos = bestEntry.getOutPortInfos();
            if (outPortInfos == null || outPortInfos.isEmpty()) {
                LOG.error("routePhase: error=ROUTE_NOT_REACHABLE, no outPort for device=%s",
                    hop.getDeviceName());
                throw new PathPlanException(PlanStatus.ROUTE_NOT_REACHABLE,
                    "ROUTE_NOT_REACHABLE: no outPort for device " + hop.getDeviceName());
            }

            // Set the first outPort on the hop (ECMP handling in V2)
            String outPort = outPortInfos.keySet().iterator().next();
            hop.setOutPort(outPort);
            LOG.debug("routePhase: hopIndex=" + i + ", device=" + hop.getDeviceName()
                + ", outPort=" + outPort + ", mask=" + bestMaskLen);

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