/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: parse topology template file
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.service;

import com.alibaba.fastjson2.JSON;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.topo.template.loader.NodeLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PathPolicyItemsLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PathPolicyLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PermitOrDenyPolicy;
import com.huawei.umdk.snc.route.topo.template.loader.PolicyLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PortFwdPolicyLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PrefixLoader;
import com.huawei.umdk.snc.route.topo.template.loader.PrefixPolicyLoader;
import com.huawei.umdk.snc.route.topo.template.loader.TemplateLoader;
import com.huawei.umdk.snc.route.topo.template.model.AddrType;
import com.huawei.umdk.snc.route.topo.template.model.Address;
import com.huawei.umdk.snc.route.topo.template.model.Bitmap;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.PolicyPath;
import com.huawei.umdk.snc.route.topo.template.model.PolicyPrefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class TopoTemplateService {
    private static final Logger log = new Logger(TopoTemplateService.class);

    private static final int MASK_LEN = 32;

    private static SncNode getNode(NodeLoader templateLoader) {
        SncNode node = new SncNode();
        node.getLabel().refreshAllNames(templateLoader.getNodeLabel());
        if (templateLoader.getNodeCna() != null && templateLoader.getMask() != null) {
            long addr = Long.decode(templateLoader.getNodeCna());
            long mask = Long.decode(templateLoader.getMask());
            if ("npu".equals(node.type())) {
                node.getAddrList().add(new Address(addr, MASK_LEN, mask, AddrType.PRIMARY_ADDR));
            } else {
                node.getAddrList().add(new Address(addr, MASK_LEN, mask, AddrType.NODE_ADDR));
            }
        }

        templateLoader.getPortLoaders().forEach(port -> {
            int portId = port.getPortId(); // portid 从0开始算
            SncPort topoPort = new SncPort(portId);
            topoPort.setPortName(port.getPortName());
            if (port.getPortCna() != null && port.getMask() != null) {
                long addr = Long.decode(port.getPortCna());
                long mask = Long.decode(port.getMask());
                topoPort.getAddrList().add(new Address(addr, MASK_LEN, mask, AddrType.PORT_ADDR));
            }
            topoPort.setPeerNodeId(port.getPeerNodeLabel());
            topoPort.setPeerPortId(port.getPeerPortId());
            topoPort.getLabel().refreshAllNames(templateLoader.getNodeLabel() + "|port:" + portId);
            node.getPortMap().put(topoPort.getId(), topoPort);
        });

        templateLoader.getLogicalPortLoaders().forEach(logicalPort -> {
            if (logicalPort.getPortCna() != null && logicalPort.getMask() != null) {
                long addr = Long.decode(logicalPort.getPortCna());
                long mask = Long.decode(logicalPort.getMask());
                if (logicalPort.getMembers() == null || logicalPort.getMembers().isEmpty()) {
                    throw new IllegalArgumentException("logical port must have at least one member");
                }
                for (Integer portId : logicalPort.getMembers()) {
                    SncPort sncPort = node.getPortMap().get(portId);
                    if (sncPort == null) {
                        throw new IllegalArgumentException(String.format("Port %s not found", portId));
                    }
                    sncPort.getAddrList().add(new Address(addr, MASK_LEN, mask, AddrType.PORT_GROUP_ADDR));
                }
            }
        });

        return node;
    }

    private static SncTopology genTopology(TemplateLoader templateLoader) {
        log.info("begin to generate snc topology");
        if (templateLoader == null || templateLoader.getNodeLoaders() == null ||
            templateLoader.getNodeLoaders().isEmpty()) {
            throw new IllegalArgumentException("templateLoader is null or has no node");
        }

        SncTopology topology = new SncTopology();
        topology.getLabel().refreshAllNames(templateLoader.getTemplateLabel());
        for (NodeLoader nodeLoader : templateLoader.getNodeLoaders()) {
            SncNode node = getNode(nodeLoader);
            topology.getNodeMap().put(node.getLabel().toString(), node);
        }

        loadPolicy(topology, templateLoader.getRoutePolicies());

        return topology;
    }

    public static SncTopology parseTemplateJson(String jsonStr) {
        if (jsonStr == null || jsonStr.isEmpty()) {
            throw new IllegalArgumentException("jsonStr is null or empty");
        }

        TemplateLoader templateLoader = JSON.parseObject(jsonStr, TemplateLoader.class);
        return genTopology(templateLoader);
    }



    private static void setFwdPolicyByLabel(Label inLabel, Label outLabel, SncNode srcNode, boolean allowFwd) {
        srcNode.getPortMap().values().stream()
            .filter(port -> matchPeerLabel(port, inLabel))
            .map(SncPort::getPortPolicyCache)
            .forEach(ppc -> {
                ppc.getEnBitmap().set(SncPort.PortPolicyCache.PolicyEnType.FWD.getValue());
                srcNode.getPortMap().values().stream()
                    .filter(outPort -> matchPeerLabel(outPort, outLabel))
                    .mapToInt(SncPort::getId)
                    .forEach(id -> ppc.getPortFwdCapBitmap().set(id, allowFwd));
            });
    }

    private static void setFwdPolicyByPort(SncNode node, List<Integer> inPorts, List<Integer> outPorts,
                                           boolean allowFwd) {
        for (Integer inPortId : inPorts) {
            SncPort inPort = node.getPortMap().get(inPortId);
            SncPort.PortPolicyCache ppc = inPort.getPortPolicyCache();
            ppc.getEnBitmap().set(SncPort.PortPolicyCache.PolicyEnType.FWD.getValue());
            if (ppc.getPortFwdCapBitmap() == null) {
                ppc.setPortFwdCapBitmap(new Bitmap(node.getPortMap().size(), true));
            }
            outPorts.forEach(outPortId -> ppc.getPortFwdCapBitmap().set(outPortId, allowFwd));
        }
    }

    private static void loadPolicy(SncTopology topology, PolicyLoader policyLoader) {
        if (policyLoader == null) {
            throw new IllegalArgumentException("policyLoader is null");
        }
        policyLoader.getPathPolicies().forEach(p -> loadPathPolicy(topology, p));
        policyLoader.getPortFwdPolicyLoader().forEach(p -> loadPortFwdPolicy(topology, p));
        policyLoader.getPrefixPolicyLoader().forEach(p -> loadPrefixPolicy(topology, p));
    }

    private static void loadPathPolicy(SncTopology topology, PathPolicyLoader pathPolicyLoader) {
        for (PathPolicyItemsLoader item : pathPolicyLoader.getPolicies()) {
            loadPathPolicyItem(topology, pathPolicyLoader, item);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadPathPolicyItem(SncTopology topology, PathPolicyLoader pathPolicyLoader,
                                           PathPolicyItemsLoader item) {
        List<List<Object>> keyFields = new ArrayList<>();
        keyFields.add((List<Object>) (List<?>) item.getDstNodeLabels());
        keyFields.add((List<Object>) (List<?>) item.getDstAddressTypes());
        keyFields.add((List<Object>) (List<?>) item.getDstAddresses());

        cartesianProductWrapper(keyFields).forEach(fieldComb -> {
            for (Label match : pathPolicyLoader.getNodeLabels()) {
                topology.getNodeMap().values().stream()
                    .filter(node -> node.getLabel().matchLabel(match))
                    .forEach(node -> {
                        PolicyPath.PolicyPathKey ppk = loadPolicyKeyFromFields(fieldComb);
                        PolicyPath pp = new PolicyPath();
                        pp.setKey(ppk);

                        pp.setShortestEnable(item.getPathTypes().contains("Shortest"));
                        pp.setSecondShortestEnable(item.getPathTypes().contains("SecondShortest"));
                        pp.setOtherEnable(item.getPathTypes().contains("Other"));
                        pp.setBlackHoleEnable(item.getPathTypes().contains("BlackHole"));

                        node.setPolicy(SncNode.NodePolicyCache.PolicyEnType.PATH, true);
                        node.getPolicyCache().getPathMap().put(ppk, pp);
                    });
            }
        });
    }

    private static PolicyPath.PolicyPathKey loadPolicyKeyFromFields(List<Object> fieldComb) {
        PolicyPath.PolicyPathKey ppk = new PolicyPath.PolicyPathKey();
        Object dstNodeLabel = fieldComb.get(0);
        Object dstAddrType = fieldComb.get(1);
        Object dstPrefixLoader = fieldComb.get(2);

        if (dstNodeLabel instanceof Label) {
            ppk.setDstNodeLabel((Label) dstNodeLabel);
        }
        if (dstAddrType instanceof AddrType) {
            ppk.setDstAddrType((AddrType) dstAddrType);
        }
        if (dstPrefixLoader instanceof PrefixLoader) {
            ppk.setDstPrefix(((PrefixLoader) dstPrefixLoader).asPrefix());
        }
        return ppk;
    }

    private static void loadPortFwdPolicy(SncTopology topology, PortFwdPolicyLoader portFwdPolicyLoader) {
        for (Label match : portFwdPolicyLoader.getNodeLabels()) {
            topology.getNodeMap().values().stream()
                .filter(node -> node.getLabel().matchLabel(match))
                .forEach(node -> setNodePortFwdPolicy(portFwdPolicyLoader, node));
        }
    }

    private static void setNodePortFwdPolicy(PortFwdPolicyLoader portFwdPolicyLoader, SncNode node) {
        String defaultPolicy = portFwdPolicyLoader.getDefaultPolicy();
        if (defaultPolicy == null) {
            throw new IllegalArgumentException("defaultPolicy is null");
        }
        boolean defaultDeny = switch (defaultPolicy) {
            case "Deny":
                yield true;
            case "Permit":
                yield false;
            default: {
                log.warn("Default port fwd policy is neither Deny or Permit, denying all fwd by default");
                yield true;
            }
        };
        List<Integer> portList = node.getPortMap().keySet().stream().toList();
        setFwdPolicyByPort(node, portList, portList, !defaultDeny);

        List<PermitOrDenyPolicy> specialCase = defaultDeny ? portFwdPolicyLoader.getPermitPolicies() :
            portFwdPolicyLoader.getDenyPolicies();

        specialCase.stream()
            .map(PermitOrDenyPolicy::getBetweenTwoNodeLabel)
            .forEach(pair -> {
                if (!(pair.size() == 2)) {
                    log.warn("Between two node label list should have 2 items");
                    return;
                }
                setFwdPolicyByLabel(pair.get(0), pair.get(1), node, defaultDeny);
                setFwdPolicyByLabel(pair.get(1), pair.get(0), node, defaultDeny);
            });
    }

    private static void loadPrefixPolicy(SncTopology topology, PrefixPolicyLoader prefixPolicyLoader) {
        for (Label match : prefixPolicyLoader.getNodeLabels()) {
            topology.getNodeMap().values().stream()
                .filter(node -> node.getLabel().matchLabel(match))
                .forEach(node -> {
                    PolicyPrefix policyPrefix = new PolicyPrefix();
                    policyPrefix.setAddr(prefixPolicyLoader.getAddress());
                    policyPrefix.setMaskLen(prefixPolicyLoader.getMaskLen());
                    policyPrefix.setMask(prefixPolicyLoader.getMask());
                    policyPrefix.setVisiblePortBitmap(new Bitmap(node.getPortMap().size()));

                    for (SncPort port : node.getPortMap().values()) {
                        if (prefixPolicyLoader.getPeerNodeLabels().stream()
                            .anyMatch(peerLabel -> matchPeerLabel(port, peerLabel))) {
                            policyPrefix.getVisiblePortBitmap().set(port.getId());
                        }
                    }

                    node.setPolicy(SncNode.NodePolicyCache.PolicyEnType.PREFIX, true);
                    node.getPolicyCache().getPrefixList().add(policyPrefix);
                });
        }
    }

    private static Stream<List<Object>> cartesianProductWrapper(List<List<Object>> sets) {
        return cartesianProduct(sets, 0);
    }

    private static Stream<List<Object>> cartesianProduct(List<List<Object>> sets, int index) {
        if (index == sets.size()) {
            List<Object> emptyList = new ArrayList<>();
            return Stream.of(emptyList);
        }
        List<Object> currentSet = sets.get(index);
        List<Object> tempSet;
        if (currentSet.isEmpty()) {
            tempSet = new ArrayList<>();
            tempSet.add(null);
        } else {
            tempSet = currentSet;
        }
        return tempSet.stream().flatMap(element -> cartesianProduct(sets, index + 1)
            .map(list -> {
                List<Object> newList = new ArrayList<>(list);
                newList.add(0, element);
                return newList;
            }));
    }

    private static boolean matchPeerLabel(SncPort port, Label targetLabel) {
        Label peerNodeLabel = new Label();
        peerNodeLabel.refreshAllNames(port.getPeerNodeId());
        return peerNodeLabel.matchLabel(targetLabel);
    }
}
