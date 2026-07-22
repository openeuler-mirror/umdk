/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route service
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.service;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.Inbound;
import com.huawei.umdk.snc.route.model.NextHopPort;
import com.huawei.umdk.snc.route.model.OriginNode;
import com.huawei.umdk.snc.route.model.RouteEntry;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.Address;
import com.huawei.umdk.snc.route.topo.template.model.PolicyPath;
import com.huawei.umdk.snc.route.topo.template.model.PolicyPrefix;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import lombok.NonNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.huawei.umdk.snc.route.topo.template.model.AddrType.ALL;
import static com.huawei.umdk.snc.route.topo.template.model.AddrType.PREFIX_ADDR;
import static com.huawei.umdk.snc.route.topo.template.model.AddrType.isNodeAddress;
import static com.huawei.umdk.snc.route.topo.template.model.PolicyPath.PolicyEnType.OTHER;
import static com.huawei.umdk.snc.route.topo.template.model.PolicyPath.PolicyEnType.SECOND_SHORTEST;
import static com.huawei.umdk.snc.route.topo.template.model.PolicyPath.PolicyEnType.SHORTEST;
import static com.huawei.umdk.snc.route.topo.template.model.SncNode.NodePolicyCache.PolicyEnType.PREFIX;

public class RouteMspService {
    private static final Logger log = new Logger(RouteMspService.class);

    private static final int MAX_COST = 10;

    public static Map<String, RouteTable> routeMsp(@NonNull SncTopology topology) {
        Map<String, RouteTable> routeTableMap = new HashMap<>();
        for (SncNode topoNode : topology.getNodeMap().values()) {
            topoNode.getRouteTable().getRouteEntries().clear();
            if (topoNode.enabledPolicy(SncNode.NodePolicyCache.PolicyEnType.PATH)) {
                routeMspSingleNode(topology, topoNode);
                if (!topoNode.getRouteTable().getRouteEntries().isEmpty()) {
                    RouteTable copyRouteTable = new RouteTable();
                    copyRouteTable.getRouteEntries().putAll(topoNode.getRouteTable().getRouteEntries());
                    routeTableMap.put(topoNode.getLabel().toString(), copyRouteTable);
                }
            }
        }

        return routeTableMap;
    }

    private static void addPortNameForNhp(SncNode srcNode) {
        RouteTable routeTable = srcNode.getRouteTable();
        for (Map.Entry<Prefix, RouteEntry> entry : routeTable.getRouteEntries().entrySet()) {
            RouteEntry routeEntry = entry.getValue();
            for (NextHopPort nhp : routeEntry.getNhpSet()) {
                nhp.setOutPortName(srcNode.getPortMap().get(nhp.getOutPortId()).getPortName());
            }
        }
    }

    public static Map<String, OriginNode> routeMspSingleNode(SncTopology topology, SncNode srcNode) {
        // 初始化图结构
        Map<String, OriginNode> currentGraph = new LinkedHashMap<>();
        Map<String, OriginNode> searchGraph = new LinkedHashMap<>();
        Map<String, OriginNode> nextGraph = new LinkedHashMap<>();

        addSrcSearchNode(currentGraph, srcNode.getLabel().toString());

        addInboundsFromParents(topology, currentGraph, searchGraph, nextGraph);

        addInboundsToParents(topology, searchGraph);

        saveRouteTable(topology, searchGraph, srcNode);

        addPortNameForNhp(srcNode);

        dividePathTypes(srcNode);

        return searchGraph;
    }

    private static void addInboundsFromParents(SncTopology topology,
                                               Map<String, OriginNode> currentGraph,
                                               Map<String, OriginNode> searchGraph,
                                               Map<String, OriginNode> nextGraph) {
        do {
            // 为了在循环中安全修改 currentGraph，先复制 key 集合
            Iterator<Map.Entry<String, OriginNode>> iterator = currentGraph.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, OriginNode> entry = iterator.next();
                String nodeId = entry.getKey();
                OriginNode cn = entry.getValue();

                // 获取当前节点对应拓扑节点信息
                SncNode topoNode = topology.getNodeMap().get(nodeId);

                // 遍历当前节点的所有端口（下行）
                for (SncPort topoPort : topoNode.getPortMap().values()) {
                    String peerNodeId = topoPort.getPeerNodeId();
                    if (!topology.getNodeMap().containsKey(peerNodeId)) {
                        log.warn("Peer node missing, node id: %s, port id: %s, peer node id: %s",
                            nodeId, topoPort.getId(), peerNodeId);
                        continue; // 对端节点信息缺失则跳过对端节点
                    }

                    OriginNode sOriginNode = searchGraph.get(peerNodeId);
                    // 上行跳过
                    if (Objects.nonNull(sOriginNode) && sOriginNode.getLayer() < cn.getLayer()) {
                        continue;
                    }

                    OriginNode cOriginNode = currentGraph.get(peerNodeId);
                    // 如果该对端节点已经存在于当前层或已搜索层，则认为是在同层，更新已有节点的 inbound 信息
                    if (existsInCurrentLayer(cOriginNode, sOriginNode, cn.getLayer())) {
                        // 同层： 取出已有的 OriginNode 进行 inbound 更新
                        OriginNode existingNode = Objects.nonNull(sOriginNode) ? sOriginNode : cOriginNode;
                        // 继承邻居节点 cost最小的条目 更新parentNodeId=peerNodeId cost+1
                        Set<Integer> allowedInPortIds = topology.getNodeMap().get(peerNodeId)
                            .allowedInPortIds(topoPort.getPeerPortId());
                        cn.inheritInbound(existingNode, topoPort.getId(), allowedInPortIds, true);
                    }

                    // 下行节点
                    if (Objects.isNull(sOriginNode) && Objects.isNull(cOriginNode)) {
                        if (!nextGraph.containsKey(peerNodeId)) {
                            // 新生成
                            OriginNode newOriginNode = newOriginNode(cn, topoNode, topoPort, peerNodeId);
                            if (newOriginNode.getInboundMap().isEmpty()) {
                                // 由于配置了转发策略，即使是邻居节点也可能在当前层中无法连通（即无新增inbound）
                                continue;
                            }
                            nextGraph.put(peerNodeId, newOriginNode);
                        } else {
                            int inPortId = topoPort.getPeerPortId();
                            if (cn.getLayer() == 1) {
                                nextGraph.get(peerNodeId).getInboundMap().put(
                                    inPortId, new Inbound(inPortId, cn.getNodeId(), 1,
                                        new HashSet<>(Collections.singleton(topoPort.getId()))));
                            } else {
                                nextGraph.get(peerNodeId).inheritInbound(cn, inPortId,
                                    topoNode.allowedInPortIds(topoPort.getId()), true);
                            }
                        }
                    }
                }

                // 该节点处理完毕后，从 currentGraph 移除，并放入 searchGraph 中
                iterator.remove();
                searchGraph.put(nodeId, cn);
            }
        } while (nextGraphProcess(nextGraph, currentGraph));
    }

    private static boolean existsInCurrentLayer(OriginNode cOriginNode, OriginNode sOriginNode, int currentLayer) {
        return Objects.nonNull(cOriginNode) ||
            (Objects.nonNull(sOriginNode) && sOriginNode.getLayer() == currentLayer);
    }

    private static void addInboundsToParents(SncTopology topology, Map<String, OriginNode> searchGraph) {
        List<String> keys = new ArrayList<>(searchGraph.keySet());
        ListIterator<String> iterator = keys.listIterator(keys.size());
        while (iterator.hasPrevious()) {
            String nodeId = iterator.previous();
            OriginNode on = searchGraph.get(nodeId);
            // 如果该节点 inbound 为空，则跳过
            if (on.getInboundMap().isEmpty()) {
                continue;
            }

            // 如果层级为 2，则结束逆序遍历
            if (on.getLayer() == 2) {
                break;
            }

            // 处理 inboundMap 中 cost 最小的 inbound
            Map.Entry<Integer, Inbound> firstEntry = on.getInboundMap().entrySet().iterator().next();
            int minCost = firstEntry.getValue().getCost();
            boolean syncSuccess;
            for (Inbound inbound : on.getInboundMap().values()) {
                if (inbound.getCost() > minCost) {
                    break;
                }
                minCost = inbound.getCost();
                SncNode lowTopoNode = topology.getNodeMap().get(on.getNodeId());
                SncPort lowTopoPort = lowTopoNode.getPortMap().get(inbound.getInPortId());
                OriginNode parentNode = searchGraph.get(inbound.getParentNodeId());
                Set<Integer> allowedInPortIds = lowTopoNode.allowedInPortIds(lowTopoPort.getId());
                syncSuccess = parentNode.inheritInbound(on, lowTopoPort.getPeerPortId(),
                    allowedInPortIds, true);
                if (!syncSuccess) {
                    parentNode.inheritInbound(
                        on, lowTopoPort.getPeerPortId(), allowedInPortIds, false);
                }
            }
        }
    }

    private static OriginNode newOriginNode(OriginNode cn, SncNode node, SncPort topoPort, String peerNodeId) {
        // 新生成
        OriginNode originNode = new OriginNode();
        originNode.setNodeId(peerNodeId);
        originNode.setLayer(cn.getLayer() + 1);

        // cn == 源节点
        if (cn.getLayer() == 1) {
            Integer inPortId = topoPort.getPeerPortId();
            originNode.getInboundMap().put(inPortId, new Inbound(inPortId, cn.getNodeId(), 1,
                new HashSet<>(Collections.singleton(topoPort.getId()))));
        } else {
            originNode.inheritInbound(cn, topoPort.getPeerPortId(), node.allowedInPortIds(topoPort.getId()),
                true);
        }
        return originNode;
    }

    private static void addSrcSearchNode(Map<String, OriginNode> current, String srcNodeId) {
        OriginNode srcOriginNode = new OriginNode();
        srcOriginNode.setNodeId(srcNodeId);
        srcOriginNode.setLayer(1);
        current.put(srcNodeId, srcOriginNode);
    }

    private static boolean nextGraphProcess(Map<String, OriginNode> nextGraph, Map<String, OriginNode> current) {
        if (nextGraph.isEmpty()) {
            return false;
        }

        current.clear();
        // 更新current
        current.putAll(nextGraph);
        nextGraph.clear();
        return true;
    }

    private static void saveRouteTable(SncTopology topology, Map<String, OriginNode> searchGraph, SncNode srcNode) {
        // 先获取所有黑洞路由策略，生成黑洞路由，后续的所有处理中，跳过这些地址
        addBlackHoleRoute(srcNode);

        // 遍历所有原始节点
        searchGraph.forEach((nodeId, originNode) -> {
            if (originNode.getLayer() == 1) {
                return;
            }
            SncNode topoNode = topology.getNodeMap().get(nodeId);
            Collection<Inbound> inbounds = originNode.sortedInboundMapByCost().values();
            // 获取 primaryCNA
            for (Address address : topoNode.getAddrList()) {
                genRouteEntry(srcNode, inbounds, address, topoNode, false);
            }

            // 第二层连源节点特殊处理
            if (originNode.getLayer() == 2) {
                String srcNodeId = srcNode.getLabel().toString();
                for (SncPort topoPort : topoNode.getPortMap().values()) {
                    if (Objects.equals(topoPort.getPeerNodeId(), srcNodeId)) {
                        // 找到和该topoPort对应的inBound：inPortId为topoPort的
                        Collection<Inbound> validInbounds = inbounds.stream().filter(
                            inbound -> inbound.getInPortId() == topoPort.getId()).toList();
                        if (validInbounds.isEmpty()) {
                            continue;
                        }
                        for (Address address : topoPort.getAddrList()) {
                            genRouteEntry(srcNode, validInbounds, address, topoNode, true);
                        }
                    }
                }
            }

            // 遍历 topoPort 获取 peerPort
            topoNode.getPortMap().forEach((portId, topoPort) -> {
                OriginNode peerOriginNode = searchGraph.get(topoPort.getPeerNodeId());
                if (Objects.isNull(peerOriginNode) || peerOriginNode.getLayer() == 1) {
                    return;
                }
                // 跳过peerOriginNode的端口转发策略中禁止转发的inbound
                SncNode peerNode = topology.getNodeMap().get(peerOriginNode.getNodeId());
                Collection<Inbound> allowedInbounds = peerOriginNode.getInboundMap().values().stream()
                    .filter(inbound -> !peerNode.rejectForwarding(inbound.getInPortId(), topoPort.getPeerPortId()))
                    .sorted(Comparator.comparing(Inbound::getCost))
                    .collect(Collectors.toList());

                for (Address address : topoPort.getAddrList()) {
                    genRouteEntry(srcNode, allowedInbounds, address, topoNode, false);
                }
            });

            // 源节点不出框，目标节点出框场景，追加出框路由
            if (topoNode.enabledPolicy(PREFIX)) {
                processPolicyPrefix(srcNode, topoNode, originNode);
            }
        });
    }

    private static void addBlackHoleRoute(SncNode srcNode) {
        // 获取策略中配置的所有黑洞路由地址，添加一个空的路由表项，然后返回黑洞路由的Prefix集合
        srcNode.getPolicyCache().getPathMap().values().stream()
            .filter(policy -> policy.getKey().getDstPrefix() != null && policy.isBlackHoleEnable())
            .forEach(policy -> {
                Prefix prefix = policy.getKey().getDstPrefix();
                RouteEntry emptyEntry = new RouteEntry(prefix);
                srcNode.getRouteTable().getRouteEntries().put(prefix, emptyEntry);
            });
    }

    private static PolicyPath getNonBlackHolePolicy(Map<PolicyPath.PolicyPathKey, PolicyPath> pathMap,
                                                    SncNode dstNode, @NonNull Address address) {
        return pathMap.values().stream()
            .filter(policy -> {
                PolicyPath.PolicyPathKey key = policy.getKey();
                // 1. 框内节点地址，匹配节点或类型label以及地址类型；出框场景dstNode为null所以不会匹配此条件
                boolean matchNodeLabel = dstNode != null &&
                    dstNode.getLabel().matchLabel(key.getDstNodeLabel());
                boolean matchAddrType = key.getDstAddrType() == address.getAddrType() ||
                    key.getDstAddrType() == ALL;

                // 2. 出框场景，dstPrefix为空时匹配任意地址，不为空时精准匹配
                boolean matchDstPrefix = (key.getDstPrefix() == null) ||
                    (PREFIX_ADDR.equals(address.getAddrType()) && address.asPrefix().equals(key.getDstPrefix()));

                // 要求不是黑洞路径策略，且1和2条件都满足
                return matchNodeLabel && matchAddrType && matchDstPrefix && !policy.isBlackHoleEnable();
            })
            .findAny()
            .orElse(null);
    }

    private static void genNextHopsByInbound(PolicyPath policyPath, RouteEntry routeEntry, Inbound inbound,
                                             int costOffset) {
        // 所有从原始几点继承的inbound 生成时cost+1
        if (isIncInbound(policyPath, routeEntry, inbound.getCost() + costOffset, SHORTEST)) {
            // 最短
            for (Integer outIf : inbound.getOutIfSet()) {
                NextHopPort nhp = new NextHopPort(inbound.getCost() + costOffset, outIf, SHORTEST);
                routeEntry.updateNhpSetCosts(nhp);
            }
        } else if (isIncInbound(policyPath, routeEntry, inbound.getCost() + costOffset, SECOND_SHORTEST)) {
            // 非最短
            for (Integer outIf : inbound.getOutIfSet()) {
                NextHopPort nhp = new NextHopPort(inbound.getCost() + costOffset, outIf, SECOND_SHORTEST);
                routeEntry.updateNhpSetCosts(nhp);
            }
        } else if (isIncInbound(policyPath, routeEntry, inbound.getCost() + costOffset, OTHER)) {
            // 备份
            for (Integer outIf : inbound.getOutIfSet()) {
                NextHopPort nhp = new NextHopPort(inbound.getCost() + costOffset, outIf, OTHER);
                routeEntry.updateNhpSetCosts(nhp);
            }
        } else {
            log.debug("Inbound has no applicable path type, inbound: %s", inbound);
        }
    }

    private static void genRouteEntry(SncNode srcNode, Collection<Inbound> inbounds, Address topoAddress,
                                      SncNode topoNode, boolean isDirectLink) {
        if (Objects.isNull(topoAddress) || inbounds.isEmpty()) {
            return;
        }

        RouteTable routeTable = srcNode.getRouteTable();
        Prefix prefix = topoAddress.asPrefix();
        RouteEntry routeEntry = routeTable.getRouteEntries().get(prefix);

        if (Objects.isNull(routeEntry)) {
            routeEntry = new RouteEntry(prefix);
        } else {
            if (routeEntry.getNhpSet().isEmpty()) {
                // 只有黑洞路由的场景会出现非空routeEntry带有空的nhpSet
                return;
            }
        }

        // 最短未启用都不会生成
        PolicyPath policyPath = getNonBlackHolePolicy(srcNode.getPolicyCache().getPathMap(), topoNode, topoAddress);
        if (Objects.isNull(policyPath) || !policyPath.isShortestEnable()) {
            return;
        }

        // Node地址：不加1；Port地址：直连源节点的Port不加1，否则加1
        int costOffset = (isNodeAddress(topoAddress.getAddrType()) || isDirectLink) ? 0 : 1;
        String srcParentNodeId = (isDirectLink ? srcNode : topoNode).getLabel().toString();
        for (Inbound inbound : inbounds) {
            if (inbound.getCost() > MAX_COST) {
                log.info("src node %s topo node %s inPort %s cost %s", srcNode.getLabel(),
                    topoNode.getLabel(), inbound.getInPortId(), inbound.getCost());
                continue;
            }
            // 直连：只处理parentNode是源节点的inbound；非直连：只处理parentNode不是目的节点自身的情况
            if (Objects.equals(inbound.getParentNodeId(), srcParentNodeId) ^ isDirectLink) {
                continue;
            }
            genNextHopsByInbound(policyPath, routeEntry, inbound, costOffset);
        }
        if (!routeEntry.getNhpSet().isEmpty()) {
            routeTable.getRouteEntries().put(routeEntry.getPrefix(), routeEntry);
        }
    }

    private static void processPolicyPrefix(SncNode srcNode, SncNode topoNode, OriginNode oUnion) {
        // 遍历所有Prefix策略（地址、端口配置）
        List<PolicyPrefix> policyList = topoNode.getPolicyCache().getPrefixList();
        RouteTable routeTable = srcNode.getRouteTable();
        for (PolicyPrefix policy : policyList) {
            PolicyPath pp = getNonBlackHolePolicy(srcNode.getPolicyCache().getPathMap(), topoNode,
                new Address(policy.getAddr(), policy.getMaskLen(), policy.getMask(), PREFIX_ADDR));
            if (pp == null || !pp.isShortestEnable()) {
                // 未配置出框地址策略，不生成出框路由
                continue;
            }
            Map<Integer, Integer> outIfCostMap = getCostMap(
                oUnion, 1, inbound -> policy.visible(inbound.getInPortId()));

            // 空表说明所有Inbound端口都不允许出框，结束此PrefixPolicy的处理
            if (outIfCostMap.isEmpty()) {
                continue;
            }

            Prefix prefix = policy.asPrefix();
            // 生成Prefix，刷新路由表中的cost
            if (routeTable.getRouteEntries().get(prefix) == null) {
                RouteEntry entry = new RouteEntry(prefix);
                routeTable.getRouteEntries().put(prefix, entry);
            }
            RouteEntry routeEntry = routeTable.getRouteEntries().get(prefix);
            routeEntry.updateNhpSetCosts(outIfCostMap);
            routeEntry.applyPathPolicy(pp);
        }
    }

    private static Map<Integer, Integer> getCostMap(OriginNode oNode, int costOffset, Predicate<Inbound> condition) {
        Map<Integer, Integer> outIfCostMap = new HashMap<>();
        for (Inbound inbound : oNode.getInboundMap().values()) {
            if (!condition.test(inbound)) {
                continue;
            }
            // 根据Inbound，计算每个出现的outIf的最小cost
            inbound.getOutIfSet().forEach(outIf -> outIfCostMap.compute(outIf, (key, value) -> value == null ?
                (inbound.getCost() + costOffset) :
                Math.min(inbound.getCost() + costOffset, value)));
        }
        return outIfCostMap;
    }

    private static  boolean isIncInbound(PolicyPath policyPath, RouteEntry routeEntry, Integer incCost,
                                         PolicyPath.PolicyEnType pathTypeEnum) {
        Integer findCost = routeEntry.findNhpCostByPathType(pathTypeEnum);
        switch (pathTypeEnum) {
            case SHORTEST:
                if (!policyPath.isShortestEnable()) {
                    return false;
                }
                return findCost == 0 ||findCost.equals(incCost);
            case SECOND_SHORTEST:
                if (!policyPath.isSecondShortestEnable()) {
                    return false;
                }
                return findCost == 0 ||findCost.equals(incCost);
            case OTHER:
                return policyPath.isOtherEnable();
        }
        return false;
    }

    private static void dividePathTypes(SncNode srcNode) {
        Map<Prefix, RouteEntry> routeEntries = srcNode.getRouteTable().getRouteEntries();
        for (RouteEntry entry : routeEntries.values()) {
            for (NextHopPort nhp : entry.getNhpSet()) {
                switch (nhp.getPathType()) {
                    case SHORTEST:
                        entry.getShortestNhp().add(nhp);
                        break;
                    case SECOND_SHORTEST:
                        entry.getSecondNhp().add(nhp);
                        break;
                    case OTHER:
                        entry.getOtherNhp().add(nhp);
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
