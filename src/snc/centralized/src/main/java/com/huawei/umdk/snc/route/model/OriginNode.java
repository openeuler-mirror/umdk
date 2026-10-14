/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route description
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.model;

import lombok.Data;

import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Data
public class OriginNode {
    private String nodeId;

    private LinkedHashMap<Integer, Inbound> inboundMap = new LinkedHashMap<>();

    private int layer;

    public boolean inheritInbound(OriginNode originNode, int inPortId, Set<Integer> allowedInPortIds,
                                  boolean restrictCost) {
        LinkedHashMap<Integer, Inbound> candidateInboundMap = originNode.getInboundMap();
        if (candidateInboundMap.isEmpty()) {
            return false;
        }

        Collection<Inbound> inboundList = candidateInboundMap.values();
        // 取得 candidateInboundMap 中第一条记录的 cost，作为最小 cost
        int minCost = inboundList.iterator().next().getCost();
        boolean hasChanged = false;

        // 遍历 candidateInboundMap，选取所有 cost 等于最小值的条目
        for (Inbound candidate : inboundList) {
            if (restrictCost && candidate.getCost() > minCost) {
                // 因为 map 已排序，超过最小 cost 后后面都不可能是最小值了
                break;
            }
            if (!allowedInPortIds.contains(candidate.getInPortId())) {
                continue;
            }
            Set<Integer> availableOutIfs = filterAvailableOutIfs(candidate);
            if (availableOutIfs.isEmpty()) {
                continue;
            }
            updateInboundMap(originNode.getNodeId(), inPortId, availableOutIfs, candidate.getCost() + 1);
            hasChanged = true;
        }
        return hasChanged;
    }

    public LinkedHashMap<Integer, Inbound> sortedInboundMapByCost() {
        return inboundMap.entrySet().stream()
            .sorted(Comparator.comparing(entry -> entry.getValue().getCost()))
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1,
                LinkedHashMap::new));
    }

    private Set<Integer> filterAvailableOutIfs(Inbound candidate) {
        Set<Integer> result = new LinkedHashSet<>();
        int inheritedCost = candidate.getCost() + 1;

        for (Integer outIf : candidate.getOutIfSet()) {
            Iterator<Inbound> existingInboundIter = inboundMap.values().stream()
                .filter(inbound -> inbound.getOutIfSet().contains(outIf))
                .iterator();
            if (!existingInboundIter.hasNext()) {
                // 没有占用，直接添加
                result.add(outIf);
                continue;
            }
            while (existingInboundIter.hasNext()) {
                Inbound existingInbound = existingInboundIter.next();
                if (existingInbound.getCost() < inheritedCost) {
                    break;
                }
                if (existingInbound.getCost() == inheritedCost) {
                    result.add(outIf);
                    break;
                }
                // 旧的 cost 更大，删除旧的 outIf，必要时删掉整个 inbound
                existingInbound.getOutIfSet().remove(outIf);
                result.add(outIf);
            }
        }
        inboundMap.entrySet().removeIf(entry -> entry.getValue().getOutIfSet().isEmpty());
        return result;
    }

    private void updateInboundMap(String neighborNodeId, Integer inPortId, Set<Integer> availableOutIfs, int newCost) {
        // 存在相同parentNode跳过；配置了策略拒绝转发的跳过
        if (inboundMap.containsKey(inPortId)) {
            // 合并到已有 inbound
            inboundMap.get(inPortId).getOutIfSet().addAll(availableOutIfs);
        } else {
            // 新建 inbound
            inboundMap.put(inPortId, new Inbound(inPortId, neighborNodeId, newCost, availableOutIfs));
        }
    }
}
