/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route description
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.route.topo.template.model.PolicyPath;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import lombok.Getter;
import lombok.NonNull;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
public class RouteEntry {
    private final Prefix prefix;

    private final Set<NextHopPort> nhpSet = new HashSet<>();

    private final Set<NextHopPort> shortestNhp = new HashSet<>();

    private final Set<NextHopPort> secondNhp = new HashSet<>();

    private final Set<NextHopPort> otherNhp = new HashSet<>();

    public RouteEntry(@NonNull Prefix prefix) {
        this.prefix = prefix;
    }

    public void updateNhpSetCosts(@NonNull Map<Integer, Integer> outIfCosts) {
        // 更新当前nhpSet中已包含的下一跳cost
        Set<Integer> includedOutIf = new HashSet<>();
        for (NextHopPort nhp : nhpSet) {
            int outIf = nhp.getOutPortId();
            includedOutIf.add(outIf);
            Integer updatedCost = outIfCosts.get(outIf);
            if (updatedCost != null && nhp.getCost() > updatedCost) {
                nhp.setCost(updatedCost);
            }
        }

        // 添加新增的outIf
        outIfCosts.forEach((outIf, cost) -> {
            if (!includedOutIf.contains(outIf)) {
                nhpSet.add(new NextHopPort(cost, outIf, null));
            }
        });
    }

    public void updateNhpSetCosts(@NonNull NextHopPort nhp) {
        for (NextHopPort current : nhpSet) {
            if (current.getOutPortId() != nhp.getOutPortId()) {
                continue;
            }
            if (nhp.getCost() < current.getCost()) {
                current.setCost(nhp.getCost());
                current.setPathType(nhp.getPathType());
                return;
            }
        }
        nhpSet.add(nhp);
    }

    public void applyPathPolicy(PolicyPath policy) {
        if (policy == null || nhpSet.isEmpty()) {
            return;
        }

        int[] topTwoCosts = nhpSet.stream().mapToInt(NextHopPort::getCost).distinct().sorted().limit(2L).toArray();

        // 最短或非最短路径，添加相同cost的所有nhp；如果开启了备份路径，则添加所有剩余nhp
        nhpSet.forEach(nhp -> {
            nhp.setPathType(null);
            if (policy.isShortestEnable() && nhp.getCost() == topTwoCosts[0]) {
                nhp.setPathType(PolicyPath.PolicyEnType.SHORTEST);
                return;
            }
            if (topTwoCosts.length > 1 && nhp.getCost() == topTwoCosts[1] && policy.isSecondShortestEnable()) {
                nhp.setPathType(PolicyPath.PolicyEnType.SECOND_SHORTEST);
                return;
            }
            if (policy.isOtherEnable() && nhp.getCost() > topTwoCosts[0]) {
                nhp.setPathType(PolicyPath.PolicyEnType.OTHER);
            }
        });

        // 无备份场景，去除所有未标记类别的路径
        nhpSet.removeIf(nhp -> nhp.getPathType() == null);
    }

    public int findNhpCostByPathType(@NonNull PolicyPath.PolicyEnType pathTypeEnum) {
        return nhpSet.stream()
            .filter(nhp -> nhp.getPathType() == pathTypeEnum)
            .mapToInt(NextHopPort::getCost)
            .min()
            .orElse(0);
    }
}
