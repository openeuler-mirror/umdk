/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import com.huawei.umdk.snc.route.model.RouteTable;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class SncNode {
    @NonNull
    private Label label = new Label();

    @NonNull
    private List<Address> addrList = new ArrayList<>();

    @NonNull
    private Map<Integer, SncPort> portMap = new LinkedHashMap<>();

    @NonNull
    private NodePolicyCache policyCache = new NodePolicyCache();

    @Setter(AccessLevel.NONE)
    private RouteTable routeTable = new RouteTable();

    @Data
    public static class NodePolicyCache {
        private Bitmap enBitmap = new Bitmap(PolicyEnType.MAX.value);

        private Map<PolicyPath.PolicyPathKey, PolicyPath> pathMap = new HashMap<>();

        private List<PolicyPrefix> prefixList = new ArrayList<>();

        @Getter
        public enum PolicyEnType {
            PATH(0),
            PREFIX(1),
            MAX(2);

            private final int value;

            PolicyEnType(int value) {
                this.value = value;
            }
        }
    }

    public boolean enabledPolicy(@NonNull NodePolicyCache.PolicyEnType type) {
        return policyCache.enBitmap.get(type.getValue());
    }

    public void setPolicy(@NonNull NodePolicyCache.PolicyEnType type, boolean enabled) {
        policyCache.enBitmap.set(type.getValue(), enabled);
    }

    public boolean rejectForwarding(int inPortId, int outPortId) {
        SncPort inPort = portMap.get(inPortId);
        if (inPort == null || portMap.get(outPortId) == null || inPortId == outPortId) {
            // 端口号不正确；或者出入端口相同
            return true;
        }
        return !inPort.forwardPolicyEnabled(outPortId);
    }

    public Set<Integer> allowedInPortIds(int outPortId) {
        Set<Integer> res = new HashSet<>(portMap.keySet());
        res.removeIf(inPortId -> rejectForwarding(inPortId, outPortId));
        return res;
    }

    public String type() {
        return label.getNames().get("type");
    }
}
