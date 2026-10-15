/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.util.Objects;

@Data
@NoArgsConstructor
public class PolicyPath {
    @NonNull
    private PolicyPathKey key = new PolicyPathKey();

    private boolean shortestEnable;

    private boolean secondShortestEnable;

    private boolean otherEnable;

    private boolean blackHoleEnable;

    public PolicyPath(PolicyPathKey key) {
        this.key = key;
        this.shortestEnable = true;
    }

    @Data
    @NoArgsConstructor
    public static class PolicyPathKey {
        private Label dstNodeLabel = new Label();

        private AddrType dstAddrType;

        private Prefix dstPrefix;

        public PolicyPathKey(@NonNull String dstNodeType, AddrType dstAddrType) {
            this.dstAddrType = dstAddrType;
            this.dstNodeLabel.getNames().put("type", dstNodeType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(dstNodeLabel.getNames(), dstAddrType, dstPrefix);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof PolicyPathKey)) {
                return false;
            }
            PolicyPathKey ppOther = (PolicyPathKey) other;
            return this.dstNodeLabel.getNames().equals(ppOther.dstNodeLabel.getNames())
                && Objects.equals(this.dstAddrType, ppOther.dstAddrType)
                && Objects.equals(this.dstPrefix, ppOther.dstPrefix);
        }
    }

    @Getter
    public enum PolicyEnType {
        SHORTEST(0),
        SECOND_SHORTEST(1),
        OTHER(2),
        BLACK_HOLE(3),
        MAX(4);

        private final int value;

        PolicyEnType(int value) {
            this.value = value;
        }
    }
}
