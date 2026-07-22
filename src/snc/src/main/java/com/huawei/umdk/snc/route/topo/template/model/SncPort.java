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
import lombok.NonNull;

import java.util.ArrayList;
import java.util.List;

@Data
public class SncPort {
    @NonNull
    private Integer id;

    @NonNull
    private Label label = new Label();

    @NonNull
    private String portName;

    @NonNull
    private List<Address> addrList = new ArrayList<>();

    @NonNull
    private String peerNodeId;

    @NonNull
    private Integer peerPortId;

    @NonNull
    private PortPolicyCache portPolicyCache = new PortPolicyCache();

    public SncPort(int id) {
        this.id = id;
    }

    @Data
    public static class PortPolicyCache {
        private Bitmap enBitmap = new Bitmap(PolicyEnType.MAX.value);

        private Bitmap portFwdCapBitmap;

        @Getter
        public enum PolicyEnType {
            FWD(0),
            MAX(1);

            private final int value;

            PolicyEnType(int value) {
                this.value = value;
            }
        }
    }

    public boolean forwardPolicyEnabled(int outPortId) {
        return portPolicyCache.portFwdCapBitmap == null ||
            !portPolicyCache.enBitmap.get(PortPolicyCache.PolicyEnType.FWD.getValue()) ||
            portPolicyCache.portFwdCapBitmap.get(outPortId);
    }
}
