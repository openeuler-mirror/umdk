/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.dto;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class PathPlanResult {

    public enum PlanStatus {
        SUCCESS(0, "success"),
        SRC_INFO_ERR(1003, "src info error"),
        DST_INFO_ERR(1004, "dst info error"),
        ACL_CHECK_FAILED(1005, "acl check failed"),
        TOPO_INCOMPLETE(1007, "topo incomplete"),
        TOPO_CONNECTION_ERROR(1008, "topo connection error"),
        TOPO_CONNECTION_NOT_FOUND(1009, "topo connection not found"),
        ROUTE_NOT_REACHABLE(1010, "route not reachable"),
        TOPO_NOT_FOUND(1012, "topo not found"),
        ACL_NOT_FOUND(1013, "acl not found"),
        SRC_AND_DST_MUST_BE_NPU(3002, "src and dst must be npu"),
        UPI_MISMATCH(3003, "upi mismatch");

        @Getter
        private final int code;

        @Getter
        private final String message;

        PlanStatus(int code, String message) {
            this.code = code;
            this.message = message;
        }
    }

    private String srcEid;
    private String dstEid;
    private PathInfo path;
    private PlanStatus status;
    private String errorMessage;
    private int ackUdpSrcPort;
    private int dataUdpSrcPort;
    private boolean spray;

    public PathPlanResult(PlanStatus status, String errorMessage) {
        this.status = status;
        this.errorMessage = errorMessage;
    }
}
