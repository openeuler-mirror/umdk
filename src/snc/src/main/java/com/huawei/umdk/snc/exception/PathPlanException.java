/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.exception;

import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;

public class PathPlanException extends SNCException {

    private static final long serialVersionUID = 1L;

    private final PlanStatus status;

    public PathPlanException(PlanStatus status, String message) {
        super(message);
        this.status = status;
    }

    public PathPlanException(PlanStatus status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public PlanStatus getStatus() {
        return status;
    }
}
