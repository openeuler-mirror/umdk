/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path plan exception test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.exception;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;

@DisplayName("PathPlanException")
class PathPlanExceptionTest {

    @Test
    @DisplayName("Constructor with status and message")
    void constructorWithStatusAndMessage() {
        PathPlanException e = new PathPlanException(PlanStatus.TOPO_INCOMPLETE, "topo incomplete");
        assertEquals("topo incomplete", e.getMessage());
        assertEquals(PlanStatus.TOPO_INCOMPLETE, e.getStatus());
        assertNull(e.getCause());
    }

    @Test
    @DisplayName("Is SNCException")
    void isSNCException() {
        PathPlanException e = new PathPlanException(PlanStatus.SUCCESS, "ok");
        assertInstanceOf(SNCException.class, e);
    }

    @Test
    @DisplayName("getStatus returns the plan status")
    void getStatus() {
        PathPlanException e = new PathPlanException(PlanStatus.TOPO_NOT_FOUND, "topo missing");
        assertEquals(PlanStatus.TOPO_NOT_FOUND, e.getStatus());
    }
}
