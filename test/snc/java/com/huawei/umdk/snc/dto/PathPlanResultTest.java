/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path plan result test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;

@DisplayName("PathPlanResult DTO")
class PathPlanResultTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        PathPlanResult result = new PathPlanResult();
        assertNotNull(result);
    }

    @Test
    @DisplayName("Partial constructor sets status and errorMessage")
    void partialConstructor() {
        PathPlanResult result = new PathPlanResult(PlanStatus.SUCCESS, "success");
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertEquals("success", result.getErrorMessage());
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        PathInfo path = new PathInfo();
        PathPlanResult result = new PathPlanResult(
            "eid1", "eid2", path, PlanStatus.SUCCESS, null, 10001, 20001, true);
        assertEquals("eid1", result.getSrcEid());
        assertEquals("eid2", result.getDstEid());
        assertSame(path, result.getPath());
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertNull(result.getErrorMessage());
        assertEquals(10001, result.getAckUdpSrcPort());
        assertEquals(20001, result.getDataUdpSrcPort());
        assertTrue(result.isSpray());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        PathPlanResult result = new PathPlanResult();
        result.setSrcEid("src");
        result.setDstEid("dst");
        result.setStatus(PlanStatus.SUCCESS);
        result.setErrorMessage("ok");
        assertEquals("src", result.getSrcEid());
        assertEquals("dst", result.getDstEid());
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertEquals("ok", result.getErrorMessage());
    }

    @Test
    @DisplayName("PlanStatus enum has expected values")
    void planStatusEnumValues() {
        PlanStatus[] values = PlanStatus.values();
        assertTrue(values.length >= 8);
        assertEquals(PlanStatus.SUCCESS, PlanStatus.valueOf("SUCCESS"));
        assertEquals(PlanStatus.TOPO_NOT_FOUND, PlanStatus.valueOf("TOPO_NOT_FOUND"));
    }

    @Test
    @DisplayName("PlanStatus code and message")
    void planStatusCodeAndMessage() {
        assertEquals(0, PlanStatus.SUCCESS.getCode());
        assertEquals("success", PlanStatus.SUCCESS.getMessage());
        assertEquals(1011, PlanStatus.COVERAGE_INCOMPLETE.getCode());
        assertEquals("coverage incomplete", PlanStatus.COVERAGE_INCOMPLETE.getMessage());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        PathPlanResult a = new PathPlanResult("e1", "e2", null, PlanStatus.SUCCESS, null, 0, 0, false);
        PathPlanResult b = new PathPlanResult("e1", "e2", null, PlanStatus.SUCCESS, null, 0, 0, false);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        PathPlanResult result = new PathPlanResult("e1", "e2", null, PlanStatus.SUCCESS, null, 0, 0, false);
        int hash = result.hashCode();
        assertEquals(hash, result.hashCode());
        assertEquals(hash, new PathPlanResult("e1", "e2", null, PlanStatus.SUCCESS, null, 0, 0, false).hashCode());
    }

    @Test
    @DisplayName("toString() returns non-null")
    void toStringNonNull() {
        PathPlanResult result = new PathPlanResult();
        assertNotNull(result.toString());
    }
}
