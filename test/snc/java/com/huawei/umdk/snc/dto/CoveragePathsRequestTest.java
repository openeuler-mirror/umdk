/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage paths request test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CoveragePathsRequest DTO")
class CoveragePathsRequestTest {

    @Test
    @DisplayName("默认构造器创建非空对象")
    void defaultConstructor() {
        assertNotNull(new CoveragePathsRequest());
    }

    @Test
    @DisplayName("全参构造器与 getter")
    void allArgsConstructor() {
        CoveragePathsRequest req = new CoveragePathsRequest(
            "sn1", CoverageRequirement.REDUNDANT);
        assertEquals("sn1", req.getSuperNodeName());
        assertEquals(CoverageRequirement.REDUNDANT, req.getCoverageRequirement());
    }

    @Test
    @DisplayName("setter 工作正常")
    void setters() {
        CoveragePathsRequest req = new CoveragePathsRequest();
        req.setSuperNodeName("sn2");
        req.setCoverageRequirement(CoverageRequirement.MIN_COVERAGE);
        assertEquals("sn2", req.getSuperNodeName());
        assertEquals(CoverageRequirement.MIN_COVERAGE, req.getCoverageRequirement());
    }

    @Test
    @DisplayName("equals/hashCode/toString")
    void equalsHashCodeToString() {
        CoveragePathsRequest a = new CoveragePathsRequest(
            "sn1", CoverageRequirement.REDUNDANT);
        CoveragePathsRequest b = new CoveragePathsRequest(
            "sn1", CoverageRequirement.REDUNDANT);
        CoveragePathsRequest c = new CoveragePathsRequest(
            "sn2", CoverageRequirement.REDUNDANT);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotNull(a.toString());
    }
}
