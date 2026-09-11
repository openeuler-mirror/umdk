/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage paths result test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.List;

import com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CoveragePathsResult DTO")
class CoveragePathsResultTest {

    @Test
    @DisplayName("默认构造器创建非空对象")
    void defaultConstructor() {
        assertNotNull(new CoveragePathsResult());
    }

    @Test
    @DisplayName("全参构造器与 getter")
    void allArgsConstructor() {
        CoverageLink link = new CoverageLink();
        CoveredEidPair pair = new CoveredEidPair();
        java.util.Map<String, Integer> npu = new HashMap<>();
        npu.put("chassis0", 10);
        CoverageStats stats = new CoverageStats(
            2048, 2048, 1.0, 1, 3, 1.5, 0.5,
            100, 200, 0.25, 1, 4, 2.0,
            1, 2, 1.5, 1, 2, 1.5, npu);
        CoveragePathsResult result = new CoveragePathsResult(
            PlanStatus.SUCCESS, null, List.of(pair), List.of(link), stats);
        assertEquals(PlanStatus.SUCCESS, result.getStatus());
        assertNull(result.getErrorMessage());
        assertEquals(1, result.getEidPairs().size());
        assertEquals(1, result.getCoverageLinks().size());
        assertSame(stats, result.getStats());
        assertEquals(2048, result.getStats().getTotalLinks());
        assertEquals(2048, result.getStats().getCoveredCount());
        assertEquals(1.0, result.getStats().getCoverageRate());
        assertEquals(1, result.getStats().getMinRepeatCount());
        assertEquals(3, result.getStats().getMaxRepeatCount());
        assertEquals(1.5, result.getStats().getAvgRepeatCount());
        assertEquals(0.5, result.getStats().getRepeatRate());
        assertEquals(100, result.getStats().getUniqueEidCount());
        assertEquals(200, result.getStats().getTotalEidAppearances());
        assertEquals(0.25, result.getStats().getEidRepeatRate());
        assertEquals(1, result.getStats().getEidMinRepeat());
        assertEquals(4, result.getStats().getEidMaxRepeat());
        assertEquals(2.0, result.getStats().getEidAvgRepeat());
        assertEquals(1, result.getStats().getSrcEidMinRepeat());
        assertEquals(2, result.getStats().getSrcEidMaxRepeat());
        assertEquals(1.5, result.getStats().getSrcEidAvgRepeat());
        assertEquals(1, result.getStats().getDstEidMinRepeat());
        assertEquals(2, result.getStats().getDstEidMaxRepeat());
        assertEquals(1.5, result.getStats().getDstEidAvgRepeat());
        assertEquals(10, result.getStats().getNpuUsageByChassis().get("chassis0"));
    }

    @Test
    @DisplayName("setter 工作正常")
    void setters() {
        CoveragePathsResult result = new CoveragePathsResult();
        result.setStatus(PlanStatus.COVERAGE_INCOMPLETE);
        result.setErrorMessage("incomplete");
        result.setStats(new CoverageStats());
        result.getStats().setTotalLinks(10);
        result.getStats().setCoveredCount(8);
        result.getStats().setCoverageRate(0.8);
        result.getStats().setRepeatRate(0.1);
        result.getStats().setEidRepeatRate(0.2);
        assertEquals(PlanStatus.COVERAGE_INCOMPLETE, result.getStatus());
        assertEquals("incomplete", result.getErrorMessage());
        assertEquals(10, result.getStats().getTotalLinks());
        assertEquals(8, result.getStats().getCoveredCount());
        assertEquals(0.8, result.getStats().getCoverageRate());
        assertEquals(0.1, result.getStats().getRepeatRate());
        assertEquals(0.2, result.getStats().getEidRepeatRate());
    }

    @Test
    @DisplayName("equals/hashCode/toString")
    void equalsHashCodeToString() {
        CoveragePathsResult a = new CoveragePathsResult();
        CoveragePathsResult b = new CoveragePathsResult();
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        b.setStatus(PlanStatus.TOPO_NOT_FOUND);
        assertNotEquals(a, b);
        assertNotNull(a.toString());
    }
}
