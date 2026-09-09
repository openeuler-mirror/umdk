/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: covered eid pair test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CoveredEidPair DTO")
class CoveredEidPairTest {

    @Test
    @DisplayName("默认构造器创建非空对象")
    void defaultConstructor() {
        assertNotNull(new CoveredEidPair());
    }

    @Test
    @DisplayName("全参构造器与 getter")
    void allArgsConstructor() {
        CoverageLink link = new CoverageLink();
        CoveredEidPair pair = new CoveredEidPair(
            "eid1", "eid2", "npu1", "port1", "cna1", "cna2",
            "npu2", "port2", List.of(link));
        assertEquals("eid1", pair.getSrcEid());
        assertEquals("eid2", pair.getDstEid());
        assertEquals("npu1", pair.getSrcDevice());
        assertEquals("port1", pair.getSrcPort());
        assertEquals("cna1", pair.getSrcCna());
        assertEquals("cna2", pair.getDstCna());
        assertEquals("npu2", pair.getDestDevice());
        assertEquals("port2", pair.getDestPort());
        assertEquals(1, pair.getCoveredLinks().size());
    }

    @Test
    @DisplayName("setter 工作正常")
    void setters() {
        CoveredEidPair pair = new CoveredEidPair();
        pair.setSrcEid("s");
        pair.setDstEid("d");
        pair.setSrcDevice("npu0");
        pair.setSrcPort("p0");
        pair.setSrcCna("c0");
        pair.setDstCna("c1");
        pair.setDestDevice("npu1");
        pair.setDestPort("p1");
        assertEquals("s", pair.getSrcEid());
        assertEquals("d", pair.getDstEid());
        assertEquals("npu0", pair.getSrcDevice());
        assertEquals("p0", pair.getSrcPort());
        assertEquals("c0", pair.getSrcCna());
        assertEquals("c1", pair.getDstCna());
        assertEquals("npu1", pair.getDestDevice());
        assertEquals("p1", pair.getDestPort());
    }

    @Test
    @DisplayName("equals/hashCode/toString")
    void equalsHashCodeToString() {
        CoveredEidPair a = new CoveredEidPair(
            "eid1", "eid2", "npu1", "port1", "cna1", "cna2",
            "npu2", "port2", null);
        CoveredEidPair b = new CoveredEidPair(
            "eid1", "eid2", "npu1", "port1", "cna1", "cna2",
            "npu2", "port2", null);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        b.setSrcEid("other");
        assertNotEquals(a, b);
        assertNotNull(a.toString());
    }
}
