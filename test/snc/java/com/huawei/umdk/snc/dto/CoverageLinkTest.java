/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage link test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CoverageLink DTO")
class CoverageLinkTest {

    @Test
    @DisplayName("默认构造器创建非空对象")
    void defaultConstructor() {
        assertNotNull(new CoverageLink());
    }

    @Test
    @DisplayName("全参构造器与 getter")
    void allArgsConstructor() {
        CoveredEidPairRef ref1 =
            new CoveredEidPairRef("eid1", "eid2");
        CoveredEidPairRef ref2 =
            new CoveredEidPairRef("eid3", "eid4");
        CoverageLink link = new CoverageLink(
            "l1sw1", 0, "out1", "l2sw1", "in1", 3, 64,
            List.of(ref1, ref2), 2);
        assertEquals("l1sw1", link.getSwitchDevice());
        assertEquals(0, link.getChipIndex());
        assertEquals("out1", link.getOutPort());
        assertEquals("l2sw1", link.getRemoteSwitch());
        assertEquals("in1", link.getRemotePort());
        assertEquals(3, link.getOutPortIndex());
        assertEquals(64, link.getTotalOutPorts());
        assertEquals(List.of(ref1, ref2), link.getCoveredPairs());
        assertEquals("eid1", link.getCoveredPairs().get(0).getSrcEid());
        assertEquals("eid2", link.getCoveredPairs().get(0).getDstEid());
        assertEquals("eid3", link.getCoveredPairs().get(1).getSrcEid());
        assertEquals("eid4", link.getCoveredPairs().get(1).getDstEid());
        assertEquals(2, link.getCoverCount());
    }

    @Test
    @DisplayName("setter 工作正常")
    void setters() {
        CoverageLink link = new CoverageLink();
        link.setSwitchDevice("l1sw0");
        link.setChipIndex(1);
        link.setOutPort("out0");
        link.setRemoteSwitch("l2sw0");
        link.setRemotePort("in0");
        link.setOutPortIndex(5);
        link.setTotalOutPorts(32);
        link.setCoveredPairs(List.of(new CoveredEidPairRef("s", "d")));
        link.setCoverCount(1);
        assertEquals("l1sw0", link.getSwitchDevice());
        assertEquals(1, link.getChipIndex());
        assertEquals("out0", link.getOutPort());
        assertEquals("l2sw0", link.getRemoteSwitch());
        assertEquals("in0", link.getRemotePort());
        assertEquals(5, link.getOutPortIndex());
        assertEquals(32, link.getTotalOutPorts());
        assertEquals(1, link.getCoveredPairs().size());
        assertEquals("s", link.getCoveredPairs().get(0).getSrcEid());
        assertEquals("d", link.getCoveredPairs().get(0).getDstEid());
        assertEquals(1, link.getCoverCount());
    }

    @Test
    @DisplayName("equals/hashCode/toString")
    void equalsHashCodeToString() {
        CoveredEidPairRef ref =
            new CoveredEidPairRef("eid1", "eid2");
        CoverageLink a = new CoverageLink("l1sw1", 0, "out1", "l2sw1", "in1", 3, 64,
            List.of(ref), 2);
        CoverageLink b = new CoverageLink("l1sw1", 0, "out1", "l2sw1", "in1", 3, 64,
            List.of(ref), 2);
        CoverageLink c = new CoverageLink("l1sw9", 0, "out1", "l2sw1", "in1", 3, 64,
            List.of(ref), 2);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotNull(a.toString());
    }
}
