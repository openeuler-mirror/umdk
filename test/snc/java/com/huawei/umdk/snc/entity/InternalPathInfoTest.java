/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: internal path info test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("InternalPathInfo Entity")
class InternalPathInfoTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        InternalPathInfo info = new InternalPathInfo();
        assertNotNull(info);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        InternalPathHop hop = new InternalPathHop();
        InternalPathInfo info = new InternalPathInfo(Arrays.asList(hop), "srcEid", "dstEid",
                "srcCna", "dstCna", 1);
        assertEquals(1, info.getHops().size());
        assertSame(hop, info.getHops().get(0));
        assertEquals("srcEid", info.getSrcEid());
        assertEquals("dstEid", info.getDstEid());
        assertEquals("srcCna", info.getSourceCna());
        assertEquals("dstCna", info.getDestCna());
        assertEquals(1, info.getHopCount());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        InternalPathInfo info = new InternalPathInfo();
        info.setHops(Arrays.asList(new InternalPathHop()));
        info.setSrcEid("seid");
        info.setDstEid("deid");
        info.setSourceCna("scna");
        info.setDestCna("dcna");
        info.setHopCount(1);
        assertEquals(1, info.getHops().size());
        assertEquals("seid", info.getSrcEid());
        assertEquals("deid", info.getDstEid());
        assertEquals("scna", info.getSourceCna());
        assertEquals("dcna", info.getDestCna());
        assertEquals(1, info.getHopCount());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        InternalPathInfo a = new InternalPathInfo(Arrays.asList(), "sEid", "dEid", "sCna", "dCna", 0);
        InternalPathInfo b = new InternalPathInfo(Arrays.asList(), "sEid", "dEid", "sCna", "dCna", 0);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        InternalPathInfo a = new InternalPathInfo(Arrays.asList(), "sEid", "dEid", "sCna", "dCna", 0);
        InternalPathInfo b = new InternalPathInfo(Arrays.asList(), "sEidX", "dEid", "sCna", "dCna", 0);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        InternalPathInfo info = new InternalPathInfo(Arrays.asList(), "sEid", "dEid", "sCna", "dCna", 0);
        int hash = info.hashCode();
        assertEquals(hash, info.hashCode());
        assertEquals(hash, new InternalPathInfo(Arrays.asList(), "sEid", "dEid", "sCna", "dCna", 0).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new InternalPathInfo().toString());
    }
}
