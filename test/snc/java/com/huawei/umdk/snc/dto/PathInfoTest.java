/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path info test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PathInfo DTO")
class PathInfoTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        PathInfo info = new PathInfo();
        assertNotNull(info);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        List<HopInfo> hops = List.of(new HopInfo());
        PathInfo info = new PathInfo(hops);
        assertSame(hops, info.getHops());
        assertEquals(1, info.getHops().size());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        PathInfo info = new PathInfo();
        List<HopInfo> hops = List.of(new HopInfo("dev1", null, null, false, null));
        info.setHops(hops);
        assertSame(hops, info.getHops());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        PathInfo a = new PathInfo(null);
        PathInfo b = new PathInfo(null);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        PathInfo info = new PathInfo(null);
        int hash = info.hashCode();
        assertEquals(hash, info.hashCode());
        assertEquals(hash, new PathInfo(null).hashCode());
    }

    @Test
    @DisplayName("toString() returns non-null")
    void toStringNonNull() {
        PathInfo info = new PathInfo();
        assertNotNull(info.toString());
    }
}
