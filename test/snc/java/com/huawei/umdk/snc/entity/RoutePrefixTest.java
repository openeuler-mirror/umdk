/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route prefix test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RoutePrefix Entity")
class RoutePrefixTest {

    @Test
    @DisplayName("Constructor creates non-null object")
    void defaultConstructor() {
        RoutePrefix prefix = new RoutePrefix(null, null);
        assertNotNull(prefix);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 24);
        assertEquals("10.0.0.0", prefix.getDstAddress());
        assertEquals(24, prefix.getMaskLength());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        RoutePrefix a = new RoutePrefix("10.0.0.0", 24);
        RoutePrefix b = new RoutePrefix("10.0.0.0", 24);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        RoutePrefix a = new RoutePrefix("10.0.0.0", 24);
        RoutePrefix b = new RoutePrefix("10.0.0.0", 32);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 24);
        int hash = prefix.hashCode();
        assertEquals(hash, prefix.hashCode());
        assertEquals(hash, new RoutePrefix("10.0.0.0", 24).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new RoutePrefix(null, null).toString());
    }

}
