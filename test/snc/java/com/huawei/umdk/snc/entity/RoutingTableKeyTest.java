/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: routing table key test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RoutingTableKey Entity")
class RoutingTableKeyTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        RoutingTableKey key = new RoutingTableKey();
        assertNotNull(key);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        RoutingTableKey key = new RoutingTableKey("superNode1", "dev1", 0);
        assertEquals("superNode1", key.getSuperNodeName());
        assertEquals("dev1", key.getDeviceName());
        assertEquals(0, key.getChipIndex());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        RoutingTableKey key = new RoutingTableKey();
        key.setSuperNodeName("superNode2");
        key.setDeviceName("dev2");
        key.setChipIndex(1);
        assertEquals("superNode2", key.getSuperNodeName());
        assertEquals("dev2", key.getDeviceName());
        assertEquals(1, key.getChipIndex());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        RoutingTableKey a = new RoutingTableKey("superNode1", "dev1", 0);
        RoutingTableKey b = new RoutingTableKey("superNode1", "dev1", 0);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality (different superNodeName)")
    void equalsNotEqualSuperNodeName() {
        RoutingTableKey a = new RoutingTableKey("superNode1", "dev1", 0);
        RoutingTableKey b = new RoutingTableKey("superNode2", "dev1", 0);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality (different deviceName)")
    void equalsNotEqualDeviceName() {
        RoutingTableKey a = new RoutingTableKey("superNode1", "dev1", 0);
        RoutingTableKey b = new RoutingTableKey("superNode1", "dev2", 0);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality (different chipIndex)")
    void equalsNotEqualChipIndex() {
        RoutingTableKey a = new RoutingTableKey("superNode1", "dev1", 0);
        RoutingTableKey b = new RoutingTableKey("superNode1", "dev1", 1);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        RoutingTableKey key = new RoutingTableKey("superNode1", "dev1", 0);
        int hash = key.hashCode();
        assertEquals(hash, key.hashCode());
        assertEquals(hash, new RoutingTableKey("superNode1", "dev1", 0).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new RoutingTableKey().toString());
    }
}
