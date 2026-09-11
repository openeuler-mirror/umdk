/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: out port info test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OutPortInfo Entity")
class OutPortInfoTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        OutPortInfo info = new OutPortInfo();
        assertNotNull(info);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        OutPortInfo info = new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0);
        assertEquals("port1", info.getPortName());
        assertEquals("10.0.0.1", info.getNextHop());
        assertEquals(10, info.getPreference());
        assertEquals(100, info.getTag());
        assertEquals("bgp", info.getProtocol());
        assertTrue(info.getConvergedFlag() == 0);
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        OutPortInfo info = new OutPortInfo();
        info.setPortName("port2");
        info.setNextHop("192.168.1.1");
        info.setPreference(20);
        info.setTag(200);
        info.setProtocol("ospf");
        assertEquals("port2", info.getPortName());
        assertEquals("192.168.1.1", info.getNextHop());
        assertEquals(20, info.getPreference());
        assertEquals(200, info.getTag());
        assertEquals("ospf", info.getProtocol());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        OutPortInfo a = new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0);
        OutPortInfo b = new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        OutPortInfo a = new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0);
        OutPortInfo b = new OutPortInfo("port2", "10.0.0.1", 10, 100, "bgp", 0);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        OutPortInfo info = new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0);
        int hash = info.hashCode();
        assertEquals(hash, info.hashCode());
        assertEquals(hash, new OutPortInfo("port1", "10.0.0.1", 10, 100, "bgp", 0).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new OutPortInfo().toString());
    }
}
