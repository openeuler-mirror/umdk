/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: logic port entity test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("LogicPortEntity Entity")
class LogicPortEntityTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        LogicPortEntity port = new LogicPortEntity();
        assertNotNull(port);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        List<String> ports = Arrays.asList("p1", "p2");
        LogicPortEntity port = new LogicPortEntity("lp1", "10.0.0.1", "eid123", ports);
        assertEquals("lp1", port.getPortName());
        assertEquals("10.0.0.1", port.getCna());
        assertEquals("eid123", port.getEid());
        assertEquals(ports, port.getPorts());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        LogicPortEntity port = new LogicPortEntity();
        port.setPortName("lp2");
        port.setCna("20.0.0.1");
        port.setEid("eid456");
        port.setPorts(Arrays.asList("p3"));
        assertEquals("lp2", port.getPortName());
        assertEquals("20.0.0.1", port.getCna());
        assertEquals("eid456", port.getEid());
        assertEquals(1, port.getPorts().size());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        List<String> ports = Arrays.asList("p1");
        LogicPortEntity a = new LogicPortEntity("lp1", "cna1", "eid1", ports);
        LogicPortEntity b = new LogicPortEntity("lp1", "cna1", "eid1", ports);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        LogicPortEntity a = new LogicPortEntity("lp1", "cna1", "eid1", Arrays.asList("p1"));
        LogicPortEntity b = new LogicPortEntity("lp2", "cna1", "eid1", Arrays.asList("p1"));
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        LogicPortEntity port = new LogicPortEntity("lp1", "cna1", "eid1", Arrays.asList("p1"));
        int hash = port.hashCode();
        assertEquals(hash, port.hashCode());
        assertEquals(hash, new LogicPortEntity("lp1", "cna1", "eid1", Arrays.asList("p1")).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new LogicPortEntity().toString());
    }
}
