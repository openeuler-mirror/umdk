/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: sw port entity test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SwPortEntity Entity")
class SwPortEntityTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        SwPortEntity port = new SwPortEntity();
        assertNotNull(port);
    }

    @Test
    @DisplayName("Setters work correctly (including inherited fields, cna can be null)")
    void setters() {
        SwPortEntity port = new SwPortEntity();
        port.setPortName("sw-port1");
        port.setId(10);
        port.setChipIndex(1);
        port.setRemoteDevice("sw-dev");
        port.setRemotePort("sw-port2");
        port.setCna(null);
        assertEquals("sw-port1", port.getPortName());
        assertEquals(10, port.getId());
        assertEquals(1, port.getChipIndex());
        assertEquals("sw-dev", port.getRemoteDevice());
        assertEquals("sw-port2", port.getRemotePort());
        assertNull(port.getCna());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        SwPortEntity a = new SwPortEntity();
        a.setPortName("p1");
        SwPortEntity b = new SwPortEntity();
        b.setPortName("p1");
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        SwPortEntity a = new SwPortEntity();
        a.setPortName("p1");
        SwPortEntity b = new SwPortEntity();
        b.setPortName("p2");
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        SwPortEntity port = new SwPortEntity();
        port.setPortName("p1");
        int hash = port.hashCode();
        assertEquals(hash, port.hashCode());
        SwPortEntity same = new SwPortEntity();
        same.setPortName("p1");
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new SwPortEntity().toString());
    }
}
