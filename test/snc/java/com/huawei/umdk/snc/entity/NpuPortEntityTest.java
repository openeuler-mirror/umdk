/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu port entity test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NpuPortEntity Entity")
class NpuPortEntityTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        NpuPortEntity port = new NpuPortEntity();
        assertNotNull(port);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        NpuPortEntity port = new NpuPortEntity("eid1", "upi1");
        assertEquals("eid1", port.getEid());
        assertEquals("upi1", port.getUpi());
    }

    @Test
    @DisplayName("Setters work correctly (including inherited fields)")
    void setters() {
        NpuPortEntity port = new NpuPortEntity();
        port.setPortName("port1");
        port.setId(1);
        port.setChipIndex(0);
        port.setRemoteDevice("dev1");
        port.setRemotePort("port2");
        port.setCna("10.0.0.1");
        port.setEid("eid1");
        port.setUpi("upi1");
        assertEquals("port1", port.getPortName());
        assertEquals(1, port.getId());
        assertEquals(0, port.getChipIndex());
        assertEquals("dev1", port.getRemoteDevice());
        assertEquals("port2", port.getRemotePort());
        assertEquals("10.0.0.1", port.getCna());
        assertEquals("eid1", port.getEid());
        assertEquals("upi1", port.getUpi());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        NpuPortEntity a = new NpuPortEntity("eid1", "upi1");
        a.setPortName("port1");
        NpuPortEntity b = new NpuPortEntity("eid1", "upi1");
        b.setPortName("port1");
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        NpuPortEntity a = new NpuPortEntity("eid1", "upi1");
        NpuPortEntity b = new NpuPortEntity("eid2", "upi1");
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        NpuPortEntity port = new NpuPortEntity("eid1", "upi1");
        port.setPortName("port1");
        int hash = port.hashCode();
        assertEquals(hash, port.hashCode());
        NpuPortEntity same = new NpuPortEntity("eid1", "upi1");
        same.setPortName("port1");
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new NpuPortEntity().toString());
    }
}
