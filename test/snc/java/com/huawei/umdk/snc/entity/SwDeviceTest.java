/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: sw device test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SwDevice Entity")
class SwDeviceTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        SwDevice dev = new SwDevice();
        assertNotNull(dev);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        SwDevice dev = createSw(SwitchLevel.L1, 3);
        assertEquals(SwitchLevel.L1, dev.getSwitchLevel());
        assertEquals(3, dev.getIndex());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        SwDevice dev = new SwDevice();
        dev.setDeviceName("sw1");
        dev.setSwitchLevel(SwitchLevel.L2);
        dev.setIndex(5);
        dev.setRack("rack2");
        assertEquals("sw1", dev.getDeviceName());
        assertEquals(SwitchLevel.L2, dev.getSwitchLevel());
        assertEquals(5, dev.getIndex());
        assertEquals("rack2", dev.getRack());
    }

    @Test
    @DisplayName("getDeviceType returns SW")
    void getDeviceType() {
        assertEquals(DeviceType.SW, new SwDevice().getDeviceType());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        SwDevice a = createSw(SwitchLevel.L1, 3);
        a.setDeviceName("sw1");
        SwDevice b = createSw(SwitchLevel.L1, 3);
        b.setDeviceName("sw1");
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        SwDevice a = createSw(SwitchLevel.L1, 3);
        SwDevice b = createSw(SwitchLevel.L2, 3);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        SwDevice dev = createSw(SwitchLevel.L1, 3);
        dev.setDeviceName("sw1");
        int hash = dev.hashCode();
        assertEquals(hash, dev.hashCode());
        SwDevice same = createSw(SwitchLevel.L1, 3);
        same.setDeviceName("sw1");
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new SwDevice().toString());
    }

    private static SwDevice createSw(SwitchLevel level, Integer index) {
        SwDevice dev = new SwDevice();
        dev.setSwitchLevel(level);
        dev.setIndex(index);
        return dev;
    }
}
