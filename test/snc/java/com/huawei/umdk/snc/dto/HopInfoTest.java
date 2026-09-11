/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: hop info test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HopInfo DTO")
class HopInfoTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        HopInfo hop = new HopInfo();
        assertNotNull(hop);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        HopInfo hop = new HopInfo("rack1#npu1", "400GE 0/0/0", "400GE 0/0/1", true, "NPU");
        assertEquals("rack1#npu1", hop.getDeviceName());
        assertEquals("400GE 0/0/0", hop.getInPort());
        assertEquals("400GE 0/0/1", hop.getOutPort());
        assertTrue(hop.isMultiPath());
        assertEquals("NPU", hop.getDeviceType());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        HopInfo hop = new HopInfo();
        hop.setDeviceName("dev1");
        hop.setInPort("in");
        hop.setOutPort("out");
        hop.setMultiPath(false);
        hop.setDeviceType("SW");
        assertEquals("dev1", hop.getDeviceName());
        assertEquals("in", hop.getInPort());
        assertEquals("out", hop.getOutPort());
        assertFalse(hop.isMultiPath());
        assertEquals("SW", hop.getDeviceType());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        HopInfo a = new HopInfo("dev1", "in", "out", false, null);
        HopInfo b = new HopInfo("dev1", "in", "out", false, null);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        HopInfo a = new HopInfo("dev1", "in", "out", false, null);
        HopInfo b = new HopInfo("dev2", "in", "out", false, null);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        HopInfo hop = new HopInfo("dev1", "in", "out", false, null);
        int hash = hop.hashCode();
        assertEquals(hash, hop.hashCode());
        assertEquals(hash, new HopInfo("dev1", "in", "out", false, null).hashCode());
    }

    @Test
    @DisplayName("toString() returns non-null")
    void toStringNonNull() {
        HopInfo hop = new HopInfo();
        assertNotNull(hop.toString());
    }
}
