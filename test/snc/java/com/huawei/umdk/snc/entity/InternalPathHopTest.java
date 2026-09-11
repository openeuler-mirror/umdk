/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: internal path hop test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("InternalPathHop Entity")
class InternalPathHopTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        InternalPathHop hop = new InternalPathHop();
        assertNotNull(hop);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        InternalPathHop hop = new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        assertEquals("dev1", hop.getDeviceName());
        assertEquals(DeviceType.NPU, hop.getDeviceType());
        assertEquals("in1", hop.getInPort());
        assertEquals("out1", hop.getOutPort());
        assertEquals("cna1", hop.getCna());
        assertEquals("eid1", hop.getEid());
        assertEquals("remDev", hop.getRemoteDevice());
        assertEquals("remPort", hop.getRemotePort());
        assertEquals("rack1", hop.getRack());
        assertEquals(0, hop.getHopIndex());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        InternalPathHop hop = new InternalPathHop();
        hop.setDeviceName("dev2");
        hop.setDeviceType(DeviceType.SW);
        hop.setInPort("in2");
        hop.setOutPort("out2");
        hop.setCna("cna2");
        hop.setEid("eid2");
        hop.setRemoteDevice("remDev2");
        hop.setRemotePort("remPort2");
        hop.setRack("rack2");
        hop.setHopIndex(1);
        assertEquals("dev2", hop.getDeviceName());
        assertEquals(DeviceType.SW, hop.getDeviceType());
        assertEquals("in2", hop.getInPort());
        assertEquals("out2", hop.getOutPort());
        assertEquals("cna2", hop.getCna());
        assertEquals("eid2", hop.getEid());
        assertEquals("remDev2", hop.getRemoteDevice());
        assertEquals("remPort2", hop.getRemotePort());
        assertEquals("rack2", hop.getRack());
        assertEquals(1, hop.getHopIndex());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        InternalPathHop a = new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        InternalPathHop b = new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        InternalPathHop a = new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        InternalPathHop b = new InternalPathHop("devX", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        InternalPathHop hop = new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0);
        int hash = hop.hashCode();
        assertEquals(hash, hop.hashCode());
        assertEquals(hash, new InternalPathHop("dev1", DeviceType.NPU, "in1", "out1", "cna1", "eid1",
                "remDev", "remPort", "rack1", 0).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new InternalPathHop().toString());
    }
}
