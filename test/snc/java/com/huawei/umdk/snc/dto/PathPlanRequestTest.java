/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path plan request test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PathPlanRequest DTO")
class PathPlanRequestTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        PathPlanRequest req = new PathPlanRequest();
        assertNotNull(req);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        LinkedHashMap<String, String> interDevices = new LinkedHashMap<>();
        interDevices.put("l1sw0", "400GE 1/0/2");
        PathPlanRequest req = new PathPlanRequest(
            "superPod-1", "400GE 0/0/1", "400GE 0/1/1",
            "rack1#npu1", "rack1#npu2", interDevices);
        assertEquals("superPod-1", req.getSuperNodeName());
        assertEquals("400GE 0/0/1", req.getSrcPort());
        assertEquals("400GE 0/1/1", req.getDestPort());
        assertEquals("rack1#npu1", req.getSrcDevice());
        assertEquals("rack1#npu2", req.getDestDevice());
        assertSame(interDevices, req.getInterDevices());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        PathPlanRequest req = new PathPlanRequest();
        req.setSuperNodeName("sn1");
        req.setSrcDevice("dev1");
        req.setDestDevice("dev2");
        req.setSrcPort("port1");
        req.setDestPort("port2");
        LinkedHashMap<String, String> interDevices = new LinkedHashMap<>();
        interDevices.put("sw0", "port0");
        req.setInterDevices(interDevices);
        assertEquals("sn1", req.getSuperNodeName());
        assertEquals("dev1", req.getSrcDevice());
        assertEquals("dev2", req.getDestDevice());
        assertEquals("port1", req.getSrcPort());
        assertEquals("port2", req.getDestPort());
        assertEquals(interDevices, req.getInterDevices());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        PathPlanRequest a = new PathPlanRequest("sn1", "p1", "p2", "d1", "d2", null);
        PathPlanRequest b = new PathPlanRequest("sn1", "p1", "p2", "d1", "d2", null);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        PathPlanRequest a = new PathPlanRequest("sn1", "p1", "p2", "d1", "d2", null);
        PathPlanRequest b = new PathPlanRequest("sn2", "p1", "p2", "d1", "d2", null);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        PathPlanRequest req = new PathPlanRequest("sn1", "p1", "p2", "d1", "d2", null);
        int hash = req.hashCode();
        assertEquals(hash, req.hashCode());
        assertEquals(hash, new PathPlanRequest("sn1", "p1", "p2", "d1", "d2", null).hashCode());
    }

    @Test
    @DisplayName("toString() returns non-null")
    void toStringNonNull() {
        PathPlanRequest req = new PathPlanRequest();
        assertNotNull(req.toString());
    }
}
