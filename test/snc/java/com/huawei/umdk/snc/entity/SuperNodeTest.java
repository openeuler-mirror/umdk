/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: super node test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SuperNode Entity")
class SuperNodeTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        SuperNode node = new SuperNode();
        assertNotNull(node);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        Map<String, NpuDevice> npuDevices = new HashMap<>();
        npuDevices.put("npu1", new NpuDevice());
        Map<String, SwDevice> swDevices = new HashMap<>();
        swDevices.put("sw1", new SwDevice());
        SuperNode node = new SuperNode("sn1", "1.0", npuDevices, swDevices);
        assertEquals("sn1", node.getName());
        assertEquals("1.0", node.getVersion());
        assertSame(npuDevices, node.getNpuDevices());
        assertSame(swDevices, node.getSwDevices());
        assertEquals(2, node.getAllDevices().size());
        assertSame(npuDevices.get("npu1"), node.getAllDevices().get("npu1"));
        assertSame(swDevices.get("sw1"), node.getAllDevices().get("sw1"));
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        SuperNode node = new SuperNode();
        node.setName("sn2");
        node.setVersion("2.0");
        Map<String, NpuDevice> npuDevices = new HashMap<>();
        npuDevices.put("npu1", new NpuDevice());
        Map<String, SwDevice> swDevices = new HashMap<>();
        swDevices.put("sw1", new SwDevice());
        node.setNpuDevices(npuDevices);
        node.setSwDevices(swDevices);
        assertEquals("sn2", node.getName());
        assertEquals("2.0", node.getVersion());
        assertSame(npuDevices, node.getNpuDevices());
        assertSame(swDevices, node.getSwDevices());
        assertEquals(2, node.getAllDevices().size());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();
        SuperNode a = new SuperNode("sn1", "1.0", npuDevices, swDevices);
        SuperNode b = new SuperNode("sn1", "1.0", npuDevices, swDevices);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        SuperNode a = new SuperNode("sn1", "1.0", new HashMap<>(), new HashMap<>());
        SuperNode b = new SuperNode("sn2", "1.0", new HashMap<>(), new HashMap<>());
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();
        SuperNode node = new SuperNode("sn1", "1.0", npuDevices, swDevices);
        int hash = node.hashCode();
        assertEquals(hash, node.hashCode());
        assertEquals(hash, new SuperNode("sn1", "1.0", npuDevices, swDevices).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        SuperNode node = new SuperNode("sn1", "1.0", new HashMap<>(), new HashMap<>());
        assertNotNull(node.toString());
    }
}
