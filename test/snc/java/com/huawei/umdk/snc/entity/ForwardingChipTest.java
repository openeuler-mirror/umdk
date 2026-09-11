/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: forwarding chip test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ForwardingChip")
class ForwardingChipTest {

    @Test
    @DisplayName("abstract class cannot be instantiated directly")
    void testAbstractClassCannotBeInstantiated() {
        assertTrue(java.lang.reflect.Modifier.isAbstract(ForwardingChip.class.getModifiers()));
    }

    @Test
    @DisplayName("two-arg constructor sets chipIndex and ports via concrete subclass")
    void testTwoArgConstructor() {
        HashMap<String, NpuPortEntity> ports = new HashMap<>();
        NpuForwardingChip fc = new NpuForwardingChip(1, ports);
        assertEquals(1, fc.getChipIndex());
        assertEquals(ports, fc.getPorts());
    }

    @Test
    @DisplayName("default constructor creates instance with null fields")
    void testDefaultConstructor() {
        NpuForwardingChip fc = new NpuForwardingChip();
        assertNull(fc.getChipIndex());
        assertNull(fc.getPorts());
        assertNull(fc.getRoutingTable());
    }

    @Test
    @DisplayName("setters and getters work via concrete subclass")
    void testSettersAndGetters() {
        NpuForwardingChip fc = new NpuForwardingChip();
        fc.setChipIndex(2);
        fc.setPorts(new HashMap<>());
        fc.setRoutingTable(new RoutingTable());

        assertEquals(2, fc.getChipIndex());
        assertNotNull(fc.getPorts());
        assertNotNull(fc.getRoutingTable());
    }
}
