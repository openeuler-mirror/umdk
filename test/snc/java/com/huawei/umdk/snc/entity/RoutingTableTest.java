/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: routing table test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RoutingTable Entity")
class RoutingTableTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        RoutingTable rt = new RoutingTable();
        assertNotNull(rt);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        routes.put(new RoutePrefix("10.0.0.0", 24), new RoutingEntry());
        RoutingTable rt = new RoutingTable("dev1", 0, routes, Arrays.asList(24, 32));
        assertEquals(routes, rt.getRoutes());
        assertEquals(2, rt.getMaskLengths().size());
        assertEquals("dev1", rt.getDeviceName());
        assertEquals(0, rt.getChipIndex());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        RoutingTable rt = new RoutingTable();
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        rt.setRoutes(routes);
        rt.setMaskLengths(Arrays.asList(24));
        rt.setDeviceName("dev1");
        rt.setChipIndex(0);
        assertEquals(routes, rt.getRoutes());
        assertEquals(1, rt.getMaskLengths().size());
        assertEquals("dev1", rt.getDeviceName());
        assertEquals(0, rt.getChipIndex());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        RoutingTable a = new RoutingTable("dev1", 0, routes, Arrays.asList(24));
        RoutingTable b = new RoutingTable("dev1", 0, routes, Arrays.asList(24));
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        RoutingTable a = new RoutingTable("dev1", 0, new HashMap<>(), Arrays.asList(24));
        RoutingTable b = new RoutingTable("dev2", 0, new HashMap<>(), Arrays.asList(24));
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        RoutingTable rt = new RoutingTable("dev1", 0, new HashMap<>(), Arrays.asList(24, 32));
        int hash = rt.hashCode();
        assertEquals(hash, rt.hashCode());
        assertEquals(hash, new RoutingTable("dev1", 0, new HashMap<>(), Arrays.asList(24, 32)).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new RoutingTable().toString());
    }
}
