/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: routing entry test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RoutingEntry Entity")
class RoutingEntryTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        RoutingEntry entry = new RoutingEntry();
        assertNotNull(entry);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 24);
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        outPortInfos.put("port1", new OutPortInfo("port1", "10.0.0.1", 60, 0, "STATIC", 0));
        RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
        assertSame(prefix, entry.getPrefix());
        assertEquals(outPortInfos, entry.getOutPortInfos());
        assertEquals(1, entry.getOutPortInfos().size());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        RoutingEntry entry = new RoutingEntry();
        RoutePrefix prefix = new RoutePrefix("192.168.0.0", 16);
        entry.setPrefix(prefix);
        Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
        outPortInfos.put("eth0", new OutPortInfo("eth0", "192.168.1.1", 60, 0, "STATIC", 0));
        entry.setOutPortInfos(outPortInfos);
        assertSame(prefix, entry.getPrefix());
        assertEquals(outPortInfos, entry.getOutPortInfos());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        Map<String, OutPortInfo> infos = new LinkedHashMap<>();
        infos.put("port1", new OutPortInfo("port1", "10.0.0.1", 60, 0, "STATIC", 0));
        RoutingEntry a = new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infos, true);
        RoutingEntry b = new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infos, true);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        Map<String, OutPortInfo> infosA = new LinkedHashMap<>();
        infosA.put("port1", new OutPortInfo("port1", "10.0.0.1", 60, 0, "STATIC", 0));
        Map<String, OutPortInfo> infosB = new LinkedHashMap<>();
        infosB.put("port2", new OutPortInfo("port2", "10.0.0.2", 60, 0, "STATIC", 0));
        RoutingEntry a = new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infosA, true);
        RoutingEntry b = new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infosB, true);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        Map<String, OutPortInfo> infos = new LinkedHashMap<>();
        infos.put("port1", new OutPortInfo("port1", "10.0.0.1", 60, 0, "STATIC", 0));
        RoutingEntry entry = new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infos, true);
        int hash = entry.hashCode();
        assertEquals(hash, entry.hashCode());
        assertEquals(hash, new RoutingEntry(new RoutePrefix("10.0.0.0", 24), infos, true).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new RoutingEntry().toString());
    }
}
