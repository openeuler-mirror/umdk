/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route lookup engine test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

import com.huawei.umdk.snc.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RouteLookupEngine")
class RouteLookupEngineTest {

    private RouteLookupEngine engine;

    @BeforeEach
    void setUp() {
        engine = new RouteLookupEngine();
    }

    private RoutingEntry createEntry(String nextHop, String portName) {
        Map<String, OutPortInfo> outPortInfos = new HashMap<>();
        outPortInfos.put(portName, new OutPortInfo(portName, nextHop, 60, 0, "STATIC", 0));
        RoutePrefix prefix = null;
        return new RoutingEntry(prefix, outPortInfos, true);
    }

    @Test
    @DisplayName("lookup returns exact /24 match when applicable")
    void lookup_exactMatch() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        RoutingEntry entry24 = createEntry("10.0.0.1", "port1");
        RoutingEntry entry16 = createEntry("10.0.0.254", "port0");
        routes.put(new RoutePrefix("10.0.0.0", 24), entry24);
        routes.put(new RoutePrefix("10.0.0.0", 16), entry16);
        List<Integer> masks = List.of(24, 16);

        RoutingEntry result = engine.lookup("10.0.0.5", routes, masks);
        assertSame(entry24, result);
    }

    @Test
    @DisplayName("lookup falls back to /16 when /24 misses")
    void lookup_fallbackTo16() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        RoutingEntry entry16 = createEntry("10.0.0.254", "port0");
        routes.put(new RoutePrefix("10.0.1.0", 24), createEntry("10.0.1.1", "port1"));
        routes.put(new RoutePrefix("10.0.0.0", 16), entry16);
        List<Integer> masks = List.of(24, 16);

        RoutingEntry result = engine.lookup("10.0.2.5", routes, masks);
        assertSame(entry16, result);
    }

    @Test
    @DisplayName("lookup returns null when no match found")
    void lookup_noMatch() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        routes.put(new RoutePrefix("192.168.0.0", 24), createEntry("gw", "port"));
        List<Integer> masks = List.of(24);

        assertNull(engine.lookup("10.0.0.1", routes, masks));
    }

    @Test
    @DisplayName("lookup returns null when routes map is null")
    void lookup_nullRoutes() {
        assertNull(engine.lookup("10.0.0.1", null, List.of(24)));
    }

    @Test
    @DisplayName("lookup returns null when routes map is empty")
    void lookup_emptyRoutes() {
        assertNull(engine.lookup("10.0.0.1", new HashMap<>(), List.of(24)));
    }

    @Test
    @DisplayName("lookup falls back to default route 0.0.0.0/0 when no specific match and maskLengths does not contain 0")
    void lookup_defaultRoute() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        RoutingEntry defaultEntry = createEntry("10.0.0.1", "port0");
        routes.put(new RoutePrefix("10.0.0.0", 24), createEntry("gw", "port"));
        routes.put(new RoutePrefix("0.0.0.0", 0), defaultEntry);
        List<Integer> masks = List.of(24);

        RoutingEntry result = engine.lookup("192.168.1.1", routes, masks);
        assertSame(defaultEntry, result);
    }

    @Test
    @DisplayName("lookup does not double-match default route when maskLengths already contains 0")
    void lookup_defaultRouteAlreadyInMasks() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        RoutingEntry defaultEntry = createEntry("gw", "port0");
        routes.put(new RoutePrefix("0.0.0.0", 0), defaultEntry);
        List<Integer> masks = List.of(0);

        RoutingEntry result = engine.lookup("10.0.0.1", routes, masks);
        assertSame(defaultEntry, result);
    }

    @Test
    @DisplayName("lookup returns null when maskLengths contains 0 but no route matches")
    void lookup_maskContains0_noRouteMatch() {
        Map<RoutePrefix, RoutingEntry> routes = new HashMap<>();
        routes.put(new RoutePrefix("10.0.0.0", 24), createEntry("gw", "port1"));
        List<Integer> masks = List.of(0);

        RoutingEntry result = engine.lookup("10.0.0.1", routes, masks);
        assertNull(result);
    }
}
