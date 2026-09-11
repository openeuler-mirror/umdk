/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route selection record test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("RouteSelectionRecord Entity")
class RouteSelectionRecordTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        RouteSelectionRecord record = new RouteSelectionRecord();
        assertNotNull(record);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        RoutePrefix prefix = new RoutePrefix("10.0.0.0", 24);
        List<RouteSelectionRecord.CandidateOutPort> candidates = Arrays.asList(
                new RouteSelectionRecord.CandidateOutPort("port1", "10.0.0.1", true));
        RouteSelectionRecord record = new RouteSelectionRecord("dev1", prefix, candidates,
                "scna", "dcna", "hash1", RouteSelectionRecord.Direction.FORWARD);
        assertEquals("dev1", record.getDeviceName());
        assertSame(prefix, record.getPrefix());
        assertEquals(candidates, record.getCandidateOutPorts());
        assertEquals("scna", record.getScna());
        assertEquals("dcna", record.getDcna());
        assertEquals("hash1", record.getHashInfo());
        assertEquals(RouteSelectionRecord.Direction.FORWARD, record.getDirection());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        RouteSelectionRecord record = new RouteSelectionRecord();
        record.setDeviceName("dev2");
        record.setPrefix(new RoutePrefix("192.168.0.0", 16));
        record.setCandidateOutPorts(Arrays.asList());
        record.setScna("scna2");
        record.setDcna("dcna2");
        record.setHashInfo("hash2");
        record.setDirection(RouteSelectionRecord.Direction.REVERSE);
        assertEquals("dev2", record.getDeviceName());
        assertEquals("192.168.0.0", record.getPrefix().getDstAddress());
        assertEquals(0, record.getCandidateOutPorts().size());
        assertEquals("scna2", record.getScna());
        assertEquals("dcna2", record.getDcna());
        assertEquals("hash2", record.getHashInfo());
        assertEquals(RouteSelectionRecord.Direction.REVERSE, record.getDirection());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        RouteSelectionRecord a = new RouteSelectionRecord("dev1", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD);
        RouteSelectionRecord b = new RouteSelectionRecord("dev1", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        RouteSelectionRecord a = new RouteSelectionRecord("dev1", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD);
        RouteSelectionRecord b = new RouteSelectionRecord("dev2", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        RouteSelectionRecord record = new RouteSelectionRecord("dev1", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD);
        int hash = record.hashCode();
        assertEquals(hash, record.hashCode());
        assertEquals(hash, new RouteSelectionRecord("dev1", new RoutePrefix("10.0.0.0", 24),
                Arrays.asList(), "scna", "dcna", "hash", RouteSelectionRecord.Direction.FORWARD).hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new RouteSelectionRecord().toString());
    }

    @Nested
    @DisplayName("CandidateOutPort inner class")
    class CandidateOutPortTest {

        @Test
        @DisplayName("Default constructor creates non-null object")
        void defaultConstructor() {
            RouteSelectionRecord.CandidateOutPort cp = new RouteSelectionRecord.CandidateOutPort();
            assertNotNull(cp);
        }

        @Test
        @DisplayName("All-args constructor and getters")
        void allArgsConstructor() {
            RouteSelectionRecord.CandidateOutPort cp = new RouteSelectionRecord.CandidateOutPort(
                    "port1", "10.0.0.1", true);
            assertEquals("port1", cp.getPortName());
            assertEquals("10.0.0.1", cp.getNextHop());
            assertTrue(cp.isSelected());
        }

        @Test
        @DisplayName("Setters work correctly")
        void setters() {
            RouteSelectionRecord.CandidateOutPort cp = new RouteSelectionRecord.CandidateOutPort();
            cp.setPortName("port2");
            cp.setNextHop("192.168.1.1");
            cp.setSelected(false);
            assertEquals("port2", cp.getPortName());
            assertEquals("192.168.1.1", cp.getNextHop());
            assertFalse(cp.isSelected());
        }

        @Test
        @DisplayName("equals() - equality")
        void equalsEqual() {
            RouteSelectionRecord.CandidateOutPort a = new RouteSelectionRecord.CandidateOutPort(
                    "port1", "10.0.0.1", true);
            RouteSelectionRecord.CandidateOutPort b = new RouteSelectionRecord.CandidateOutPort(
                    "port1", "10.0.0.1", true);
            assertEquals(a, b);
        }

        @Test
        @DisplayName("equals() - inequality")
        void equalsNotEqual() {
            RouteSelectionRecord.CandidateOutPort a = new RouteSelectionRecord.CandidateOutPort(
                    "port1", "10.0.0.1", true);
            RouteSelectionRecord.CandidateOutPort b = new RouteSelectionRecord.CandidateOutPort(
                    "port2", "10.0.0.1", true);
            assertNotEquals(a, b);
        }

        @Test
        @DisplayName("hashCode() consistency")
        void hashCodeConsistent() {
            RouteSelectionRecord.CandidateOutPort cp = new RouteSelectionRecord.CandidateOutPort(
                    "port1", "10.0.0.1", true);
            int hash = cp.hashCode();
            assertEquals(hash, cp.hashCode());
        }

        @Test
        @DisplayName("toString() returns not null")
        void toStringNotNull() {
            assertNotNull(new RouteSelectionRecord.CandidateOutPort().toString());
        }
    }

    @Nested
    @DisplayName("Direction inner enum")
    class DirectionTest {

        @Test
        @DisplayName("Enum has expected values")
        void enumValues() {
            RouteSelectionRecord.Direction[] values = RouteSelectionRecord.Direction.values();
            assertEquals(2, values.length);
            assertEquals(RouteSelectionRecord.Direction.FORWARD, values[0]);
            assertEquals(RouteSelectionRecord.Direction.REVERSE, values[1]);
        }

        @Test
        @DisplayName("valueOf round-trip")
        void valueOf() {
            assertSame(RouteSelectionRecord.Direction.FORWARD,
                    RouteSelectionRecord.Direction.valueOf("FORWARD"));
            assertSame(RouteSelectionRecord.Direction.REVERSE,
                    RouteSelectionRecord.Direction.valueOf("REVERSE"));
        }
    }
}
