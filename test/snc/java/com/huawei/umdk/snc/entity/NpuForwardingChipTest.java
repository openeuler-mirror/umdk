/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu forwarding chip test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NpuForwardingChip Entity")
class NpuForwardingChipTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        NpuForwardingChip chip = new NpuForwardingChip();
        assertNotNull(chip);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        NpuForwardingChip chip = new NpuForwardingChip(0, new HashMap<>());
        assertNotNull(chip.getPorts());
        assertEquals(0, chip.getChipIndex());
    }

    @Test
    @DisplayName("Setters work correctly (including inherited fields)")
    void setters() {
        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(1);
        chip.setPorts(new HashMap<>());
        chip.setRoutingTable(new RoutingTable());
        chip.setLogicPorts(new HashMap<>());
        assertEquals(1, chip.getChipIndex());
        assertNotNull(chip.getPorts());
        assertNotNull(chip.getRoutingTable());
        assertNotNull(chip.getLogicPorts());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        NpuForwardingChip a = new NpuForwardingChip(0, new HashMap<>());
        a.setChipIndex(1);
        NpuForwardingChip b = new NpuForwardingChip(0, new HashMap<>());
        b.setChipIndex(1);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        NpuForwardingChip a = new NpuForwardingChip();
        a.setChipIndex(1);
        NpuForwardingChip b = new NpuForwardingChip();
        b.setChipIndex(2);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        NpuForwardingChip chip = new NpuForwardingChip(0, new HashMap<>());
        chip.setChipIndex(1);
        int hash = chip.hashCode();
        assertEquals(hash, chip.hashCode());
        NpuForwardingChip same = new NpuForwardingChip(0, new HashMap<>());
        same.setChipIndex(1);
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new NpuForwardingChip().toString());
    }
}
