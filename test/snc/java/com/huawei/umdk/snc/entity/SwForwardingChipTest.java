/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: sw forwarding chip test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SwForwardingChip Entity")
class SwForwardingChipTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        SwForwardingChip chip = new SwForwardingChip();
        assertNotNull(chip);
    }

    @Test
    @DisplayName("Setters work correctly (inherited fields)")
    void setters() {
        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(2);
        chip.setPorts(new HashMap<>());
        chip.setRoutingTable(new RoutingTable());
        assertEquals(2, chip.getChipIndex());
        assertNotNull(chip.getPorts());
        assertNotNull(chip.getRoutingTable());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        SwForwardingChip a = new SwForwardingChip();
        a.setChipIndex(1);
        SwForwardingChip b = new SwForwardingChip();
        b.setChipIndex(1);
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        SwForwardingChip a = new SwForwardingChip();
        a.setChipIndex(1);
        SwForwardingChip b = new SwForwardingChip();
        b.setChipIndex(2);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(1);
        int hash = chip.hashCode();
        assertEquals(hash, chip.hashCode());
        SwForwardingChip same = new SwForwardingChip();
        same.setChipIndex(1);
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new SwForwardingChip().toString());
    }
}
