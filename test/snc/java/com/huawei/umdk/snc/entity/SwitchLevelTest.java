/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: switch level test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SwitchLevel Enum")
class SwitchLevelTest {

    @Test
    @DisplayName("Enum has expected values")
    void enumValues() {
        SwitchLevel[] values = SwitchLevel.values();
        assertEquals(2, values.length);
        assertEquals(SwitchLevel.L1, values[0]);
        assertEquals(SwitchLevel.L2, values[1]);
    }

    @Test
    @DisplayName("L1 value")
    void l1Value() {
        assertEquals("L1", SwitchLevel.L1.name());
    }

    @Test
    @DisplayName("L2 value")
    void l2Value() {
        assertEquals("L2", SwitchLevel.L2.name());
    }

    @Test
    @DisplayName("valueOf round-trip")
    void valueOf() {
        assertSame(SwitchLevel.L1, SwitchLevel.valueOf("L1"));
        assertSame(SwitchLevel.L2, SwitchLevel.valueOf("L2"));
    }
}
