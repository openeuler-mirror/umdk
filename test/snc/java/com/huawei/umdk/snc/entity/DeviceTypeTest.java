/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: device type test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DeviceType Enum")
class DeviceTypeTest {

    @Test
    @DisplayName("Enum has expected values")
    void enumValues() {
        DeviceType[] values = DeviceType.values();
        assertEquals(2, values.length);
        assertEquals(DeviceType.NPU, values[0]);
        assertEquals(DeviceType.SW, values[1]);
    }

    @Test
    @DisplayName("NPU value")
    void npuValue() {
        assertEquals("NPU", DeviceType.NPU.name());
    }

    @Test
    @DisplayName("SW value")
    void swValue() {
        assertEquals("SW", DeviceType.SW.name());
    }

    @Test
    @DisplayName("valueOf round-trip")
    void valueOf() {
        assertSame(DeviceType.NPU, DeviceType.valueOf("NPU"));
        assertSame(DeviceType.SW, DeviceType.valueOf("SW"));
    }
}
