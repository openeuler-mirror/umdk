/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: device entity test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DeviceEntity")
class DeviceEntityTest {

    private static DeviceEntity newAnonymousDeviceEntity() {
        return new DeviceEntity() {
            @Override
            public DeviceType getDeviceType() {
                return null;
            }

            @Override
            public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
                return null;
            }
        };
    }

    @Test
    @DisplayName("abstract class cannot be instantiated directly")
    void testAbstractClassCannotBeInstantiated() {
        assertTrue(java.lang.reflect.Modifier.isAbstract(DeviceEntity.class.getModifiers()));
    }

    @Test
    @DisplayName("single-arg constructor sets deviceName via anonymous subclass")
    void testTwoArgConstructor() {
        DeviceEntity de = new DeviceEntity("testDevice", null, null) {
            @Override
            public DeviceType getDeviceType() {
                return DeviceType.NPU;
            }

            @Override
            public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
                return null;
            }
        };
        assertEquals("testDevice", de.getDeviceName());
        assertEquals(DeviceType.NPU, de.getDeviceType());
    }

    @Test
    @DisplayName("default constructor creates instance with null fields via anonymous subclass")
    void testDefaultConstructor() {
        DeviceEntity de = newAnonymousDeviceEntity();
        assertNull(de.getDeviceName());
        assertNull(de.getDeviceType());
        assertNull(de.getMgmtInfo());
        assertNull(de.getRack());
    }

    @Test
    @DisplayName("setters and getters work via anonymous subclass")
    void testSettersAndGetters() {
        DeviceEntity de = newAnonymousDeviceEntity();
        de.setDeviceName("dev1");
        de.setMgmtInfo(new MgmtInfo("10.0.0.1", 8080, "user", "pass"));
        de.setRack("rack1");

        assertEquals("dev1", de.getDeviceName());
        assertNotNull(de.getMgmtInfo());
        assertEquals("rack1", de.getRack());
    }
}
