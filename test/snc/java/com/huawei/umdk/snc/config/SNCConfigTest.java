/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: snc config test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SNCConfig")
class SNCConfigTest {

    @Test
    @DisplayName("Default constructor creates non-null object with default values")
    void defaultConstructor() {
        SNCConfig config = new SNCConfig();
        assertNotNull(config);
        assertEquals(1, config.getHashFunc());
        assertEquals(0, config.getFixedDataUdpPort());
        assertEquals(0, config.getFixedAckUdpPort());
        assertEquals(HashTuple.TWO, config.getHashTuple());
    }

    @Test
    @DisplayName("hashTuple defaults to TWO")
    void hashTupleDefault() {
        assertEquals(HashTuple.TWO, new SNCConfig().getHashTuple());
    }

    @Test
    @DisplayName("hashTuple setter works")
    void hashTupleSetter() {
        SNCConfig config = new SNCConfig();
        config.setHashTuple(HashTuple.FIVE);
        assertEquals(HashTuple.FIVE, config.getHashTuple());
        assertNotEquals(config, new SNCConfig());
    }

    @Test
    @DisplayName("HashTuple.fromCount maps counts 2..5")
    void hashTupleFromCount() {
        assertEquals(HashTuple.TWO, HashTuple.fromCount(2));
        assertEquals(HashTuple.THREE, HashTuple.fromCount(3));
        assertEquals(HashTuple.FOUR, HashTuple.fromCount(4));
        assertEquals(HashTuple.FIVE, HashTuple.fromCount(5));
    }

    @Test
    @DisplayName("HashTuple.fromCount rejects out-of-range counts")
    void hashTupleFromCountInvalid() {
        assertThrows(IllegalArgumentException.class, () -> HashTuple.fromCount(1));
        assertThrows(IllegalArgumentException.class, () -> HashTuple.fromCount(6));
    }

    @Test
    @DisplayName("fixedDataUdpPort defaults to 0")
    void fixedDataUdpPortDefault() {
        assertEquals(0, new SNCConfig().getFixedDataUdpPort());
    }

    @Test
    @DisplayName("fixedAckUdpPort defaults to 0")
    void fixedAckUdpPortDefault() {
        assertEquals(0, new SNCConfig().getFixedAckUdpPort());
    }

    @Test
    @DisplayName("fixedDataUdpPort setter works")
    void fixedDataUdpPortSetter() {
        SNCConfig config = new SNCConfig();
        config.setFixedDataUdpPort(42);
        assertEquals(42, config.getFixedDataUdpPort());
        assertNotEquals(config, new SNCConfig());
    }

    @Test
    @DisplayName("fixedAckUdpPort setter works")
    void fixedAckUdpPortSetter() {
        SNCConfig config = new SNCConfig();
        config.setFixedAckUdpPort(137);
        assertEquals(137, config.getFixedAckUdpPort());
        assertNotEquals(config, new SNCConfig());
    }

    @Test
    @DisplayName("hashFunc defaults to 1")
    void hashFuncDefault() {
        assertEquals(1, new SNCConfig().getHashFunc());
    }

    @Test
    @DisplayName("hashFunc setter works")
    void hashFuncSetter() {
        SNCConfig config = new SNCConfig();
        config.setHashFunc(2);
        assertEquals(2, config.getHashFunc());
        assertNotEquals(config, new SNCConfig());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        SNCConfig a = new SNCConfig();
        SNCConfig b = new SNCConfig();
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        SNCConfig a = new SNCConfig();
        SNCConfig b = new SNCConfig();
        b.setHashFunc(2);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        SNCConfig config = new SNCConfig();
        int hash = config.hashCode();
        assertEquals(hash, config.hashCode());
        assertEquals(hash, new SNCConfig().hashCode());
    }

    @Test
    @DisplayName("toString() contains field info")
    void toStringContainsFields() {
        SNCConfig config = new SNCConfig();
        String str = config.toString();
        assertNotNull(str);
        assertTrue(str.contains("hashFunc=1"));
    }
}
