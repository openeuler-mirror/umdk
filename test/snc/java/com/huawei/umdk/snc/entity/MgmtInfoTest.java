/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: mgmt info test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("MgmtInfo Entity")
class MgmtInfoTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        MgmtInfo info = new MgmtInfo();
        assertNotNull(info);
    }

    @Test
    @DisplayName("All-args constructor and getters")
    void allArgsConstructor() {
        MgmtInfo info = new MgmtInfo("10.0.0.1", 22, "admin", "secret123");
        assertEquals("10.0.0.1", info.getIp());
        assertEquals(22, info.getPort());
        assertEquals("admin", info.getUsername());
        assertEquals("secret123", info.getPassword());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        MgmtInfo info = new MgmtInfo();
        info.setIp("192.168.1.1");
        info.setPort(8080);
        info.setUsername("user");
        info.setPassword("pass");
        assertEquals("192.168.1.1", info.getIp());
        assertEquals(8080, info.getPort());
        assertEquals("user", info.getUsername());
        assertEquals("pass", info.getPassword());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        MgmtInfo a = new MgmtInfo("10.0.0.1", 22, "admin", "secret");
        MgmtInfo b = new MgmtInfo("10.0.0.1", 22, "admin", "secret");
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        MgmtInfo a = new MgmtInfo("10.0.0.1", 22, "admin", "secret");
        MgmtInfo b = new MgmtInfo("10.0.0.2", 22, "admin", "secret");
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        MgmtInfo info = new MgmtInfo("10.0.0.1", 22, "admin", "secret");
        int hash = info.hashCode();
        assertEquals(hash, info.hashCode());
        assertEquals(hash, new MgmtInfo("10.0.0.1", 22, "admin", "secret").hashCode());
    }

    @Test
    @DisplayName("toString() does not leak password")
    void toStringDoesNotLeakPassword() {
        MgmtInfo info = new MgmtInfo("10.0.0.1", 22, "admin", "secret123");
        String str = info.toString();
        assertNotNull(str);
        assertTrue(str.contains("port=22"));
        assertFalse(str.contains("10.0.0.1"));
        assertFalse(str.contains("admin"));
        assertFalse(str.contains("secret123"));
        assertFalse(str.contains("password"));
    }
}
