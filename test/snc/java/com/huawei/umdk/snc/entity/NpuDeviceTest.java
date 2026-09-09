/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu device test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.entity;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NpuDevice Entity")
class NpuDeviceTest {

    @Test
    @DisplayName("Default constructor creates non-null object")
    void defaultConstructor() {
        NpuDevice dev = new NpuDevice();
        assertNotNull(dev);
    }

    @Test
    @DisplayName("All-args constructor and getters for NpuDevice fields")
    void allArgsConstructor() {
        NpuDevice dev = createNpu("ubuntu", "10.0.0.1");
        assertEquals("ubuntu", dev.getOsName());
        assertEquals("10.0.0.1", dev.getOsIp());
        assertEquals(0, dev.getBoardId());
        assertEquals(1, dev.getModuleId());
        assertEquals(2, dev.getBoardIndex());
    }

    @Test
    @DisplayName("Setters work correctly")
    void setters() {
        NpuDevice dev = new NpuDevice();
        dev.setDeviceName("npu1");
        dev.setOsName("ubuntu");
        dev.setOsIp("10.0.0.1");
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);
        dev.setRack("rack1");
        dev.setMgmtInfo(new MgmtInfo("10.0.0.1", 22, "admin", "pass"));
        dev.setForwardingChips(new HashMap<>());
        assertEquals("npu1", dev.getDeviceName());
        assertEquals("ubuntu", dev.getOsName());
        assertEquals("10.0.0.1", dev.getOsIp());
        assertEquals(0, dev.getBoardId());
        assertEquals(1, dev.getModuleId());
        assertEquals(2, dev.getBoardIndex());
        assertEquals("rack1", dev.getRack());
    }

    @Test
    @DisplayName("getDeviceType returns NPU")
    void getDeviceType() {
        assertEquals(DeviceType.NPU, new NpuDevice().getDeviceType());
    }

    @Test
    @DisplayName("equals() - equality")
    void equalsEqual() {
        NpuDevice a = createNpu("os", "ip");
        a.setDeviceName("dev1");
        NpuDevice b = createNpu("os", "ip");
        b.setDeviceName("dev1");
        assertEquals(a, b);
    }

    @Test
    @DisplayName("equals() - inequality")
    void equalsNotEqual() {
        NpuDevice a = createNpu("os1", "ip");
        NpuDevice b = createNpu("os2", "ip");
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("hashCode() consistency")
    void hashCodeConsistent() {
        NpuDevice dev = createNpu("os", "ip");
        dev.setDeviceName("dev1");
        int hash = dev.hashCode();
        assertEquals(hash, dev.hashCode());
        NpuDevice same = createNpu("os", "ip");
        same.setDeviceName("dev1");
        assertEquals(hash, same.hashCode());
    }

    @Test
    @DisplayName("toString() returns not null")
    void toStringNotNull() {
        assertNotNull(new NpuDevice().toString());
    }

    private static NpuDevice createNpu(String osName, String osIp) {
        NpuDevice dev = new NpuDevice();
        dev.setOsName(osName);
        dev.setOsIp(osIp);
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);
        return dev;
    }
}
