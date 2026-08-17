/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04  Create File
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.LinkEvent;
import com.huawei.umdk.snc.entity.MgmtInfo;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.exception.SNCStateException;

/**
 * LinkEvent 通知功能 UT。
 *
 * <p>构建包含 2 个 NPU、1 个 L1 SW、1 个 L2 SW 的 SuperNode，调用 notifyLinkEvent
 * 刷新链路状态，校验对应端口的 linkStatus 与 updateAt 字段。</p>
 */
class LinkEventServiceTest {

    private SncService snc;

    private static final String SUPER_NODE_NAME = "sn-01";

    // NPU 设备名
    private static final String NPU_0 = "npu-0";
    private static final String NPU_1 = "npu-1";

    // SW 设备名
    private static final String L1_SW = "sw-l1-0";
    private static final String L2_SW = "sw-l2-0";

    // 端口名
    private static final String NPU0_PORT = "npu-0-port-0";
    private static final String NPU1_PORT = "npu-1-port-0";
    private static final String L1_SW_PORT = "sw-l1-0-port-0";
    private static final String L2_SW_PORT = "sw-l2-0-port-0";

    @BeforeEach
    void setUp() {
        snc = new SncService();
        snc.init(new SNCConfig());
        snc.setSuperNode(buildSuperNode());
    }

    @AfterEach
    void tearDown() {
        if (snc != null) {
            snc.uninit();
        }
    }

    @Test
    void notifyLinkEvent_down_updatesNpuPortStatus() {
        LinkEvent event = new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:00:00");

        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event);

        PortEntity port = findPort(snc.getSuperNode(SUPER_NODE_NAME), NPU_0, NPU0_PORT);
        assertNotNull(port);
        assertEquals("down", port.getLinkStatus());
        assertEquals("2026-08-04 10:00:00", port.getUpdateAt());
    }

    @Test
    void notifyLinkEvent_up_restoresNpuPortStatus() {
        // 先 down 再 up
        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME),
            new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:00:00"));
        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME),
            new LinkEvent(NPU_0, NPU0_PORT, "up", "2026-08-04 10:05:00"));

        PortEntity port = findPort(snc.getSuperNode(SUPER_NODE_NAME), NPU_0, NPU0_PORT);
        assertNotNull(port);
        assertEquals("up", port.getLinkStatus());
        assertEquals("2026-08-04 10:05:00", port.getUpdateAt());
    }

    @Test
    void notifyLinkEvent_down_updatesL1SwPortStatus() {
        LinkEvent event = new LinkEvent(L1_SW, L1_SW_PORT, "down", "2026-08-04 10:10:00");

        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event);

        PortEntity port = findPort(snc.getSuperNode(SUPER_NODE_NAME), L1_SW, L1_SW_PORT);
        assertNotNull(port);
        assertEquals("down", port.getLinkStatus());
        assertEquals("2026-08-04 10:10:00", port.getUpdateAt());
    }

    @Test
    void notifyLinkEvent_down_updatesL2SwPortStatus() {
        LinkEvent event = new LinkEvent(L2_SW, L2_SW_PORT, "down", "2026-08-04 10:15:00");

        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event);

        PortEntity port = findPort(snc.getSuperNode(SUPER_NODE_NAME), L2_SW, L2_SW_PORT);
        assertNotNull(port);
        assertEquals("down", port.getLinkStatus());
        assertEquals("2026-08-04 10:15:00", port.getUpdateAt());
    }

    @Test
    void notifyLinkEvent_onlyAffectsTargetPort() {
        snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME),
            new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:20:00"));

        // 目标端口已 down
        assertEquals("down",
            findPort(snc.getSuperNode(SUPER_NODE_NAME), NPU_0, NPU0_PORT).getLinkStatus());
        // 其他端口仍为默认 up，updateAt 为 null
        PortEntity other1 = findPort(snc.getSuperNode(SUPER_NODE_NAME), NPU_1, NPU1_PORT);
        assertEquals("up", other1.getLinkStatus());
        assertNull(other1.getUpdateAt());

        PortEntity other2 = findPort(snc.getSuperNode(SUPER_NODE_NAME), L1_SW, L1_SW_PORT);
        assertEquals("up", other2.getLinkStatus());
        assertNull(other2.getUpdateAt());
    }

    @Test
    void notifyLinkEvent_nullSupernode_throwsIllegalArgument() {
        LinkEvent event = new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:00:00");
        assertThrows(IllegalArgumentException.class, () -> snc.notifyLinkEvent(null, event));
    }

    @Test
    void notifyLinkEvent_nullEvent_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
            () -> snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), null));
    }

    @Test
    void notifyLinkEvent_invalidEventType_throwsIllegalArgument() {
        LinkEvent event = new LinkEvent(NPU_0, NPU0_PORT, "unknown", "2026-08-04 10:00:00");
        assertThrows(IllegalArgumentException.class,
            () -> snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event));
    }

    @Test
    void notifyLinkEvent_deviceNotFound_throwsIllegalState() {
        LinkEvent event = new LinkEvent("not-exist-device", NPU0_PORT, "down", "2026-08-04 10:00:00");
        assertThrows(IllegalStateException.class,
            () -> snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event));
    }

    @Test
    void notifyLinkEvent_portNotFound_throwsIllegalState() {
        LinkEvent event = new LinkEvent(NPU_0, "not-exist-port", "down", "2026-08-04 10:00:00");
        assertThrows(IllegalStateException.class,
            () -> snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event));
    }

    @Test
    void notifyLinkEvent_superNodeNotLoaded_throwsArgumentState() {
        snc.removeSuperNode(SUPER_NODE_NAME);
        LinkEvent event = new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:00:00");
        assertThrows(IllegalArgumentException.class,
            () -> snc.notifyLinkEvent(snc.getSuperNode(SUPER_NODE_NAME), event));
    }

    @Test
    void notifyLinkEvent_inUninitState_throwsSncState() {
        snc.uninit();
        LinkEvent event = new LinkEvent(NPU_0, NPU0_PORT, "down", "2026-08-04 10:00:00");
        SuperNode sn = new SuperNode(SUPER_NODE_NAME, "v1", null, null);
        assertThrows(SNCStateException.class, () -> snc.notifyLinkEvent(sn, event));
    }

    // ===== 测试数据构建 =====

    private SuperNode buildSuperNode() {
        Map<String, NpuDevice> npuDevices = new LinkedHashMap<>();
        npuDevices.put(NPU_0, buildNpuDevice(NPU_0, NPU0_PORT, L1_SW, L1_SW_PORT));
        npuDevices.put(NPU_1, buildNpuDevice(NPU_1, NPU1_PORT, L1_SW, L1_SW_PORT));

        Map<String, SwDevice> swDevices = new LinkedHashMap<>();
        swDevices.put(L1_SW, buildSwDevice(L1_SW, L1_SW_PORT, SwitchLevel.L1, 0));
        swDevices.put(L2_SW, buildSwDevice(L2_SW, L2_SW_PORT, SwitchLevel.L2, 0));

        return new SuperNode(SUPER_NODE_NAME, "v1", npuDevices, swDevices);
    }

    private NpuDevice buildNpuDevice(String name, String portName,
                                     String remoteDevice, String remotePort) {
        NpuPortEntity port = new NpuPortEntity();
        port.setPortName(portName);
        port.setRemoteDevice(remoteDevice);
        port.setRemotePort(remotePort);
        port.setLinkStatus("up");

        Map<String, NpuPortEntity> ports = new HashMap<>();
        ports.put(portName, port);

        Map<Integer, NpuForwardingChip> chips = new HashMap<>();
        chips.put(0, new NpuForwardingChip(0, ports));

        MgmtInfo mgmtInfo = new MgmtInfo("127.0.0.1", 22, "admin", "pwd");
        return new NpuDevice(name, mgmtInfo, "rack-0", chips, "osName", "127.0.0.1", 0, 0, 0);
    }

    private SwDevice buildSwDevice(String name, String portName, SwitchLevel level, Integer index) {
        SwPortEntity port = new SwPortEntity();
        port.setPortName(portName);
        port.setLinkStatus("up");

        Map<String, SwPortEntity> ports = new HashMap<>();
        ports.put(portName, port);

        Map<Integer, SwForwardingChip> chips = new HashMap<>();
        chips.put(0, new SwForwardingChip(0, ports));

        MgmtInfo mgmtInfo = new MgmtInfo("127.0.0.1", 22, "admin", "pwd");
        return new SwDevice(name, mgmtInfo, "rack-0", chips, level, index);
    }

    private PortEntity findPort(SuperNode superNode, String deviceName, String portName) {
        DeviceEntity device = superNode.getAllDevices().get(deviceName);
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip == null || chip.getPorts() == null) {
                continue;
            }
            PortEntity port = chip.getPorts().get(portName);
            if (port != null) {
                return port;
            }
        }
        return null;
    }
}
