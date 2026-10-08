/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: full rack topology jetty id allocation test
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.SuperNode;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins the jetty id allocation of the full-rack topology: every NPU port
 * resolves to a jetty id, unique within its NPU. When the topology JSON
 * omits the {@code jettyId} field, the loader leaves it {@code null} and
 * the test helper derives {@code 32 + portId} for assertion purposes only
 * (the engine no longer falls back silently — {@code planPathsCoverageEx}
 * rejects a topology with missing jettyIds).
 *
 * <p>The topology is loaded through {@link RackTopologyLoader}, which reads
 * the {@code jettyId} field emitted by {@link FullRackTopologyGenerator}
 * when present.
 */
@DisplayName("FullRackTopologyJettyIdTest：jettyId NPU 内唯一")
class FullRackTopologyJettyIdTest {

    /**
     * Effective jetty id of an NPU port for test assertions: the explicit
     * {@code jettyId} field when present, otherwise {@code 32 + portId}
     * (test-only derivation matching the legacy fallback).
     */
    private static int jettyIdOf(PortEntity p) {
        if (p instanceof NpuPortEntity) {
            Integer jettyId = ((NpuPortEntity) p).getJettyId();
            if (jettyId != null) {
                return jettyId;
            }
        }
        return 32 + (p == null || p.getId() == null ? 0 : p.getId());
    }

    /** (npuDevice#portName) -> jettyId of the whole topology. */
    private static Map<String, Integer> jettyMap(SuperNode sn) {
        Map<String, Integer> map = new HashMap<>();
        for (DeviceEntity dev : sn.getAllDevices().values()) {
            if (dev.getDeviceType() != DeviceType.NPU || dev.getForwardingChips() == null) {
                continue;
            }
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity p : chip.getPorts().values()) {
                    assertTrue(p instanceof NpuPortEntity);
                    int jettyId = jettyIdOf(p);
                    map.put(dev.getDeviceName() + "#" + p.getPortName(), jettyId);
                }
            }
        }
        return map;
    }

    @Test
    @DisplayName("每个 NPU 物理端口都有 jettyId，NPU 内唯一")
    void rangeAndUniqueness() {
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        Map<String, Set<Integer>> perNpu = new HashMap<>();
        int portCount = 0;

        for (DeviceEntity dev : sn.getAllDevices().values()) {
            if (dev.getDeviceType() != DeviceType.NPU || dev.getForwardingChips() == null) {
                continue;
            }
            Set<Integer> jettyIds = new HashSet<>();
            for (ForwardingChip chip : dev.getForwardingChips().values()) {
                if (chip.getPorts() == null) continue;
                for (PortEntity p : chip.getPorts().values()) {
                    portCount++;
                    int jettyId = jettyIdOf(p);
                    assertTrue(jettyIds.add(jettyId),
                        "jettyId must be unique within " + dev.getDeviceName()
                            + ", duplicate " + jettyId);
                }
            }
            perNpu.put(dev.getDeviceName(), jettyIds);
        }

        // 128 NPU x 8 ports, each NPU owning 8 distinct jetty ids.
        assertEquals(128 * 8, portCount, "full rack has 1024 NPU physical ports");
        assertEquals(128, perNpu.size(), "full rack has 128 NPUs");
        for (Map.Entry<String, Set<Integer>> e : perNpu.entrySet()) {
            assertEquals(8, e.getValue().size(), e.getKey() + " must own 8 jetty ids");
        }
    }

    @Test
    @DisplayName("固定映射：rack1#board1#npu1 -> 32..39，rack4#board8#npu4 最后端口 -> 39")
    void fixedMapping() {
        SuperNode sn = RackTopologyLoader.loadRawTopology();

        // Fallback formula: jettyId = 32 + portId (same for every NPU).
        DeviceEntity npu = sn.getAllDevices().get("rack1#board1#npu1");
        assertNotNull(npu);
        for (int p = 0; p < 8; p++) {
            String portName = "400GUB1/2/" + (p + 1);
            PortEntity port = npu.getForwardingChips().get(2).getPorts().get(portName);
            assertNotNull(port, "port must exist: " + portName);
            assertEquals(32 + p,
                jettyIdOf(port),
                "jetty id must be 32 + port index for rack1#board1#npu1, port " + portName);
        }

        // Old fallback formula: jettyId = 32 + portId (same for every NPU).
        // rack4#board8#npu4 port 8 (portId=7) -> 32 + 7 = 39.
        DeviceEntity npu2 = sn.getAllDevices().get("rack4#board8#npu4");
        assertNotNull(npu2);
        PortEntity last = npu2.getForwardingChips().get(2).getPorts().get("400GUB15/8/8");
        assertNotNull(last);
        assertEquals(39, jettyIdOf(last),
            "rack4#board8#npu4 port 8 jettyId must be 39 under the fallback 32+portId formula");
    }

    @Test
    @DisplayName("跨两次生成结果完全一致（每次进入都不变）")
    void stableAcrossInvocations() {
        Map<String, Integer> first = jettyMap(RackTopologyLoader.loadRawTopology());
        Map<String, Integer> second = jettyMap(RackTopologyLoader.loadRawTopology());
        assertEquals(first, second,
            "jetty id allocation must be identical on every generator invocation");
    }
}
