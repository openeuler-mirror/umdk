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
import com.huawei.umdk.snc.util.HashUtils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins the fixed jetty id allocation of the full-rack topology: the
 * jetty id of NPU port index {@code p} is {@code 32 + p}, identical on every
 * generator invocation, unique per NPU and inside {@code [32, 1023]}.
 * The topology is loaded through {@link RackTopologyLoader}, which auto-
 * generates the JSON via {@link FullRackTopologyGenerator} when absent.
 *
 * <p>The generator JSON does not carry an explicit {@code jettyId} field,
 * so the effective jetty id is computed by the same fallback used by the
 * coverage engine: {@code JETTY_ID_MIN + port.id} when the field is absent
 * or out of range.
 */
@DisplayName("FullRackTopologyGenerator：jettyId 固定分配（32 + 端口序号）")
class FullRackTopologyJettyIdTest {

    /**
     * Effective jetty id of an NPU port: the explicit {@code jettyId} field
     * when present and valid, otherwise the deterministic fallback
     * {@code JETTY_ID_MIN + port.id}.
     */
    private static int jettyIdOf(PortEntity p) {
        Integer jettyId = ((NpuPortEntity) p).getJettyId();
        if (jettyId != null && HashUtils.isValidJettyId(jettyId)) {
            return jettyId;
        }
        return HashUtils.JETTY_ID_MIN + (p == null || p.getId() == null ? 0 : p.getId());
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
                    assertTrue(HashUtils.isValidJettyId(jettyId),
                        "jettyId out of [32,1023]: " + jettyId
                            + " for " + dev.getDeviceName() + ":" + p.getPortName());
                    map.put(dev.getDeviceName() + "#" + p.getPortName(), jettyId);
                }
            }
        }
        return map;
    }

    @Test
    @DisplayName("每个 NPU 物理端口都有 jettyId，且在 [32,1023] 内、NPU 内唯一")
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
                    assertTrue(HashUtils.isValidJettyId(jettyId),
                        "jettyId out of [32,1023]: " + jettyId);
                    assertTrue(jettyIds.add(jettyId),
                        "jettyId must be unique within " + dev.getDeviceName()
                            + ", duplicate " + jettyId);
                }
            }
            perNpu.put(dev.getDeviceName(), jettyIds);
        }

        // 128 NPU x 8 ports, each NPU owning exactly the 8 fixed jetty ids 32..39
        assertEquals(128 * 8, portCount, "full rack has 1024 NPU physical ports");
        assertEquals(128, perNpu.size(), "full rack has 128 NPUs");
        for (Map.Entry<String, Set<Integer>> e : perNpu.entrySet()) {
            assertEquals(8, e.getValue().size(), e.getKey() + " must own 8 jetty ids");
        }
    }

    @Test
    @DisplayName("固定映射：端口序号 p -> 32 + p（含已知端口的精确断言）")
    void fixedMapping() {
        SuperNode sn = RackTopologyLoader.loadRawTopology();
        DeviceEntity npu = sn.getAllDevices().get("rack1#board1#npu1");
        assertNotNull(npu);

        // portName = "400GUB{2b-1}/{2n}/{p+1}" -> 400GUB1/2/1 .. 400GUB1/2/8
        for (int p = 0; p < 8; p++) {
            String portName = "400GUB1/2/" + (p + 1);
            PortEntity port = npu.getForwardingChips().get(2).getPorts().get(portName);
            assertNotNull(port, "port must exist: " + portName);
            assertEquals(HashUtils.JETTY_ID_MIN + p,
                jettyIdOf(port),
                "jetty id must be fixed as 32 + port index, port " + portName);
        }
        assertEquals(32, HashUtils.JETTY_ID_MIN);

        // spot check another NPU in another rack: board8 -> 2*8-1=15, npu4 -> 2*4=8
        DeviceEntity npu2 = sn.getAllDevices().get("rack4#board8#npu4");
        assertNotNull(npu2);
        PortEntity last = npu2.getForwardingChips().get(2).getPorts().get("400GUB15/8/8");
        assertNotNull(last);
        assertEquals(39, jettyIdOf(last));
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
