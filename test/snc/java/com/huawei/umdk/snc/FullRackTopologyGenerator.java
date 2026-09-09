/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Builds the full 148-device rack topology (128 NPU + 16 L1SW + 4 L2SW)
 *              directly as an in-memory SuperNode, with devices ordered NPU -> L1 -> L2,
 *              and correct CNA-based routing tables.
 * Create: 2026-08-18
 *
 * Topology: 4 racks x (8 boards x 4 NPUs + 4 L1SW) + 4 global L2SW = 148 devices.
 *
 * CNA addressing rule:
 *   bits 31-16 = 0xDFDF (223.223)
 *   bits 15-12 = rack number (0-3, i.e. rack1->0, rack2->1, rack3->2, rack4->3)
 *   bits 11-7  = board index (0-based within the rack's 4-group)
 *   bits 6-5   = NPU index (0-based)
 *   bit  4     = default 1 (always set)
 *   bits 3-0   = port number (1-8)
 *
 * Routing:
 *   NPU: 1016 routes (all NPU ports except own 8), each 1 outPort -- the local port
 *        that connects to the same L1 as the destination NPU port.
 *   L1:  256 routes = 64 NPU-facing (1 outPort) + 192 L2-facing (64 outPorts).
 *        NPU-facing routes are at positions (R-1)*64 .. R*64-1 in the routing table.
 *        L2-facing routes (3 blocks x 64) target the 3 other racks in sorted order.
 *   L2:  2 chips, each 256 routes (4 blocks x 64, one per rack), each 32 outPorts
 *        (the 32 ports on this chip to the L1 that directly connects to the NPU port).
 */
package com.huawei.umdk.snc;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;

public final class FullRackTopologyGenerator {

    private static final String NAME = "A5-superPod-rack";
    private static final String VERSION = "1.0";

    private static final int RACK_COUNT = 4;
    private static final int BOARD_COUNT = 8;
    private static final int NPU_PER_BOARD = 4;
    private static final int PORTS_PER_NPU = 8;
    private static final int L1SW_PER_RACK = 4;
    private static final int L2SW_COUNT = 4;
    private static final int L1SW_PORT_COUNT = 128;
    private static final int L2SW_PORTS_PER_CHIP = 128;

    private FullRackTopologyGenerator() {
    }

    /**
     * Builds the full 148-device rack topology directly in memory as a
     * {@link SuperNode}, with correct CNA-based routing tables but without
     * any ECMP default or cross-chassis routes (those are added later by
     * {@link CoverageRouteAugmentor}).
     *
     * @return a SuperNode containing all 148 devices
     */
    public static SuperNode buildRawTopology() {
        Map<String, NpuDevice> npuDevices = new LinkedHashMap<>();
        Map<String, SwDevice> swDevices = new LinkedHashMap<>();

        // Order: NPU -> L1 -> L2.
        for (int r = 1; r <= RACK_COUNT; r++) {
            for (int b = 1; b <= BOARD_COUNT; b++) {
                for (int n = 1; n <= NPU_PER_BOARD; n++) {
                    NpuDevice npu = buildNpuDevice(r, b, n);
                    npuDevices.put(npu.getDeviceName(), npu);
                }
            }
        }
        for (int r = 1; r <= RACK_COUNT; r++) {
            for (int s = 1; s <= L1SW_PER_RACK; s++) {
                SwDevice sw = buildL1swDevice(r, s);
                swDevices.put(sw.getDeviceName(), sw);
            }
        }
        for (int s = 1; s <= L2SW_COUNT; s++) {
            SwDevice sw = buildL2swDevice(s);
            swDevices.put(sw.getDeviceName(), sw);
        }

        return new SuperNode(NAME, VERSION, npuDevices, swDevices);
    }

    // ========================= Pattern helpers =========================

    /** 32-bit CNA: 0xDFDF0000 + (R-1)*0x1000 + (B-1)*0x80 + (N-1)*0x20 + 0x11 + P. */
    private static int cnaInt(int r, int b, int n, int p) {
        return 0xDFDF0000
            + (r - 1) * 0x1000
            + (b - 1) * 0x80
            + (n - 1) * 0x20
            + 0x11
            + p;
    }

    /** Format CNA as "223.223.X.Y". */
    private static String cnaIp(int r, int b, int n, int p) {
        int cna = cnaInt(r, b, n, p);
        return ((cna >> 24) & 0xFF) + "."
            + ((cna >> 16) & 0xFF) + "."
            + ((cna >> 8) & 0xFF) + "."
            + (cna & 0xFF);
    }

    /** 24-hex-char EID. */
    private static String eidStr(int r, int b, int n, int p) {
        int suffix = (r - 1) * 0x1000 + (b - 1) * 0x80 + (n - 1) * 0x20 + 0x11 + p;
        return String.format("000000000000000000000000dfdf%04x", suffix);
    }

    /** NPU portName: "400GUB {B}/{2*N}/{P+1}". */
    private static String npuPortName(int b, int n, int p) {
        return "400GUB " + b + "/" + (2 * n) + "/" + (p + 1);
    }

    /** L1SW portName: "400GUB 1/0/{P+1}". */
    private static String l1swPortName(int s, int p) {
        return "400GUB 1/0/" + (p + 1);
    }

    /** L2SW portName: "400GUB 1/0/{P+1}:{C}". */
    private static String l2swPortName(int p, int c) {
        return "400GUB 1/0/" + (p + 1) + ":" + c;
    }

    /**
     * Returns the 64 (board, npu, port) tuples for NPU ports connected to L1 switch S,
     * in the order they appear in the routing table.
     *
     * Pattern: board pairs (1,5),(2,6),(3,7),(4,8) x NPU 1-4 x port-pair 0,1 x board1,board2.
     */
    private static int[][] npuPortListForL1(int s) {
        int[][] result = new int[64][3];
        int idx = 0;
        for (int bp = 0; bp < 4; bp++) {
            int b1 = bp + 1;
            int b2 = bp + 5;
            for (int n = 1; n <= NPU_PER_BOARD; n++) {
                for (int pp = 0; pp < 2; pp++) {
                    int p = (s - 1) * 2 + pp;
                    result[idx++] = new int[]{b1, n, p};
                    result[idx++] = new int[]{b2, n, p};
                }
            }
        }
        return result;
    }

    /** L1 port index (0-based) for board B, npu N, port P. */
    private static int l1PortIndex(int b, int n, int p) {
        return (b - 1) * 8 + (n - 1) * 2 + p;
    }

    // ========================= Route helpers ===========================

    private static RoutingEntry singlePortRoute(String dstAddr, String outIface) {
        RoutePrefix prefix = new RoutePrefix(dstAddr, 32);
        Map<String, OutPortInfo> outPorts = new LinkedHashMap<>();
        outPorts.put(outIface,
            new OutPortInfo(outIface, "", 60, 0, "static", 0));
        return new RoutingEntry(prefix, outPorts, true);
    }

    private static RoutingEntry multiPortRoute(String dstAddr, String[] outIfaces) {
        RoutePrefix prefix = new RoutePrefix(dstAddr, 32);
        Map<String, OutPortInfo> outPorts = new LinkedHashMap<>();
        for (String iface : outIfaces) {
            outPorts.put(iface,
                new OutPortInfo(iface, "", 60, 0, "static", 0));
        }
        return new RoutingEntry(prefix, outPorts, true);
    }

    private static <T extends com.huawei.umdk.snc.entity.ForwardingChip> void attachRoutingTable(
            T chip, String deviceName, Map<RoutePrefix, RoutingEntry> routes) {
        RoutingTable rt = new RoutingTable();
        rt.setDeviceName(deviceName);
        rt.setChipIndex(chip.getChipIndex());
        rt.setRoutes(routes);
        List<Integer> masks = routes.keySet().stream()
            .map(RoutePrefix::getMaskLength)
            .sorted(Comparator.reverseOrder())
            .collect(Collectors.toList());
        rt.setMaskLengths(masks);
        chip.setRoutingTable(rt);
    }

    // ========================= NPU device ===============================

    private static NpuDevice buildNpuDevice(int r, int b, int n) {
        String deviceKey = "rack" + r + "#board" + b + "#npu" + n;
        NpuDevice npu = new NpuDevice();
        npu.setDeviceName(deviceKey);
        npu.setRack(String.valueOf(r));
        npu.setOsName("os0");
        npu.setOsIp("172.16." + (r - 1) + ".0");
        npu.setBoardId(b);
        npu.setModuleId(n);
        npu.setBoardIndex(n);

        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(2);
        chip.setPorts(buildNpuPorts(r, b, n));
        attachRoutingTable(chip, deviceKey, buildNpuRouting(r, b, n));
        Map<Integer, NpuForwardingChip> chips = new LinkedHashMap<>();
        chips.put(chip.getChipIndex(), chip);
        npu.setForwardingChips(chips);
        return npu;
    }

    private static Map<String, NpuPortEntity> buildNpuPorts(int r, int b, int n) {
        Map<String, NpuPortEntity> ports = new LinkedHashMap<>();
        for (int p = 0; p < PORTS_PER_NPU; p++) {
            int l1swIdx = p / 2 + 1;
            int peerPortId = (b - 1) * 8 + (n - 1) * 2 + (p % 2);
            NpuPortEntity port = new NpuPortEntity(eidStr(r, b, n, p), "0A0A0A01");
            port.setPortName(npuPortName(b, n, p));
            port.setId(p);
            port.setChipIndex(2);
            port.setRemoteDevice("rack" + r + "#l1sw" + l1swIdx);
            port.setRemotePort("400GUB 1/0/" + (peerPortId + 1));
            port.setCna(cnaIp(r, b, n, p));
            ports.put(port.getPortName(), port);
        }
        return ports;
    }

    private static Map<RoutePrefix, RoutingEntry> buildNpuRouting(int ownR, int ownB, int ownN) {
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    if (rr == ownR && rb == ownB && rn == ownN) {
                        continue;
                    }
                    for (int rp = 0; rp < PORTS_PER_NPU; rp++) {
                        String dst = cnaIp(rr, rb, rn, rp);
                        String outIface = npuPortName(ownB, ownN, (rp / 2) * 2);
                        routes.put(new RoutePrefix(dst, 32), singlePortRoute(dst, outIface));
                    }
                }
            }
        }
        return routes;
    }

    // ========================= L1SW device =============================

    private static SwDevice buildL1swDevice(int r, int s) {
        String deviceKey = "rack" + r + "#l1sw" + s;
        SwDevice sw = new SwDevice();
        sw.setDeviceName(deviceKey);
        sw.setRack(String.valueOf(r));
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(s);

        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(1);
        chip.setPorts(buildL1swPorts(r, s));
        attachRoutingTable(chip, deviceKey, buildL1swRouting(r, s));
        Map<Integer, SwForwardingChip> chips = new LinkedHashMap<>();
        chips.put(chip.getChipIndex(), chip);
        sw.setForwardingChips(chips);
        return sw;
    }

    private static Map<String, SwPortEntity> buildL1swPorts(int r, int s) {
        Map<String, SwPortEntity> ports = new LinkedHashMap<>();
        for (int p = 0; p < L1SW_PORT_COUNT; p++) {
            SwPortEntity port = new SwPortEntity();
            port.setPortName(l1swPortName(s, p));
            port.setId(p);
            port.setChipIndex(1);
            if (p < 64) {
                int boardId = p / 8 + 1;
                int npuId = (p % 8) / 2 + 1;
                int portInNpu = p % 2;
                port.setRemoteDevice("rack" + r + "#board" + boardId + "#npu" + npuId);
                port.setRemotePort("400GUB " + boardId + "/" + (2 * npuId) + "/"
                    + ((s - 1) * 2 + portInNpu + 1));
            } else {
                int l2swPortNum = (p - 64) / 2 + 1;
                int chip = (p % 2 == 0 ? 1 : 2);
                port.setRemoteDevice("l2sw" + s);
                port.setRemotePort("400GUB 1/0/" + l2swPortNum + ":" + chip);
            }
            port.setCna(null);
            ports.put(port.getPortName(), port);
        }
        return ports;
    }

    private static Map<RoutePrefix, RoutingEntry> buildL1swRouting(int r, int s) {
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();

        // --- NPU-facing routes (64) ---
        int[][] npuPorts = npuPortListForL1(s);
        int npuStart = (r - 1) * 64;
        for (int i = 0; i < 64; i++) {
            int b = npuPorts[i][0];
            int n = npuPorts[i][1];
            int p = npuPorts[i][2];
            String dst = cnaIp(r, b, n, p);
            String outIface = l1swPortName(s, l1PortIndex(b, n, p % 2));
            routes.put(new RoutePrefix(dst, 32), singlePortRoute(dst, outIface));
        }

        // --- L2-facing routes (192 = 3 blocks x 64) ---
        String[] l2OutPorts = new String[64];
        for (int p = 0; p < 64; p++) {
            l2OutPorts[p] = l1swPortName(s, 64 + p);
        }

        int[] targetRacks = new int[3];
        int ti = 0;
        for (int tr = 1; tr <= RACK_COUNT; tr++) {
            if (tr != r) {
                targetRacks[ti++] = tr;
            }
        }

        for (int block = 0; block < 3; block++) {
            int targetRack = targetRacks[block];
            int[][] targetPorts = npuPortListForL1(s);
            for (int i = 0; i < 64; i++) {
                int b = targetPorts[i][0];
                int n = targetPorts[i][1];
                int p = targetPorts[i][2];
                String dst = cnaIp(targetRack, b, n, p);
                routes.put(new RoutePrefix(dst, 32), multiPortRoute(dst, l2OutPorts));
            }
        }

        return routes;
    }

    // ========================= L2SW device =============================

    private static SwDevice buildL2swDevice(int s) {
        String deviceKey = "l2sw" + s;
        SwDevice sw = new SwDevice();
        sw.setDeviceName(deviceKey);
        sw.setRack(String.valueOf(s));
        sw.setSwitchLevel(SwitchLevel.L2);
        sw.setIndex(s);

        Map<Integer, SwForwardingChip> chips = new LinkedHashMap<>();
        for (int c = 1; c <= 2; c++) {
            SwForwardingChip chip = new SwForwardingChip();
            chip.setChipIndex(c);
            chip.setPorts(buildL2swPorts(s, c));
            attachRoutingTable(chip, deviceKey, buildL2swRouting(s, c));
            chips.put(chip.getChipIndex(), chip);
        }
        sw.setForwardingChips(chips);
        return sw;
    }

    private static Map<String, SwPortEntity> buildL2swPorts(int s, int c) {
        Map<String, SwPortEntity> ports = new LinkedHashMap<>();
        for (int p = 0; p < L2SW_PORTS_PER_CHIP; p++) {
            int remoteRack = p / 32 + 1;
            int l1swPortNum = 65 + (p % 32) * 2 + (c - 1);
            SwPortEntity port = new SwPortEntity();
            port.setPortName(l2swPortName(p, c));
            port.setId(p);
            port.setChipIndex(c);
            port.setRemoteDevice("rack" + remoteRack + "#l1sw" + s);
            port.setRemotePort("400GUB 1/0/" + l1swPortNum);
            port.setCna(null);
            ports.put(port.getPortName(), port);
        }
        return ports;
    }

    private static Map<RoutePrefix, RoutingEntry> buildL2swRouting(int s, int c) {
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();
        for (int targetRack = 1; targetRack <= RACK_COUNT; targetRack++) {
            int portBase = (targetRack - 1) * 32;
            String[] outPorts = new String[32];
            for (int i = 0; i < 32; i++) {
                outPorts[i] = l2swPortName(portBase + i, c);
            }
            int[][] npuPorts = npuPortListForL1(s);
            for (int i = 0; i < 64; i++) {
                int b = npuPorts[i][0];
                int n = npuPorts[i][1];
                int p = npuPorts[i][2];
                String dst = cnaIp(targetRack, b, n, p);
                routes.put(new RoutePrefix(dst, 32), multiPortRoute(dst, outPorts));
            }
        }
        return routes;
    }
}
