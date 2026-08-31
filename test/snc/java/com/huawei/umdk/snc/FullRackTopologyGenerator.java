/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Generates the full 148-device rack topology JSON as a SINGLE
 *              combined file (128 NPU + 16 L1SW + 4 L2SW) at
 *              test/snc/resources/topo_data_full_rack.json, with devices
 *              ordered NPU -> L1 -> L2, and correct CNA-based routing tables.
 * Create: 2026-08-18
 *
 * Topology: 4 racks × (8 boards × 4 NPUs + 4 L1SW) + 4 global L2SW = 148 devices.
 *
 * CNA addressing rule:
 *   bits 31-16 = 0xDFDF (223.223)
 *   bits 15-12 = rack number (0-3, i.e. rack1→0, rack2→1, rack3→2, rack4→3)
 *   bits 11-7  = board index (0-based within the rack's 4-group)
 *   bits 6-5   = NPU index (0-based)
 *   bit  4     = default 1 (always set)
 *   bits 3-0   = port number (1-8)
 *
 * Routing:
 *   NPU: 1016 routes (all NPU ports except own 8), each 1 outPort — the local port
 *        that connects to the same L1 as the destination NPU port.
 *   L1:  256 routes = 64 NPU-facing (1 outPort) + 192 L2-facing (64 outPorts).
 *        NPU-facing routes are at positions (R-1)*64 .. R*64-1 in the routing table.
 *        L2-facing routes (3 blocks × 64) target the 3 other racks in sorted order.
 *   L2:  2 chips, each 256 routes (4 blocks × 64, one per rack), each 32 outPorts
 *        (the 32 ports on this chip to the L1 that directly connects to the NPU port).
 *
 * Run from test/snc directory:
 *   Compile: javac -d java java/com/huawei/umdk/snc/FullRackTopologyGenerator.java
 *   Run:     java -cp java com.huawei.umdk.snc.FullRackTopologyGenerator
 * Output:   resources/topo_data_full_rack.json (relative to test/snc)
 */
package com.huawei.umdk.snc;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class FullRackTopologyGenerator {

    private static final String COPYRIGHT =
        "SPDX-License-Identifier: MIT | Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved. "
            + "| Description: snc superNode data test fixture - individual device | Create: 2026-07-09";
    private static final String NAME = "A5-superPod-rack";
    private static final String VERSION = "1.0";
    // Run from test/snc directory: java -cp java com.huawei.umdk.snc.FullRackTopologyGenerator
    private static final Path OUTPUT_FILE =
        Paths.get("resources", "topo_data_full_rack.json");

    private static final int RACK_COUNT = 4;
    private static final int BOARD_COUNT = 8;
    private static final int NPU_PER_BOARD = 4;
    private static final int PORTS_PER_NPU = 8;
    private static final int L1SW_PER_RACK = 4;
    private static final int L2SW_COUNT = 4;
    private static final int L1SW_PORT_COUNT = 128;
    private static final int L2SW_PORTS_PER_CHIP = 128;

    public static void main(String[] args) throws IOException {
        Files.createDirectories(OUTPUT_FILE.getParent());

        Jb jb = new Jb();
        jb.openObj();
        jb.inc();
        jb.str("_copyright", COPYRIGHT);
        jb.str("name", NAME);
        jb.str("version", VERSION);
        jb.raw("\"devices\": {");
        jb.inc();

        int total = RACK_COUNT * BOARD_COUNT * NPU_PER_BOARD
            + RACK_COUNT * L1SW_PER_RACK
            + L2SW_COUNT; // 148
        int idx = 0;

        // Order: NPU -> L1 -> L2.
        for (int r = 1; r <= RACK_COUNT; r++) {
            for (int b = 1; b <= BOARD_COUNT; b++) {
                for (int n = 1; n <= NPU_PER_BOARD; n++) {
                    appendNpuDevice(jb, r, b, n, ++idx == total);
                }
            }
        }
        for (int r = 1; r <= RACK_COUNT; r++) {
            for (int s = 1; s <= L1SW_PER_RACK; s++) {
                appendL1swDevice(jb, r, s, ++idx == total);
            }
        }
        for (int s = 1; s <= L2SW_COUNT; s++) {
            appendL2swDevice(jb, s, ++idx == total);
        }

        jb.dec();
        jb.closeObj(); // closes devices
        jb.dec();
        jb.closeObj(); // closes root

        writeFile(OUTPUT_FILE, jb.toString());
        System.out.println("Generated " + total + " devices in " + OUTPUT_FILE);
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
     * Pattern: board pairs (1,5),(2,6),(3,7),(4,8) × NPU 1-4 × port-pair 0,1 × board1,board2.
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

    // ========================= JSON builder ============================

    private static final class Jb {
        private final StringBuilder sb = new StringBuilder(256 * 1024);
        private int level = 0;

        private Jb line(String s) {
            for (int i = 0; i < level; i++) {
                sb.append("    ");
            }
            sb.append(s).append("\n");
            return this;
        }

        Jb raw(String s) { return line(s); }
        Jb openObj() { return line("{"); }
        Jb closeObj() { return line("}"); }
        Jb closeObjComma() { return line("},"); }
        Jb openArr() { return line("["); }
        Jb closeArr() { return line("]"); }
        Jb closeArrComma() { return line("],"); }
        Jb inc() { level++; return this; }
        Jb dec() { level--; return this; }
        Jb str(String key, String v) { return line("\"" + key + "\": \"" + v + "\","); }
        Jb num(String key, long v) { return line("\"" + key + "\": " + v + ","); }
        Jb strLast(String key, String v) { return line("\"" + key + "\": \"" + v + "\""); }
        Jb numLast(String key, long v) { return line("\"" + key + "\": " + v); }
        Jb emptyArr(String key) { return line("\"" + key + "\": [],"); }

        @Override
        public String toString() { return sb.toString(); }
    }

    // ========================= Route entry ==============================

    /**
     * Write one routing table entry with one or more outPortInfos.
     */
    private static void writeRouteEntry(Jb jb, String dstAddr, String[] outInterfaces, boolean last) {
        jb.openObj();
        jb.inc();
        // prefix
        jb.raw("\"prefix\": {");
        jb.inc();
        jb.str("dstAddress", dstAddr);
        jb.numLast("maskLength", 32);
        jb.dec();
        jb.closeObjComma();
        // outPortInfos
        jb.raw("\"outPortInfos\": [");
        jb.inc();
        for (int i = 0; i < outInterfaces.length; i++) {
            jb.openObj();
            jb.inc();
            jb.str("outInterface", outInterfaces[i]);
            jb.str("nextHop", "");
            jb.num("preference", 60);
            jb.num("tag", 0);
            jb.strLast("protocol", "static");
            jb.dec();
            if (i < outInterfaces.length - 1) {
                jb.closeObjComma();
            } else {
                jb.closeObj();
            }
        }
        jb.dec();
        jb.closeArr();
        jb.dec();
        if (last) {
            jb.closeObj();
        } else {
            jb.closeObjComma();
        }
    }

    // ========================= File writer ==============================

    private static void writeFile(Path path, String content) throws IOException {
        try (Writer w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            w.write(content);
        }
    }

    // ========================= NPU device ===============================

    /** Append one NPU device entry to the shared devices object. */
    private static void appendNpuDevice(Jb jb, int r, int b, int n, boolean last) {
        String deviceKey = "rack" + r + "#board" + b + "#npu" + n;
        jb.raw("\"" + deviceKey + "\": {");
        jb.inc();
        jb.str("deviceName", deviceKey);
        jb.str("deviceType", "NPU");
        jb.str("osName", "os0");
        jb.str("osIp", "172.16." + (r - 1) + ".0");
        jb.num("rack", r);
        jb.num("boardId", b);
        jb.num("moduleId", n);
        jb.num("boardIndex", n);
        jb.raw("\"forwardingChip\": [");
        jb.inc();
        jb.openObj();
        jb.inc();
        jb.num("chipIndex", 2);
        writeNpuPorts(jb, r, b, n);
        jb.emptyArr("logicPorts");
        writeNpuRouting(jb, r, b, n);
        jb.closeObj();
        jb.dec();
        jb.closeArr();
        jb.dec();
        jb.closeObj(); // closes device object
        jb.dec(); // back to devices level
        if (!last) {
            jb.raw(",");
        }
    }

    private static void writeNpuPorts(Jb jb, int r, int b, int n) {
        jb.raw("\"ports\": [");
        jb.inc();
        for (int p = 0; p < PORTS_PER_NPU; p++) {
            int l1swIdx = p / 2 + 1;
            int peerPortId = (b - 1) * 8 + (n - 1) * 2 + (p % 2);
            jb.openObj();
            jb.inc();
            jb.str("portName", npuPortName(b, n, p));
            jb.num("id", p);
            jb.str("remoteDevice", "rack" + r + "#l1sw" + l1swIdx);
            jb.str("remotePort", "400GUB 1/0/" + (peerPortId + 1));
            jb.str("cna", cnaIp(r, b, n, p));
            jb.str("eid", eidStr(r, b, n, p));
            jb.strLast("upi", "0A0A0A01");
            jb.dec();
            if (p < PORTS_PER_NPU - 1) {
                jb.closeObjComma();
            } else {
                jb.closeObj();
            }
        }
        jb.dec();
        jb.closeArrComma();
    }

    private static void writeNpuRouting(Jb jb, int ownR, int ownB, int ownN) {
        // 1016 entries: all NPU ports except own 8, each with 1 outPort.
        jb.raw("\"routingTables\": [");
        jb.inc();
        int total = RACK_COUNT * BOARD_COUNT * NPU_PER_BOARD * PORTS_PER_NPU - PORTS_PER_NPU;
        int idx = 0;
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    if (rr == ownR && rb == ownB && rn == ownN) {
                        continue;
                    }
                    for (int rp = 0; rp < PORTS_PER_NPU; rp++) {
                        boolean last = (idx == total - 1);
                        // outInterface = local port that connects to the same L1 as destination port rp
                        String outIface = npuPortName(ownB, ownN, (rp / 2) * 2);
                        writeRouteEntry(jb, cnaIp(rr, rb, rn, rp), new String[]{outIface}, last);
                        idx++;
                    }
                }
            }
        }
        jb.dec();
        jb.closeArr();
    }

    // ========================= L1SW device =============================

    /** Append one L1 switch device entry to the shared devices object. */
    private static void appendL1swDevice(Jb jb, int r, int s, boolean last) {
        String deviceKey = "rack" + r + "#l1sw" + s;
        jb.raw("\"" + deviceKey + "\": {");
        jb.inc();
        jb.str("deviceName", deviceKey);
        jb.str("deviceType", "SW");
        jb.str("level", "L1");
        jb.num("rack", r);
        jb.num("index", s);
        jb.raw("\"forwardingChip\": [");
        jb.inc();
        jb.openObj();
        jb.inc();
        jb.num("chipIndex", 1);
        writeL1swPorts(jb, r, s);
        jb.emptyArr("logicPorts");
        writeL1swRouting(jb, r, s);
        jb.closeObj();
        jb.dec();
        jb.closeArr();
        jb.dec();
        jb.closeObj(); // closes device object
        jb.dec(); // back to devices level
        if (!last) {
            jb.raw(",");
        }
    }

    private static void writeL1swPorts(Jb jb, int r, int s) {
        jb.raw("\"ports\": [");
        jb.inc();
        for (int p = 0; p < L1SW_PORT_COUNT; p++) {
            jb.openObj();
            jb.inc();
            jb.str("portName", l1swPortName(s, p));
            jb.num("id", p);
            if (p < 64) {
                int boardId = p / 8 + 1;
                int npuId = (p % 8) / 2 + 1;
                int portInNpu = p % 2;
                jb.str("remoteDevice", "rack" + r + "#board" + boardId + "#npu" + npuId);
                jb.strLast("remotePort",
                    "400GUB " + boardId + "/" + (2 * npuId) + "/" + ((s - 1) * 2 + portInNpu + 1));
            } else {
                int l2swPortNum = (p - 64) / 2 + 1;
                int chip = (p % 2 == 0 ? 1 : 2);
                jb.str("remoteDevice", "l2sw" + s);
                jb.strLast("remotePort", "400GUB 1/0/" + l2swPortNum + ":" + chip);
            }
            jb.dec();
            if (p < L1SW_PORT_COUNT - 1) {
                jb.closeObjComma();
            } else {
                jb.closeObj();
            }
        }
        jb.dec();
        jb.closeArrComma();
    }

    private static void writeL1swRouting(Jb jb, int r, int s) {
        // 256 routes total:
        //   - 64 NPU-facing (1 outPort each) at positions (R-1)*64 .. R*64-1
        //   - 192 L2-facing (64 outPorts each) at remaining positions, in 3 blocks of 64
        //     targeting the 3 other racks in sorted order.

        // Build all 256 route entries in order.
        String[][] routes = new String[256][];  // each: [dstAddress, outInterface1, outInterface2, ...]

        // --- NPU-facing routes (64) ---
        int[][] npuPorts = npuPortListForL1(s);
        int npuStart = (r - 1) * 64;
        for (int i = 0; i < 64; i++) {
            int b = npuPorts[i][0];
            int n = npuPorts[i][1];
            int p = npuPorts[i][2];
            String dst = cnaIp(r, b, n, p);
            String outIface = l1swPortName(s, l1PortIndex(b, n, p % 2));
            routes[npuStart + i] = new String[]{dst, outIface};
        }

        // --- L2-facing routes (192 = 3 blocks × 64) ---
        // All 64 L2-facing outPort names (ports 64-127)
        String[] l2OutPorts = new String[64];
        for (int p = 0; p < 64; p++) {
            l2OutPorts[p] = l1swPortName(s, 64 + p);
        }

        // Target racks: sorted, excluding local rack R
        int[] targetRacks = new int[3];
        int ti = 0;
        for (int tr = 1; tr <= RACK_COUNT; tr++) {
            if (tr != r) {
                targetRacks[ti++] = tr;
            }
        }

        // Fill L2-facing routes at positions not occupied by NPU-facing routes
        int l2Pos = 0;
        for (int block = 0; block < 3; block++) {
            int targetRack = targetRacks[block];
            int[][] targetPorts = npuPortListForL1(s);  // same board/npu/port pattern
            for (int i = 0; i < 64; i++) {
                int b = targetPorts[i][0];
                int n = targetPorts[i][1];
                int p = targetPorts[i][2];
                String dst = cnaIp(targetRack, b, n, p);
                // Build outPorts array: dst + 64 outInterfaces
                String[] entry = new String[1 + 64];
                entry[0] = dst;
                System.arraycopy(l2OutPorts, 0, entry, 1, 64);
                // Find next available position (skip NPU-facing region)
                while (l2Pos >= npuStart && l2Pos < npuStart + 64) {
                    l2Pos++;
                }
                routes[l2Pos] = entry;
                l2Pos++;
            }
        }

        // Write all 256 routes
        jb.raw("\"routingTables\": [");
        jb.inc();
        for (int i = 0; i < 256; i++) {
            String[] entry = routes[i];
            String dst = entry[0];
            String[] outIfaces = new String[entry.length - 1];
            System.arraycopy(entry, 1, outIfaces, 0, outIfaces.length);
            writeRouteEntry(jb, dst, outIfaces, i == 255);
        }
        jb.dec();
        jb.closeArr();
    }

    // ========================= L2SW device =============================

    /** Append one L2 switch device entry to the shared devices object. */
    private static void appendL2swDevice(Jb jb, int s, boolean last) {
        String deviceKey = "l2sw" + s;
        jb.raw("\"" + deviceKey + "\": {");
        jb.inc();
        jb.str("deviceName", deviceKey);
        jb.str("deviceType", "SW");
        jb.str("level", "L2");
        jb.num("rack", s);
        jb.num("index", s);
        jb.raw("\"forwardingChip\": [");
        jb.inc();
        for (int c = 1; c <= 2; c++) {
            jb.openObj();
            jb.inc();
            jb.num("chipIndex", c);
            writeL2swPorts(jb, s, c);
            jb.emptyArr("logicPorts");
            writeL2swRouting(jb, s, c);
            jb.closeObj();
            jb.dec();
            if (c < 2) {
                jb.raw(",");
            }
        }
        jb.closeArr();
        jb.dec();
        jb.closeObj(); // closes device object
        jb.dec(); // back to devices level
        if (!last) {
            jb.raw(",");
        }
    }

    private static void writeL2swPorts(Jb jb, int s, int c) {
        jb.raw("\"ports\": [");
        jb.inc();
        for (int p = 0; p < L2SW_PORTS_PER_CHIP; p++) {
            int remoteRack = p / 32 + 1;
            int l1swPortNum = 65 + (p % 32) * 2 + (c - 1);
            jb.openObj();
            jb.inc();
            jb.str("portName", l2swPortName(p, c));
            jb.num("id", p);
            jb.str("remoteDevice", "rack" + remoteRack + "#l1sw" + s);
            jb.strLast("remotePort", "400GUB 1/0/" + l1swPortNum);
            jb.dec();
            if (p < L2SW_PORTS_PER_CHIP - 1) {
                jb.closeObjComma();
            } else {
                jb.closeObj();
            }
        }
        jb.dec();
        jb.closeArrComma();
    }

    private static void writeL2swRouting(Jb jb, int s, int c) {
        // 256 routes per chip: 4 blocks × 64, one per rack (rack 1-4).
        // Each route has 32 outPorts: the 32 ports on this chip to rack(b+1)#l1swS.
        jb.raw("\"routingTables\": [");
        jb.inc();
        int total = 256;
        int idx = 0;
        for (int targetRack = 1; targetRack <= RACK_COUNT; targetRack++) {
            // The 32 outPort names on this chip to rack(targetRack)#l1swS
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
                boolean last = (idx == total - 1);
                writeRouteEntry(jb, dst, outPorts, last);
                idx++;
            }
        }
        jb.dec();
        jb.closeArr();
    }
}
