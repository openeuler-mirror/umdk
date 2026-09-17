/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Generates the full 148-device rack topology JSON as a single
 *              combined file (128 NPU + 16 L1SW + 4 L2SW) at
 *              test/snc/resources/topo_data_full_rack.json, with devices
 *              ordered NPU -> L1 -> L2 and CNA-based /32 + /28 routing tables.
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
 * Routing (/32 exact routes + /28 NPU-granular routes):
 *   /28 NPU-granular destination CNA: the destination NPU's CNA block network
 *        base address — bits 3-0 (port number) all 0, bit 4 stays 1 (low nibble
 *        0000b), i.e. 0xDFDF0000 + (R-1)*0x1000 + (B-1)*0x80 + (N-1)*0x20
 *        + 0x10, written with maskLength 28.
 *   NPU: 1112 routes = 1016 /32 (all NPU ports except its own 8, each 1 outPort —
 *        the local port that connects to the same L1 as the destination NPU port)
 *        + 96 /28 (every NPU in the other 3 racks), each with all 8 local ports:
 *        local port P reaches the target NPU's CNA ports 2*(P/2) and 2*(P/2)+1
 *        via its L1(P/2+1) -> L2 -> the remote rack's same-index L1.
 *   L1:  384 routes = 256 /32 (64 NPU-facing (1 outPort) + 192 L2-facing
 *        (64 outPorts); NPU-facing routes are at positions (R-1)*64 .. R*64-1 in
 *        the routing table; L2-facing routes (3 blocks × 64) target the 3 other
 *        racks in sorted order) + 128 /28 (every NPU in all 4 racks): target in
 *        the local rack -> the 2 direct ports to that NPU (the only CNA ports of
 *        it this L1 can reach); target in another rack -> all 64 L2-facing ports.
 *   L2:  2 chips, each 384 routes = 256 /32 (4 blocks × 64, one per rack), each
 *        32 outPorts (the 32 ports on this chip to the L1 that directly connects
 *        to the NPU port) + 128 /28 (every NPU in all 4 racks), each with the 32
 *        ports on this chip to the target NPU's rack.
 *
 * Compile (from test/snc): javac -d java java/com/huawei/umdk/snc/FullRackTopologyGenerator.java
 * Run (from any directory): java -cp <path-to>/test/snc/java com.huawei.umdk.snc.FullRackTopologyGenerator
 * Output:   always <test/snc>/resources/topo_data_full_rack.json — anchored to the
 *           compiled class location (../resources relative to the classpath root),
 *           independent of the current working directory.
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
    // Output path anchored to this class's compiled location (<test/snc>/java), so
    // the JSON always lands in <test/snc>/resources regardless of the working
    // directory; falls back to a CWD-relative path if the location is unavailable.
    private static final Path OUTPUT_FILE = defaultOutputFile();

    private static Path defaultOutputFile() {
        try {
            Path classRoot = Paths.get(FullRackTopologyGenerator.class
                .getProtectionDomain().getCodeSource().getLocation().toURI());
            return classRoot.resolve("..").resolve("resources").normalize()
                .resolve("topo_data_full_rack.json");
        } catch (Exception e) {
            return Paths.get("resources", "topo_data_full_rack.json");
        }
    }

    private static final int RACK_COUNT = 4;
    private static final int BOARD_COUNT = 8;
    private static final int NPU_PER_BOARD = 4;
    private static final int PORTS_PER_NPU = 8;
    private static final int L1SW_PER_RACK = 4;
    private static final int L2SW_COUNT = 4;
    private static final int L1SW_PORT_COUNT = 128;
    private static final int L2SW_PORTS_PER_CHIP = 128;

    private static final int[] BLOCK_ROW_START = {1, 1, 9, 9};
    private static final int[] BLOCK_COL_START = {1, 5, 1, 5};

    /**
     * L1-L2 wiring table, indexed by (z-1)*2 + (a-1). Each of the 64 L1 uplinks is
     * identified by (z, a) with z = 1..32 and a = 1..2; the entry stores
     * {z, a, blockRow, blockCol, l2Lane}, where l2Lane (1-2) selects the L2 chip
     * and (blockRow, blockCol) locates the L2 cell (see l2CellNum).
     */
    private static final int[][] LANE_WIRING = new int[64][];

    static {
        for (int z = 1; z <= 32; z++) {
            for (int a = 1; a <= 2; a++) {
                int z0 = z - 1;
                int zHalf = z0 / 16;
                int q = (z0 % 16) / 4;
                int r = z0 % 4;
                int blockCol = (r % 2) * 2 + zHalf + 1;
                int l2Lane = r / 2 + 1;
                int blockRow = q * 2 + a;
                LANE_WIRING[(z - 1) * 2 + (a - 1)] =
                    new int[]{z, a, blockRow, blockCol, l2Lane};
            }
        }
    }

    private static String l1L2PortName(int l1Index, int z, int a) {
        return "800GUB" + (l1Index - 1) + "/0/" + z + ":" + a;
    }

    private static String l2PortName(int cell, int lane) {
        return "800GUB1/0/" + cell + ":" + lane;
    }

    /** L2 cell number (1-128) on the 16x8 wiring grid; each rack occupies one quadrant. */
    private static int l2CellNum(int rack, int blockRow, int blockCol) {
        int row = BLOCK_ROW_START[rack - 1] + blockRow - 1;
        int col = BLOCK_COL_START[rack - 1] + blockCol - 1;
        return (row - 1) * 8 + col;
    }

    /** The 32 lanes {cell, z, a} of the given chip that face the given rack. */
    private static int[][] l2ChipRackLanes(int chip, int rack) {
        List<int[]> lanes = new ArrayList<>(32);
        for (int[] w : LANE_WIRING) {
            if (w[4] != chip) {
                continue;
            }
            lanes.add(new int[]{l2CellNum(rack, w[2], w[3]), w[0], w[1]});
        }
        return lanes.toArray(new int[0][]);
    }

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

    /**
     * /28 NPU-granular CNA: the NPU's CNA block network base address — bits 3-0
     * (port number) all 0, bit 4 stays 1 (low nibble 0000b): 0xDFDF0000
     * + (R-1)*0x1000 + (B-1)*0x80 + (N-1)*0x20 + 0x10.
     */
    private static int cna28Int(int r, int b, int n) {
        return 0xDFDF0000
            + (r - 1) * 0x1000
            + (b - 1) * 0x80
            + (n - 1) * 0x20
            + 0x10;
    }

    /** Format the /28 NPU-granular CNA as "223.223.X.Y". */
    private static String cna28Ip(int r, int b, int n) {
        int cna = cna28Int(r, b, n);
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

    /** NPU portName: "400GUB {2B-1}/{2N}/{P+1}" — first segment is the odd board slot (1,3,...,15). */
    private static String npuPortName(int b, int n, int p) {
        return "400GUB" + (2 * b - 1) + "/" + (2 * n) + "/" + (p + 1);
    }

    /** L1SW portName: "400GUB {S-1}/0/{P+1}". */
    private static String l1swPortName(int s, int p) {
        return "400GUB" + (s - 1) + "/0/" + (p + 1);
    }

    /**
     * The 64 (board, npu, port) tuples of the NPU ports wired to L1 switch S, in
     * routing-table order: board pairs (1,5)(2,6)(3,7)(4,8) × NPU 1-4 × the two
     * ports (S-1)*2 and (S-1)*2+1, emitting board1 then board2 of each pair.
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

    /** 0-based L1 port index of the link to board B, NPU N; p selects the NPU port within its L1 pair (0-1). */
    private static int l1PortIndex(int b, int n, int p) {
        return (b - 1) * 8 + (n - 1) * 2 + p;
    }

    /** Minimal line-oriented JSON writer with indentation tracking. */
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

    /**
     * Write one routing table entry with one or more outPortInfos.
     *
     * @param maskLength 32 for exact CNA routes, 28 for NPU-granular routes
     */
    private static void writeRouteEntry(Jb jb, String dstAddr, String[] outInterfaces, int maskLength,
                                        boolean last) {
        jb.openObj();
        jb.inc();
        jb.raw("\"prefix\": {");
        jb.inc();
        jb.str("dstAddress", dstAddr);
        jb.numLast("maskLength", maskLength);
        jb.dec();
        jb.closeObjComma();
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

    private static void writeFile(Path path, String content) throws IOException {
        try (Writer w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            w.write(content);
        }
    }

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

    /** Write the NPU's 8 downlink ports to the rack's L1 switches. */
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
            jb.str("remotePort", l1swPortName(l1swIdx, peerPortId));
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
        // 1112 entries: 1016 /32 (all NPU ports except its own 8, 1 outPort each)
        // + 96 /28 NPU-granular routes (every NPU in the other 3 racks).
        jb.raw("\"routingTables\": [");
        jb.inc();
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    if (rr == ownR && rb == ownB && rn == ownN) {
                        continue;
                    }
                    for (int rp = 0; rp < PORTS_PER_NPU; rp++) {
                        // outInterface = local port that connects to the same L1 as destination port rp
                        String outIface = npuPortName(ownB, ownN, (rp / 2) * 2);
                        writeRouteEntry(jb, cnaIp(rr, rb, rn, rp), new String[]{outIface}, 32, false);
                    }
                }
            }
        }

        // /28 NPU-granular routes (96): every NPU in the other 3 racks, in
        // rack -> board -> NPU order. Out ports: all 8 local ports — local port P
        // reaches the target NPU's CNA ports 2*(P/2) and 2*(P/2)+1 (both inside
        // its /28 block) via L1(P/2+1) -> L2 -> the remote rack's same-index L1.
        int total28 = (RACK_COUNT - 1) * BOARD_COUNT * NPU_PER_BOARD;
        String[] outIfaces = new String[PORTS_PER_NPU];
        for (int p = 0; p < PORTS_PER_NPU; p++) {
            outIfaces[p] = npuPortName(ownB, ownN, p);
        }
        int idx28 = 0;
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            if (rr == ownR) {
                continue;
            }
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    boolean last = (idx28 == total28 - 1);
                    writeRouteEntry(jb, cna28Ip(rr, rb, rn), outIfaces, 28, last);
                    idx28++;
                }
            }
        }
        jb.dec();
        jb.closeArr();
    }

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

    /** Write the L1SW's 128 ports: 64 NPU downlinks and 64 L2 uplinks. */
    private static void writeL1swPorts(Jb jb, int r, int s) {
        jb.raw("\"ports\": [");
        jb.inc();
        for (int p = 0; p < L1SW_PORT_COUNT; p++) {
            jb.openObj();
            jb.inc();
            if (p < 64) {
                int boardId = p / 8 + 1;
                int npuId = (p % 8) / 2 + 1;
                int portInNpu = p % 2;
                jb.str("portName", l1swPortName(s, p));
                jb.num("id", p);
                jb.str("remoteDevice", "rack" + r + "#board" + boardId + "#npu" + npuId);
                jb.strLast("remotePort",
                    npuPortName(boardId, npuId, (s - 1) * 2 + portInNpu));
            } else {
                int[] w = LANE_WIRING[p - 64];
                jb.str("portName", l1L2PortName(s, w[0], w[1]));
                jb.num("id", p);
                jb.str("remoteDevice", "l2sw" + s);
                jb.strLast("remotePort",
                    l2PortName(l2CellNum(r, w[2], w[3]), w[4]));
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
        // 384 routes total:
        //   - 256 /32:
        //     - 64 NPU-facing (1 outPort each) at positions (R-1)*64 .. R*64-1;
        //     - 192 L2-facing (64 outPorts each) in 3 blocks of 64 targeting the
        //       other 3 racks in ascending order.
        //   - 128 /28 NPU-granular routes (every NPU in all 4 racks): target in the
        //     local rack -> the 2 direct ports to that NPU (the only CNA ports of it
        //     this L1 reaches); target in another rack -> all 64 L2-facing ports
        //     (each reaches the target's CNA ports (S-1)*2 and (S-1)*2+1 via L2
        //     -> the remote rack's L1 S).

        // Build all 256 route entries in order.
        String[][] routes = new String[256][];  // element: [dstAddress, outInterface...]

        // NPU-facing routes (64).
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

        // L2-facing routes (192 = 3 blocks × 64).
        // Shared out ports: the 64 L2 uplink ports (ids 64-127).
        String[] l2OutPorts = new String[64];
        for (int i = 0; i < 64; i++) {
            int[] w = LANE_WIRING[i];
            l2OutPorts[i] = l1L2PortName(s, w[0], w[1]);
        }

        // Target racks: the other 3 racks in ascending order.
        int[] targetRacks = new int[3];
        int ti = 0;
        for (int tr = 1; tr <= RACK_COUNT; tr++) {
            if (tr != r) {
                targetRacks[ti++] = tr;
            }
        }

        // Fill L2-facing routes into the positions outside the NPU-facing block.
        int l2Pos = 0;
        for (int block = 0; block < 3; block++) {
            int targetRack = targetRacks[block];
            int[][] targetPorts = npuPortListForL1(s);
            for (int i = 0; i < 64; i++) {
                int b = targetPorts[i][0];
                int n = targetPorts[i][1];
                int p = targetPorts[i][2];
                String dst = cnaIp(targetRack, b, n, p);
                String[] entry = new String[1 + 64];
                entry[0] = dst;
                System.arraycopy(l2OutPorts, 0, entry, 1, 64);
                // Advance past the reserved NPU-facing block.
                while (l2Pos >= npuStart && l2Pos < npuStart + 64) {
                    l2Pos++;
                }
                routes[l2Pos] = entry;
                l2Pos++;
            }
        }

        // Write the 256 /32 routes; none is last because the /28 block follows.
        jb.raw("\"routingTables\": [");
        jb.inc();
        for (int i = 0; i < 256; i++) {
            String[] entry = routes[i];
            String dst = entry[0];
            String[] outIfaces = new String[entry.length - 1];
            System.arraycopy(entry, 1, outIfaces, 0, outIfaces.length);
            writeRouteEntry(jb, dst, outIfaces, 32, false);
        }

        // /28 NPU-granular routes (128): every NPU in all 4 racks, in
        // rack -> board -> NPU order.
        int total28 = RACK_COUNT * BOARD_COUNT * NPU_PER_BOARD;
        int idx28 = 0;
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    String[] outIfaces28;
                    if (rr == r) {
                        // Local rack: the two direct ports to NPU (rb, rn) — the only
                        // CNA ports of its /28 block this L1 reaches.
                        outIfaces28 = new String[]{
                            l1swPortName(s, l1PortIndex(rb, rn, 0)),
                            l1swPortName(s, l1PortIndex(rb, rn, 1))};
                    } else {
                        // Other rack: all 64 L2-facing ports; each reaches the
                        // target's CNA ports (S-1)*2 and (S-1)*2+1 via L2 -> remote L1 S.
                        outIfaces28 = l2OutPorts;
                    }
                    boolean last = (idx28 == total28 - 1);
                    writeRouteEntry(jb, cna28Ip(rr, rb, rn), outIfaces28, 28, last);
                    idx28++;
                }
            }
        }
        jb.dec();
        jb.closeArr();
    }

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

    /** Write the chip's 128 L2 ports, grouped by target rack. */
    private static void writeL2swPorts(Jb jb, int s, int c) {
        jb.raw("\"ports\": [");
        jb.inc();
        int id = 0;
        for (int rack = 1; rack <= RACK_COUNT; rack++) {
            int[][] lanes = l2ChipRackLanes(c, rack);
            for (int[] lane : lanes) {
                jb.openObj();
                jb.inc();
                jb.str("portName", l2PortName(lane[0], c));
                jb.num("id", id);
                jb.str("remoteDevice", "rack" + rack + "#l1sw" + s);
                jb.strLast("remotePort", l1L2PortName(s, lane[1], lane[2]));
                jb.dec();
                if (id < L2SW_PORTS_PER_CHIP - 1) {
                    jb.closeObjComma();
                } else {
                    jb.closeObj();
                }
                id++;
            }
        }
        jb.dec();
        jb.closeArrComma();
    }

    private static void writeL2swRouting(Jb jb, int s, int c) {
        // 384 routes per chip: 256 /32 (4 blocks × 64, one per rack 1-4, each with
        // the 32 outPorts on this chip to that rack's l1swS) + 128 /28 NPU-granular
        // routes (every NPU in all 4 racks), each with the 32 ports on this chip to
        // the target NPU's rack (each of them reaches the target's CNA ports
        // (S-1)*2 and (S-1)*2+1 via that rack's l1swS).
        jb.raw("\"routingTables\": [");
        jb.inc();
        for (int targetRack = 1; targetRack <= RACK_COUNT; targetRack++) {
            // The 32 ports on this chip that connect to rack(targetRack)#l1swS.
            int[][] lanes = l2ChipRackLanes(c, targetRack);
            String[] outPorts = new String[32];
            for (int i = 0; i < 32; i++) {
                outPorts[i] = l2PortName(lanes[i][0], c);
            }

            int[][] npuPorts = npuPortListForL1(s);
            for (int i = 0; i < 64; i++) {
                int b = npuPorts[i][0];
                int n = npuPorts[i][1];
                int p = npuPorts[i][2];
                String dst = cnaIp(targetRack, b, n, p);
                writeRouteEntry(jb, dst, outPorts, 32, false);
            }
        }

        // /28 NPU-granular routes (128): every NPU in all 4 racks, in
        // rack -> board -> NPU order.
        int total28 = RACK_COUNT * BOARD_COUNT * NPU_PER_BOARD;
        int idx28 = 0;
        for (int rr = 1; rr <= RACK_COUNT; rr++) {
            int[][] lanes = l2ChipRackLanes(c, rr);
            String[] outPorts28 = new String[32];
            for (int i = 0; i < 32; i++) {
                outPorts28[i] = l2PortName(lanes[i][0], c);
            }
            for (int rb = 1; rb <= BOARD_COUNT; rb++) {
                for (int rn = 1; rn <= NPU_PER_BOARD; rn++) {
                    boolean last = (idx28 == total28 - 1);
                    writeRouteEntry(jb, cna28Ip(rr, rb, rn), outPorts28, 28, last);
                    idx28++;
                }
            }
        }
        jb.dec();
        jb.closeArr();
    }
}