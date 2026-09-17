/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: hash utils jetty two-tuple test
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of the NPU&rarr;L1SW hash entry point
 * {@link HashUtils#nativeHashDstCnaJetty(int, int, int, int)}.
 */
@DisplayName("HashUtils (DstCNA, jettyId) 选口 hash")
class HashUtilsJettyTest {

    private static boolean nativeAvailable() {
        try {
            HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.17"), 32, 4, 1, 1);
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }

    /** Convert a dotted-quad CNA string into the 32-bit int form. */
    private static int cnaToInt(String cna) {
        return AddressUtils.ipToInt(cna);
    }

    @Test
    @DisplayName("jettyId 合法区间为 [32, 1023]")
    void jettyIdRange() {
        assertEquals(32, HashUtils.JETTY_ID_MIN);
        assertEquals(1023, HashUtils.JETTY_ID_MAX);
        assertTrue(HashUtils.isValidJettyId(32));
        assertTrue(HashUtils.isValidJettyId(1023));
        assertTrue(HashUtils.isValidJettyId(512));
        assertTrue(!HashUtils.isValidJettyId(31));
        assertTrue(!HashUtils.isValidJettyId(1024));
        assertTrue(!HashUtils.isValidJettyId(0));
        assertTrue(!HashUtils.isValidJettyId(-1));
    }

    @Test
    @DisplayName("jettyId 不做范围校验，任意值取低 8 位参与 CRC")
    void jettyIdNoRangeCheck() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");
        // Values that were previously out-of-range [32,1023]: 0, 31, 1024, -1.
        // None of them throws; the native fold is by low 8 bits.
        for (int jetty : new int[]{0, 31, 1024, -1}) {
            int idx = HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.17"), jetty, 4, 1, 1);
            assertTrue(idx >= 0 && idx < 4, "index out of range for jetty=" + jetty);
            assertEquals(crc8Reference(0, cnaToInt("223.223.0.17"), jetty & 0xFF) % 4, idx,
                "CRC8(low 8 bits of jettyId) must match for jetty=" + jetty);
        }
    }

    @Test
    @DisplayName("结果落在 [0, ecmpCnt)，且同一入参可复现")
    void resultWithinRangeAndDeterministic() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");

        for (int ecmpCnt = 1; ecmpCnt <= 8; ecmpCnt++) {
            for (int jetty = HashUtils.JETTY_ID_MIN; jetty <= HashUtils.JETTY_ID_MIN + 16; jetty++) {
                int idx = HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.145"), jetty, ecmpCnt, 1, 1);
                assertTrue(idx >= 0 && idx < ecmpCnt,
                    "index out of range: idx=" + idx + ", ecmpCnt=" + ecmpCnt);
                assertEquals(idx,
                    HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.145"), jetty, ecmpCnt, 1, 1),
                    "hash must be deterministic");
            }
        }
    }

    @Test
    @DisplayName("ecmpCnt=0 返回原始 CRC8（0..255）")
    void rawHashWhenEcmpZero() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");
        int raw = HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.145"), 40, 0, 1, 1);
        assertTrue(raw >= 0 && raw <= 255,
            "raw CRC8 value must be in 0..255, but was " + raw);
        assertEquals(raw, HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.145"), 40, 0, 1, 1));
    }

    /** Reference CRC-8/ATM step: poly 0x07, init 0x00, no reflection/XOR. */
    private static int crc8Step(int crc, int b) {
        crc ^= b;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x80) != 0 ? ((crc << 1) ^ 0x07) & 0xFF : (crc << 1) & 0xFF;
        }
        return crc;
    }

    /**
     * Reference CRC8 over the byte stream
     * {@code (src_cna[4 BE], dst_cna[4 BE], lb[1])}.
     * The caller is expected to pass {@code srcCna = 0}.
     */
    private static int crc8Reference(int srcCna, int dstCna, int lb) {
        int crc = 0x00;
        crc = crc8Step(crc, (srcCna >>> 24) & 0xFF);
        crc = crc8Step(crc, (srcCna >>> 16) & 0xFF);
        crc = crc8Step(crc, (srcCna >>> 8) & 0xFF);
        crc = crc8Step(crc, srcCna & 0xFF);
        crc = crc8Step(crc, (dstCna >>> 24) & 0xFF);
        crc = crc8Step(crc, (dstCna >>> 16) & 0xFF);
        crc = crc8Step(crc, (dstCna >>> 8) & 0xFF);
        crc = crc8Step(crc, dstCna & 0xFF);
        crc = crc8Step(crc, lb & 0xFF);
        return crc;
    }

    @Test
    @DisplayName("functionSelect != 1 时返回 -1（不支持）")
    void unsupportedFunctionSelectReturnsNegativeOne() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");
        for (int fs : new int[]{0, 2, 3, 7, -1, 255}) {
            int r = HashUtils.nativeHashDstCnaJetty(cnaToInt("223.223.0.17"), 32, 4, 1, fs);
            assertEquals(-1, r, "functionSelect=" + fs + " must return -1 (unsupported)");
        }
    }

    @Test
    @DisplayName("NPU→L1 使用 CRC-8/ATM：原生结果与参考实现逐位一致，并可按 ecmpCnt 取模")
    void crc8MatchesReference() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");
        String[] cnas = {"223.223.0.17", "223.223.0.145", "170.170.170.18", "255.255.255.103"};
        for (String cna : cnas) {
            int dstCna = cnaToInt(cna);
            for (int jetty = HashUtils.JETTY_ID_MIN;
                 jetty <= HashUtils.JETTY_ID_MAX; jetty += 37) {
                int raw = HashUtils.nativeHashDstCnaJetty(dstCna, jetty, 0, 1, 1);
                assertEquals(crc8Reference(0, dstCna, jetty & 0xFF), raw,
                    "CRC8 must match the reference for " + cna + " jetty=" + jetty);
                for (int ecmp = 1; ecmp <= 8; ecmp++) {
                    assertEquals(raw % ecmp,
                        HashUtils.nativeHashDstCnaJetty(dstCna, jetty, ecmp, 1, 1),
                        "CRC8 must be reduced modulo ecmpCnt=" + ecmp);
                }
            }
        }
    }

    @Test
    @DisplayName("打印 (DstCNA, jettyId) -> NPU 出端口索引分布（2 成员 ECMP）")
    void printDistribution() {
        Assumptions.assumeTrue(nativeAvailable(), "libubswitch-die not available");

        Map<Integer, Integer> jettyBuckets = new LinkedHashMap<>();
        Map<String, Integer> cnaBuckets = new LinkedHashMap<>();
        cnaBuckets.put("223.223.0.17", 0);
        cnaBuckets.put("223.223.0.145", 0);

        Set<Integer> distinct = new LinkedHashSet<>();
        for (String cna : cnaBuckets.keySet()) {
            int dstCna = cnaToInt(cna);
            for (int jetty = HashUtils.JETTY_ID_MIN; jetty < HashUtils.JETTY_ID_MIN + 64; jetty++) {
                int idx = HashUtils.nativeHashDstCnaJetty(dstCna, jetty, 2, 1, 1);
                distinct.add(idx);
                jettyBuckets.merge(idx, 1, Integer::sum);
            }
        }

        System.out.println("[jetty-hash] distinct egress indexes over 128 samples = "
            + distinct + ", bucket counts = " + jettyBuckets);

        // With ecmpCnt = 2 the (DstCNA, jettyId) two-tuple must reach both members.
        assertTrue(distinct.size() >= 2,
            "the (DstCNA, jettyId) hash must spread over the ECMP members");
        assertTrue(jettyBuckets.getOrDefault(0, 0) > 0
                && jettyBuckets.getOrDefault(1, 0) > 0,
            "both ECMP members must be selected by some jetty id");
    }
}
