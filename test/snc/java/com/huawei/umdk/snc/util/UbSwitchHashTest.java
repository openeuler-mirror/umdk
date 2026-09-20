/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ubswitch hash pure-java implementation test
 * Create: 2026-09-20
 * Note:
 */
package com.huawei.umdk.snc.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link UbSwitchHash}, the pure-Java fallback used when
 * {@code libubswitch} / {@code libubswitch-die} are absent.
 */
@DisplayName("UbSwitchHash 纯 Java 哈希实现")
class UbSwitchHashTest {

    // ------------------------------------------------------------------
    //  ubswitchHashEcmp
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ecmpCnt=0 返回原始哈希值（simple 分支）")
    void ecmpRawHashSimple() {
        int raw = UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
            100, 200, 17, 6, 0);
        int expected = simpleReference("10.0.0.1", "10.0.0.2", 100, 200, 17, 6);
        assertEquals(expected, raw);
    }

    @Test
    @DisplayName("ecmpCnt=0 返回原始哈希值（FNV-1a 分支）")
    void ecmpRawHashFnv1a() {
        int raw = UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
            100, 200, 17, 1, 0);
        int expected = fnv1aReference("10.0.0.1", "10.0.0.2", 100, 200, 17, 1);
        assertEquals(expected, raw);
    }

    @Test
    @DisplayName("结果落在 [0, ecmpCnt) 且可复现")
    void ecmpResultInRangeAndDeterministic() {
        for (int ecmp = 1; ecmp <= 16; ecmp++) {
            int idx = UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
                100, 200, 17, 6, ecmp);
            assertTrue(idx >= 0 && idx < ecmp,
                "idx=" + idx + " out of range for ecmpCnt=" + ecmp);
            assertEquals(idx,
                UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
                    100, 200, 17, 6, ecmp),
                "hash must be deterministic");
        }
    }

    @Test
    @DisplayName("null dip/sip 等价于空字符串")
    void ecmpNullStringEqualsEmpty() {
        int withNull = UbSwitchHash.ubswitchHashEcmp(null, null,
            0, 0, 0, 6, 0);
        int withEmpty = UbSwitchHash.ubswitchHashEcmp("", "",
            0, 0, 0, 6, 0);
        assertEquals(withEmpty, withNull);
    }

    @Test
    @DisplayName("hashFunc 1 和 6 选择不同分支，结果不同（一般情况）")
    void ecmpFnvVsSimpleDifferent() {
        int fnv = UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
            100, 200, 17, 1, 0);
        int simple = UbSwitchHash.ubswitchHashEcmp("10.0.0.1", "10.0.0.2",
            100, 200, 17, 6, 0);
        assertTrue(fnv != simple, "FNV-1a and simple should differ for non-trivial input");
    }

    // ------------------------------------------------------------------
    //  ubswitchHashDieEcmp
    // ------------------------------------------------------------------

    @Test
    @DisplayName("functionSelect 非 0/1 返回 -1")
    void dieUnsupportedFunctionSelect() {
        for (int fs : new int[]{2, 3, 7, -1, 255}) {
            assertEquals(-1,
                UbSwitchHash.ubswitchHashDieEcmp(0, 0x12345678, 32, 4, fs),
                "functionSelect=" + fs + " must return -1");
        }
    }

    @Test
    @DisplayName("functionSelect 0 和 1 结果一致（默认别名）")
    void dieFunctionSelectZeroAliasOfOne() {
        for (int ecmp = 0; ecmp <= 8; ecmp++) {
            int r0 = UbSwitchHash.ubswitchHashDieEcmp(0, 0x12345678, 32, ecmp, 0);
            int r1 = UbSwitchHash.ubswitchHashDieEcmp(0, 0x12345678, 32, ecmp, 1);
            assertTrue(r0 >= 0, "functionSelect=0 must be supported, got " + r0);
            assertEquals(r1, r0, "functionSelect=0 must equal 1 for ecmpCnt=" + ecmp);
        }
    }

    @Test
    @DisplayName("ecmpCnt=0 返回原始 CRC8 (0..255)，与参考实现一致")
    void dieRawCrc8() {
        int[] dstCnas = {0x00000000, 0x01020304, 0x80808080, 0xFFFFFFFF,
                         AddressUtils.ipToInt("223.223.0.17")};
        int[] lbs = {0, 32, 64, 128, 255};
        for (int dst : dstCnas) {
            for (int lb : lbs) {
                int raw = UbSwitchHash.ubswitchHashDieEcmp(0, dst, lb, 0, 1);
                assertTrue(raw >= 0 && raw <= 255,
                    "raw CRC8 out of range: " + raw + " for dst=" + dst + " lb=" + lb);
                assertEquals(crc8Reference(0, dst, lb), raw,
                    "CRC8 mismatch for dst=" + dst + " lb=" + lb);
            }
        }
    }

    @Test
    @DisplayName("结果落在 [0, ecmpCnt) 且可复现")
    void dieResultInRangeAndDeterministic() {
        for (int ecmp = 1; ecmp <= 16; ecmp++) {
            int idx = UbSwitchHash.ubswitchHashDieEcmp(0, 0x12345678, 32, ecmp, 1);
            assertTrue(idx >= 0 && idx < ecmp,
                "idx=" + idx + " out of range for ecmpCnt=" + ecmp);
            assertEquals(idx,
                UbSwitchHash.ubswitchHashDieEcmp(0, 0x12345678, 32, ecmp, 1),
                "hash must be deterministic");
        }
    }

    @Test
    @DisplayName("CRC8 取模与 ecmpCnt 一致")
    void dieCrc8Modulo() {
        int[] dstCnas = {0x01020304, AddressUtils.ipToInt("223.223.0.145"),
                         0xFFFFFFFF};
        for (int dst : dstCnas) {
            for (int lb = 0; lb <= 255; lb += 17) {
                int raw = UbSwitchHash.ubswitchHashDieEcmp(0, dst, lb, 0, 1);
                for (int ecmp = 1; ecmp <= 8; ecmp++) {
                    assertEquals(raw % ecmp,
                        UbSwitchHash.ubswitchHashDieEcmp(0, dst, lb, ecmp, 1),
                        "CRC8 mod ecmpCnt=" + ecmp + " mismatch for dst=" + dst + " lb=" + lb);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    //  Reference implementations (independent re-implementation)
    // ------------------------------------------------------------------

    private static int addByte(int h, int b) {
        return h * 31 + b;
    }

    private static int mix(int h, int v) {
        return h ^ (v + 0x9e3779b9 + (h << 6) + (h >>> 2));
    }

    private static int simpleReference(String dip, String sip, int dport,
                                      int sport, int protocol, int hashFunc) {
        int h = 0;
        if (dip != null) {
            for (int i = 0; i < dip.length(); i++) {
                h = addByte(h, dip.charAt(i) & 0xFF);
            }
        }
        if (sip != null) {
            for (int i = 0; i < sip.length(); i++) {
                h = addByte(h, sip.charAt(i) & 0xFF);
            }
        }
        h = addByte(h, dport & 0xFF);
        h = addByte(h, (dport >> 8) & 0xFF);
        h = addByte(h, sport & 0xFF);
        h = addByte(h, (sport >> 8) & 0xFF);
        h = addByte(h, protocol & 0xFF);
        h = addByte(h, hashFunc & 0xFF);
        return h;
    }

    private static int fnv1aReference(String dip, String sip, int dport,
                                     int sport, int protocol, int hashFunc) {
        int h = 0x811C9DC5;  // FNV-1a 32-bit offset basis
        if (dip != null) {
            for (int i = 0; i < dip.length(); i++) {
                h ^= dip.charAt(i) & 0xFF;
                h *= 16777619;
            }
        }
        if (sip != null) {
            for (int i = 0; i < sip.length(); i++) {
                h ^= sip.charAt(i) & 0xFF;
                h *= 16777619;
            }
        }
        h = mix(h, dport & 0xFFFF);
        h = mix(h, sport & 0xFFFF);
        h = mix(h, protocol & 0xFF);
        h = mix(h, hashFunc);
        return h;
    }

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

    private static int crc8Step(int crc, int b) {
        crc ^= b;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x80) != 0 ? ((crc << 1) ^ 0x07) & 0xFF : (crc << 1) & 0xFF;
        }
        return crc;
    }
}
