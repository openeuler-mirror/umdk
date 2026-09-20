/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: pure-Java hash entry points equivalent to libubswitch / libubswitch-die
 * Create: 2026-09-20
 * Note:
 *   Ported from ubswitch_ecmp.c and ubswitch_dieEcmp.c so that the hash
 *   result is available even when the native libraries are absent.
 *   Used by HashUtils as a fallback when JNA loading fails.
 */
package com.huawei.umdk.snc.util;

/**
 * Pure-Java implementation of the two native hash entry points, serving as
 * a fallback when {@code libubswitch} / {@code libubswitch-die} are not
 * available.
 *
 * <p>Two entry points, identical in semantics to the native symbols:
 * <ul>
 *   <li>{@link #ubswitchHashEcmp} &mdash; inter-chassis L1SW&lt;-&gt;L2SW and
 *       L1SW-&gt;NPU selection (ported from {@code ubswitch_ecmp.c}).</li>
 *   <li>{@link #ubswitchHashDieEcmp} &mdash; NPU-&gt;L1SW uplink selection,
 *       CRC-8/ATM based (ported from {@code ubswitch_dieEcmp.c}).</li>
 * </ul>
 *
 * <p><b>Porting notes.</b> The C sources use {@code unsigned int} /
 * {@code unsigned char} / {@code uint32_t}; Java {@code int} bit operations
 * match the 32-bit two's-complement arithmetic when the following rules are
 * observed:
 * <ul>
 *   <li>C {@code unsigned int >> 2} (logical shift) &rarr; Java
 *       {@code int >>> 2} (must use unsigned right shift).</li>
 *   <li>C {@code unsigned char} auto-truncation after {@code << 1} &rarr;
 *       Java {@code & 0xFF} to truncate to 8 bits.</li>
 *   <li>C {@code int h % ecmp_cnt} negative-result correction &rarr;
 *       Java {@code Math.floorMod} or explicit {@code r += ecmpCnt}.</li>
 *   <li>{@code int} natural 32-bit overflow wraparound is identical to
 *       C {@code unsigned int} overflow on the low 32 bits.</li>
 * </ul>
 */
public final class UbSwitchHash {

    private UbSwitchHash() {
    }

    // ------------------------------------------------------------------
    //  ubswitch_Hash_ecmp (ported from ubswitch_ecmp.c)
    // ------------------------------------------------------------------

    /** {@code h = h * 31 + b} — identical to C {@code add_byte}. */
    private static int addByte(int h, int b) {
        return h * 31 + b;
    }

    /**
     * FNV-1a mixing step — {@code h ^= v + 0x9e3779b9 + (h<<6) + (h>>>2)}.
     *
     * <p>C uses {@code (h >> 2)} on {@code unsigned int} which is a logical
     * shift; Java must use {@code >>>} to avoid sign-extension.
     */
    private static int mix(int h, int v) {
        return h ^ (v + 0x9e3779b9 + (h << 6) + (h >>> 2));
    }

    /**
     * Simple accumulator hash (C {@code hash_simple}): iterate each byte of
     * dip/sip through {@code addByte}, then fold the two bytes of dport,
     * two bytes of sport, low byte of protocol, and low byte of hash_func.
     *
     * <p>C casts {@code (unsigned short)dport} before taking bytes; the
     * trailing {@code & 0xFF} makes the cast irrelevant for byte extraction.
     */
    private static int hashSimple(String dip, String sip, int dport, int sport,
                                  int protocol, int hashFunc) {
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

    /**
     * FNV-1a hash (C {@code hash_fnv1a}): offset basis {@code 2166136261},
     * multiplier {@code 16777619}, per-byte {@code (h ^= b; h *= m)} for
     * dip/sip, then {@code mix} for dport, sport, protocol (low 8 bits as
     * unsigned char), and hash_func (full 32 bits as unsigned int).
     *
     * <p>C truncates dport/sport via {@code (unsigned short)} before mix;
     * Java masks with {@code & 0xFFFF} to match the 16-bit value.
     */
    private static int hashFnv1a(String dip, String sip, int dport, int sport,
                                 int protocol, int hashFunc) {
        int h = 0x811C9DC5;  // FNV-1a 32-bit offset basis (2166136261u as unsigned)
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

    /**
     * Java port of {@code ubswitch_Hash_ecmp}: inter-chassis L1SW&lt;-&gt;L2SW
     * and L1SW-&gt;NPU selection.
     *
     * <p>{@code hashFunc == 1} selects FNV-1a; any other value selects the
     * simple accumulator. When {@code ecmpCnt == 0} the raw hash is returned;
     * otherwise the non-negative remainder {@code floorMod(h, ecmpCnt)} is
     * returned, matching the C negative-result correction.
     *
     * @param dip      destination IP (treated as a byte string, like C
     *                 {@code const char *})
     * @param sip      source IP
     * @param dport    destination port
     * @param sport    source port
     * @param protocol IP protocol number
     * @param hashFunc hash function selector; {@code 1} selects FNV-1a
     * @param ecmpCnt  ECMP member count; {@code 0} returns the raw hash
     * @return the selected ECMP member index, or the raw hash when
     *         {@code ecmpCnt == 0}
     */
    public static int ubswitchHashEcmp(String dip, String sip, int dport, int sport,
                                      int protocol, int hashFunc, int ecmpCnt) {
        int h = (hashFunc == 1)
            ? hashFnv1a(dip, sip, dport, sport, protocol, hashFunc)
            : hashSimple(dip, sip, dport, sport, protocol, hashFunc);
        if (ecmpCnt == 0) {
            return h;
        }
        int r = h % ecmpCnt;
        return (r < 0) ? r + ecmpCnt : r;
    }

    // ------------------------------------------------------------------
    //  ubswitch_Hash_dieEcmp (ported from ubswitch_dieEcmp.c)
    // ------------------------------------------------------------------

    /**
     * CRC-8/ATM single-byte step: polynomial {@code 0x07}, init {@code 0x00},
     * no reflection, no final XOR. Java must {@code & 0xFF} after the
     * left shift to emulate C {@code unsigned char} auto-truncation.
     */
    private static int crc8Update(int crc, int b) {
        crc ^= b;
        for (int i = 0; i < 8; i++) {
            if ((crc & 0x80) != 0) {
                crc = ((crc << 1) ^ 0x07) & 0xFF;
            } else {
                crc = (crc << 1) & 0xFF;
            }
        }
        return crc;
    }

    /**
     * Java port of {@code ubswitch_Hash_dieEcmp}: NPU-&gt;L1SW uplink
     * selection, CRC-8/ATM over the 9-byte stream
     * {@code (src_cna[4 BE], dst_cna[4 BE], lb[1])}.
     *
     * <p>{@code functionSelect} of {@code 0} (default) or {@code 1} selects
     * CRC-8/ATM; any other value returns {@code -1}, matching the C
     * contract. {@code ecmpCnt == 0} returns the raw CRC (0..255);
     * otherwise the CRC is reduced modulo {@code ecmpCnt}.
     *
     * <p>Byte extraction uses {@code >>>} for the unsigned right shift to
     * match C {@code uint32_t >> n}; the trailing {@code & 0xFF} makes the
     * choice of shift operator equivalent, but {@code >>>} is used for
     * clarity and consistency with the C source.
     *
     * @param srcCna         source CNA as a 32-bit value (caller passes 0)
     * @param dstCna         destination CNA as a 32-bit value
     * @param lb             low 8 bits of the jetty id
     * @param ecmpCnt        ECMP member count; {@code 0} returns raw CRC
     * @param functionSelect {@code 0} or {@code 1} for CRC-8/ATM; other
     *                       values return {@code -1}
     * @return the selected ECMP member index, or the raw CRC when
     *         {@code ecmpCnt == 0}; {@code -1} for unsupported
     *         {@code functionSelect}
     */
    public static int ubswitchHashDieEcmp(int srcCna, int dstCna, int lb,
                                          int ecmpCnt, int functionSelect) {
        if (functionSelect != 0 && functionSelect != 1) {
            return -1;
        }
        int crc = 0x00;
        // src_cna, 4 bytes big-endian
        crc = crc8Update(crc, (srcCna >>> 24) & 0xFF);
        crc = crc8Update(crc, (srcCna >>> 16) & 0xFF);
        crc = crc8Update(crc, (srcCna >>> 8) & 0xFF);
        crc = crc8Update(crc, srcCna & 0xFF);
        // dst_cna, 4 bytes big-endian
        crc = crc8Update(crc, (dstCna >>> 24) & 0xFF);
        crc = crc8Update(crc, (dstCna >>> 16) & 0xFF);
        crc = crc8Update(crc, (dstCna >>> 8) & 0xFF);
        crc = crc8Update(crc, dstCna & 0xFF);
        // lb, 1 byte (low 8 bits of the jetty id)
        crc = crc8Update(crc, lb & 0xFF);
        if (ecmpCnt == 0) {
            return crc;
        }
        return crc % ecmpCnt;
    }
}
