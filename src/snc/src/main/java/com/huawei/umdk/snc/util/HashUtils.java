/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.util;

import java.util.Locale;

import com.sun.jna.Library;

public final class HashUtils {

    /**
     * JNA binding for {@code libubswitch} — the inter-chassis L1SW&lt;-&gt;L2SW
     * and L1SW-&gt;NPU selection hash ({@code ubswitch_Hash_ecmp}).
     */
    private interface UbSwitchEcmpLibrary extends Library {
        int ubswitch_Hash_ecmp(String dip, String sip, int dport, int sport,
                            int protocol, int hash_func, int ecmp_cnt);
    }

    /**
     * JNA binding for {@code libubswitch-die} — the NPU-&gt;L1SW uplink
     * selection hash ({@code ubswitch_Hash_dieEcmp}), CRC-8/ATM based.
     */
    private interface UbSwitchDieLibrary extends Library {
        /**
         * NPU-&gt;L1SW uplink selection with the two-tuple
         * {@code (DstCNA, jettyId)} — CRC-8/ATM based.
         */
        int ubswitch_Hash_dieEcmp(String dstCna, int jettyId, int ecmpCnt);
    }

    private static final String ECMP_NATIVE_LIBRARY_NAME =
        detectNativeLibraryName("libubswitch");

    private static final String DIE_NATIVE_LIBRARY_NAME =
        detectNativeLibraryName("libubswitch-die");

    private static final UbSwitchEcmpLibrary LIB_ECMP;

    private static final UbSwitchDieLibrary LIB_DIE;

    static {
        UbSwitchEcmpLibrary ecmpLib;
        try {
            ecmpLib = DllLoader.load(ECMP_NATIVE_LIBRARY_NAME, UbSwitchEcmpLibrary.class);
        } catch (Throwable t) {
            // Native library unavailable; existing hash methods remain usable.
            // nativeHash will throw IllegalStateException when called.
            // Surface the underlying JNA/dlopen failure to stderr so that a
            // load failure (e.g. architecture mismatch) is diagnosable from
            // the test/build log instead of being silently swallowed.
            System.err.println("[HashUtils] Failed to load native library '"
                + ECMP_NATIVE_LIBRARY_NAME + "': " + t);
            t.printStackTrace(System.err);
            ecmpLib = null;
        }
        LIB_ECMP = ecmpLib;

        UbSwitchDieLibrary dieLib;
        try {
            dieLib = DllLoader.load(DIE_NATIVE_LIBRARY_NAME, UbSwitchDieLibrary.class);
        } catch (Throwable t) {
            // Native library unavailable; nativeHashDstCnaJetty will throw
            // IllegalStateException when called. Surface the underlying
            // JNA/dlopen failure to stderr so that a load failure (e.g.
            // architecture mismatch) is diagnosable from the test/build log
            // instead of being silently swallowed.
            System.err.println("[HashUtils] Failed to load native library '"
                + DIE_NATIVE_LIBRARY_NAME + "': " + t);
            t.printStackTrace(System.err);
            dieLib = null;
        }
        LIB_DIE = dieLib;
    }

    /**
     * Returns the platform-appropriate native library file name for the
     * given base name.
     *
     * <p>The two hash entry points are served by two separate native
     * libraries so that each exported symbol lives in its own loadable
     * artifact:
     * <ul>
     *   <li>{@code libubswitch} — {@code ubswitch_Hash_ecmp} (inter-chassis
     *       L1SW&lt;-&gt;L2SW and L1SW-&gt;NPU selection)</li>
     *   <li>{@code libubswitch-die} — {@code ubswitch_Hash_dieEcmp}
     *       (NPU-&gt;L1SW uplink selection, CRC-8/ATM)</li>
     * </ul>
     *
     * <p>On Windows returns {@code <baseName>.dll}. On Linux returns the
     * architecture-specific shared library selected via {@code os.arch}:
     * {@code <baseName>-aarch64.so} for AArch64, {@code <baseName>-x86_64.so}
     * for x86-64. This is required because a shared object built for one
     * architecture cannot be {@code dlopen}'ed on another; shipping both and
     * selecting at runtime keeps the same resource set portable across
     * x86-64 and AArch64 build/test hosts.
     *
     * @param baseName the library base name, either {@code "libubswitch"}
     *                 (for the ECMP entry point) or {@code "libubswitch-die"}
     *                 (for the dieEcmp entry point)
     */
    private static String detectNativeLibraryName(String baseName) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return baseName + ".dll";
        }
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("aarch64") || arch.equals("arm64")) {
            return baseName + "-aarch64.so";
        }
        return baseName + "-x86_64.so";
    }

    private HashUtils() {
    }

    /**
     * Computes a hash value via the native {@code libubswitch} ECMP hash
     * function.
     *
     * <p>The {@code ethertype}, {@code offset}, and {@code hashSeed}
     * parameters are accepted for API symmetry with other hash entry points
     * but are intentionally ignored by the native call.
     *
     * @param dip       destination IP
     * @param sip       source IP
     * @param dport     destination port
     * @param sport     source port
     * @param ethertype ignored by the native function
     * @param protocol  IP protocol number
     * @param offset    ignored by the native function
     * @param ecmpCnt   ECMP member count; {@code 0} returns the raw hash,
     *                  otherwise the hash is reduced modulo {@code ecmpCnt}
     * @param hashFunc  hash function selector, mapped via {@link #mapHashMode}
     * @param hashSeed  ignored by the native function
     * @return the raw hash value when {@code ecmpCnt == 0}, otherwise
     *         {@code floorMod(rawHash, ecmpCnt)}
     * @throws IllegalStateException if {@code libubswitch} was not loaded
     */
    public static int nativeHash(String dip, String sip, int dport, int sport,
                                 int ethertype, int protocol, int offset,
                                 int ecmpCnt, int hashFunc, int hashSeed) {
        if (LIB_ECMP == null) {
            throw new IllegalStateException(
                "Native library libubswitch (" + ECMP_NATIVE_LIBRARY_NAME + ") is not loaded");
        }
        // ethertype, offset, hashSeed are intentionally ignored per the
        // native API contract.
        int rawHash = LIB_ECMP.ubswitch_Hash_ecmp(dip, sip, dport, sport, protocol,
                                           mapHashMode(hashFunc), ecmpCnt);
        if (ecmpCnt == 0) {
            return rawHash;
        }
        return Math.floorMod(rawHash, ecmpCnt);
    }

    /**
     * Computes a hash value via the native {@code libubswitch} ECMP hash
     * function using a two-tuple {@code (dip, sip)}.
     *
     * <p>The remaining tuple members ({@code dport}, {@code sport},
     * {@code protocol}) are all {@code 0} when only the two-tuple is
     * specified.
     *
     * @param dip      destination IP
     * @param sip      source IP
     * @param ecmpCnt  ECMP member count; {@code 0} returns the raw hash,
     *                 otherwise the hash is reduced modulo {@code ecmpCnt}
     * @param hashFunc hash function selector, mapped via {@link #mapHashMode}
     * @return the raw hash value when {@code ecmpCnt == 0}, otherwise
     *         {@code floorMod(rawHash, ecmpCnt)}
     * @throws IllegalStateException if {@code libubswitch} was not loaded
     */
    public static int nativeHash(String dip, String sip, int ecmpCnt, int hashFunc) {
        return nativeHash(dip, sip, 0, 0, 0, ecmpCnt, hashFunc);
    }

    // ======================================================================
    //  NPU->L1SW egress port selection: (DstCNA, jettyId) two-tuple
    // ======================================================================

    /** Minimum valid jetty id (inclusive), per the UB jetty id allocation rule. */
    public static final int JETTY_ID_MIN = 32;

    /** Maximum valid jetty id (inclusive), per the UB jetty id allocation rule. */
    public static final int JETTY_ID_MAX = 1023;

    /**
     * Returns whether {@code jettyId} is within the valid range
     * {@code [32, 1023]}.
     *
     * @param jettyId the jetty id to validate
     * @return {@code true} when the value is a legal jetty id
     */
    public static boolean isValidJettyId(int jettyId) {
        return jettyId >= JETTY_ID_MIN && jettyId <= JETTY_ID_MAX;
    }

    /**
     * Computes the NPU egress port index for the NPU-&gt;L1SW hop using the
     * standard two-tuple {@code (DstCNA, jettyId)}.
     *
     * <p><b>Algorithm.</b> This entry point is served by the dedicated native
     * symbol {@code ubswitch_Hash_dieEcmp} (CRC-8/ATM, poly {@code 0x07},
     * init {@code 0x00}) over the bytes of the DstCNA string followed by the
     * low and high bytes of the jetty id. It is intentionally different from
     * the inter-chassis L1SW/L2SW entry point ({@code ubswitch_Hash_ecmp}):
     * the NPU uplink hash of the hardware uses the {@code (DstCNA, jettyId)}
     * two-tuple only.
     *
     * <p>The jetty id is not range-checked; the native symbol folds it into
     * the CRC by its low 8 bits (and high 8 bits), so any non-negative
     * {@code int} value is accepted.
     *
     * <p>The native call already reduces the CRC modulo {@code ecmpCnt}, so the
     * returned value is directly the index of the selected NPU uplink out-port
     * within the ECMP member set.
     *
     * @param dstCna   destination CNA (dotted-quad) of the flow
     * @param jettyId  jetty id of the sending NPU port; not range-checked,
     *                 the low 8 bits participate in the CRC
     * @param ecmpCnt  number of NPU uplink candidate ports; {@code 0} returns
     *                 the raw CRC (0..255)
     * @param hashFunc accepted for API symmetry with the L1SW/L2SW entry point;
     *                 CRC8 has no algorithm selector and ignores it
     * @return the selected out-port index, or the raw CRC when
     *         {@code ecmpCnt == 0}
     * @throws IllegalStateException if {@code libubswitch-die} was not loaded
     */
    public static int nativeHashDstCnaJetty(String dstCna, int jettyId,
                                            int ecmpCnt, int hashFunc) {
        if (LIB_DIE == null) {
            throw new IllegalStateException(
                "Native library libubswitch-die (" + DIE_NATIVE_LIBRARY_NAME + ") is not loaded");
        }
        return LIB_DIE.ubswitch_Hash_dieEcmp(dstCna, jettyId, ecmpCnt);
    }

    /**
     * Computes a hash value via the native {@code libubswitch} ECMP hash
     * function using a five-tuple {@code (dip, sip, dport, sport, protocol)}.
     *
     * <p>The {@code ethertype}, {@code offset}, and {@code hashSeed}
     * parameters are accepted for API symmetry with the full hash entry
     * point but are intentionally ignored by the native call.
     *
     * @param dip      destination IP
     * @param sip      source IP
     * @param dport    destination port
     * @param sport    source port
     * @param protocol IP protocol number
     * @param ecmpCnt  ECMP member count; {@code 0} returns the raw hash,
     *                 otherwise the hash is reduced modulo {@code ecmpCnt}
     * @param hashFunc hash function selector, mapped via {@link #mapHashMode}
     * @return the raw hash value when {@code ecmpCnt == 0}, otherwise
     *         {@code floorMod(rawHash, ecmpCnt)}
     * @throws IllegalStateException if {@code libubswitch} was not loaded
     */
    public static int nativeHash(String dip, String sip, int dport, int sport,
                                 int protocol, int ecmpCnt, int hashFunc) {
        return nativeHash(dip, sip, dport, sport, 0, protocol, 0,
                          ecmpCnt, hashFunc, 0);
    }

    /**
     * Maps the public {@code hashFunc} selector to the native
     * {@code hash_func} code expected by {@code ubswitch_Hash_ecmp}.
     *
     * <p>Current implementation is an identity mapping. Override or extend
     * here when the native library defines distinct mode codes.
     */
    private static int mapHashMode(int hashFunc) {
        if(hashFunc == 1) return 6;
        if(hashFunc == 6) return 1;
        return hashFunc;
    }
}
