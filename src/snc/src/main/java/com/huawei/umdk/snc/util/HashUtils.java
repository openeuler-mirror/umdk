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

    private interface UbSwitchLibrary extends Library {
        int ubswitch_Hash_ecmp(String dip, String sip, int dport, int sport,
                            int protocol, int hash_func, int ecmp_cnt);
    }

    private static final String NATIVE_LIBRARY_NAME = detectNativeLibraryName();

    private static final UbSwitchLibrary LIB;

    static {
        UbSwitchLibrary lib;
        try {
            lib = DllLoader.load(NATIVE_LIBRARY_NAME, UbSwitchLibrary.class);
        } catch (Throwable t) {
            // Native library unavailable; existing hash methods remain usable.
            // nativeHash will throw IllegalStateException when called.
            // Surface the underlying JNA/dlopen failure to stderr so that a
            // load failure (e.g. architecture mismatch) is diagnosable from
            // the test/build log instead of being silently swallowed.
            System.err.println("[HashUtils] Failed to load native library '"
                + NATIVE_LIBRARY_NAME + "': " + t);
            t.printStackTrace(System.err);
            lib = null;
        }
        LIB = lib;
    }

    /**
     * Returns the platform-appropriate native library file name.
     *
     * <p>On Windows returns {@code libubswitch.dll}. On Linux returns the
     * architecture-specific shared library selected via {@code os.arch}:
     * {@code libubswitch-aarch64.so} for AArch64, {@code libubswitch-x86_64.so}
     * for x86-64. This is required because a shared object built for one
     * architecture cannot be {@code dlopen}'ed on another; shipping both and
     * selecting at runtime keeps the same resource set portable across
     * x86-64 and AArch64 build/test hosts.
     */
    private static String detectNativeLibraryName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return "libubswitch.dll";
        }
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("aarch64") || arch.equals("arm64")) {
            return "libubswitch-aarch64.so";
        }
        return "libubswitch-x86_64.so";
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
        if (LIB == null) {
            throw new IllegalStateException(
                "Native library libubswitch (" + NATIVE_LIBRARY_NAME + ") is not loaded");
        }
        // ethertype, offset, hashSeed are intentionally ignored per the
        // native API contract.
        int rawHash = LIB.ubswitch_Hash_ecmp(dip, sip, dport, sport, protocol,
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
