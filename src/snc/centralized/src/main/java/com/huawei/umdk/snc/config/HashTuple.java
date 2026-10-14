/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.config;

/**
 * Number of tuple members passed to {@code nativeHash} in coverage planning.
 *
 * <ul>
 *   <li>{@link #TWO} (default): {@code (dip, sip)} — all other tuple
 *       members are {@code 0}</li>
 *   <li>{@link #THREE}: {@code (dip, sip, sport)}</li>
 *   <li>{@link #FOUR}: {@code (dip, sip, sport, dport)}</li>
 *   <li>{@link #FIVE}: {@code (dip, sip, sport, dport, protocol)}</li>
 * </ul>
 */
public enum HashTuple {
    /** Two-tuple {@code (dip, sip)}; other tuple members are {@code 0}. */
    TWO(2),

    /** Three-tuple {@code (dip, sip, sport)}. */
    THREE(3),

    /** Four-tuple {@code (dip, sip, sport, dport)}. */
    FOUR(4),

    /** Five-tuple {@code (dip, sip, sport, dport, protocol)}. */
    FIVE(5);

    private final int tupleCount;

    HashTuple(int tupleCount) {
        this.tupleCount = tupleCount;
    }

    /**
     * Returns the number of tuple members represented by this value.
     *
     * @return the tuple member count
     */
    public int getTupleCount() {
        return tupleCount;
    }

    /**
     * Looks up a {@code HashTuple} by its tuple member count.
     *
     * @param tupleCount the tuple member count ({@code 2..5})
     * @return the matching {@code HashTuple}
     * @throws IllegalArgumentException if {@code tupleCount} is out of the
     *         supported range
     */
    public static HashTuple fromCount(int tupleCount) {
        for (HashTuple t : values()) {
            if (t.tupleCount == tupleCount) {
                return t;
            }
        }
        throw new IllegalArgumentException(
            "Unsupported hash tuple count: " + tupleCount + " (supported: 2..5)");
    }
}
