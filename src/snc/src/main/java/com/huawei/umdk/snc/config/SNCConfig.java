/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.config;

import com.huawei.umdk.snc.log.LogCallback;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class SNCConfig {
    private LogCallback logCallback;

    /**
     * Native hash function selector for {@code ubswitch_Hash_ecmp}.
     * Defaults to 1; pass through to {@code nativeHash}'s {@code hashFunc}.
     */
    private int hashFunc = 1;

    /**
     * Fixed UDP source port ({@code sport}) used in the coverage-planning
     * ECMP hash. Defaults to 0 (no effect when only the {@code (dip, sip)}
     * two-tuple participates in the hash).
     */
    private int fixedDataUdpPort = 0;

    /**
     * Fixed UDP destination port ({@code dport}) used in the coverage-planning
     * ECMP hash. Defaults to 0 (no effect when only the {@code (dip, sip)}
     * two-tuple participates in the hash).
     */
    private int fixedAckUdpPort = 0;

    /**
     * Tuple width passed to {@code nativeHash} in coverage planning.
     * Defaults to {@link HashTuple#TWO} (two-tuple {@code (dip, sip)}).
     */
    private HashTuple hashTuple = HashTuple.TWO;
}
