/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * NPU physical port.
 *
 * <p>Besides the EID/UPI, each physical port carries a {@code jettyId} used as
 * the entropy member of the NPU-&gt;L1SW egress port selection hash
 * (two-tuple {@code (DstCNA, jettyId)}, see
 * {@code HashUtils.nativeHashDstCnaJetty}). The value must be inside
 * {@code [32, 1023]} and is unique per physical port within one NPU device.
 */
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuPortEntity extends PortEntity {
    private String eid;
    private String upi;

    /**
     * Jetty id of this physical port, in {@code [32, 1023]}; {@code null} when
     * the topology input did not provide one.
     */
    private Integer jettyId;

    /**
     * Keeps the historical two-argument form so that existing callers and
     * topology loaders keep compiling; {@code jettyId} stays {@code null}.
     *
     * @param eid port EID
     * @param upi port UPI
     */
    public NpuPortEntity(String eid, String upi) {
        this(eid, upi, null);
    }

    /**
     * Full constructor.
     *
     * @param eid     port EID
     * @param upi     port UPI
     * @param jettyId jetty id in {@code [32, 1023]}, or {@code null} if unknown
     */
    public NpuPortEntity(String eid, String upi, Integer jettyId) {
        this.eid = eid;
        this.upi = upi;
        this.jettyId = jettyId;
    }
}

