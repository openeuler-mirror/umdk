/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class CoverageLink {

    /**
     * Owner device of the out-port. <b>Extended semantics:</b> the value is a
     * switch device name for the L1SW↔L2SW segment and an NPU device name for
     * the NPU↔L1SW segment.
     */
    private String switchDevice;

    private Integer chipIndex;

    private String outPort;

    private String remoteSwitch;

    private String remotePort;

    private Integer outPortIndex;

    private Integer totalOutPorts;

    private List<CoveredEidPairRef> coveredPairs;

    private Integer coverCount;

    /**
     * Owner device type of the out-port, {@code "NPU"} or {@code "SW"}. The
     * value is converted from {@code DeviceType.name()} by the service layer so
     * that this DTO does not depend on the entity package.
     */
    private String deviceType;

    /** Link layer; {@code null} for results produced by the original interface. */
    private CoverageLinkLayer layer;
}
