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

    private String switchDevice;

    private Integer chipIndex;

    private String outPort;

    private String remoteSwitch;

    private String remotePort;

    private Integer outPortIndex;

    private Integer totalOutPorts;

    private List<CoveredEidPairRef> coveredPairs;

    private Integer coverCount;
}
