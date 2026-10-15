/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.dto;

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
public class CoverageStats {

    private Integer totalLinks;

    private Integer coveredCount;

    private Double coverageRate;

    private Integer minRepeatCount;

    private Integer maxRepeatCount;

    private Double avgRepeatCount;

    private Double repeatRate;

    private Integer uniqueEidCount;

    private Integer totalEidAppearances;

    private Double eidRepeatRate;

    private Integer eidMinRepeat;

    private Integer eidMaxRepeat;

    private Double eidAvgRepeat;

    private Integer srcEidMinRepeat;

    private Integer srcEidMaxRepeat;

    private Double srcEidAvgRepeat;

    private Integer dstEidMinRepeat;

    private Integer dstEidMaxRepeat;

    private Double dstEidAvgRepeat;

    private java.util.Map<String, Integer> npuUsageByChassis;
}
