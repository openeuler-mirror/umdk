/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc.dto;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Coverage statistics of a single {@link CoverageLinkLayer}. The field
 * semantics and formulas are identical to {@link CoverageStats} so that the
 * per-layer numbers stay comparable with the aggregate ones.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class CoverageLayerStats {

    /** Number of links of this layer. */
    private Integer totalLinks;

    /** Number of covered links of this layer. */
    private Integer coveredCount;

    /** {@code coveredCount / totalLinks} of this layer. */
    private Double coverageRate;

    /** Minimum cover count over the covered links of this layer. */
    private Integer minRepeatCount;

    /** Maximum cover count over the covered links of this layer. */
    private Integer maxRepeatCount;

    /** Average cover count over the covered links of this layer. */
    private Double avgRepeatCount;

    /** {@code (sum(coverCount) - coveredCount) / totalLinks} of this layer. */
    private Double repeatRate;
}
