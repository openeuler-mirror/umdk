/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: coverage requirement test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.dto;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CoverageRequirement 枚举")
class CoverageRequirementTest {

    @Test
    @DisplayName("枚举值")
    void values() {
        assertEquals(2, CoverageRequirement.values().length);
        assertEquals(CoverageRequirement.MIN_COVERAGE,
            CoverageRequirement.valueOf("MIN_COVERAGE"));
        assertEquals(CoverageRequirement.REDUNDANT,
            CoverageRequirement.valueOf("REDUNDANT"));
    }
}
