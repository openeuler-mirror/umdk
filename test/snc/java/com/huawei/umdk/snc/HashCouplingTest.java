/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: hash coupling test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import com.huawei.umdk.snc.util.HashUtils;

import static org.junit.jupiter.api.Assertions.*;

class HashCouplingTest {

    @Test
    @DisplayName("nativeHash ecmpCnt=64 vs ecmpCnt=32 should be independent")
    void testHashIndependence() {
        String[][] pairs = {
            {"223.223.0.21", "223.223.32.21"},
            {"223.223.0.22", "223.223.32.22"},
            {"223.223.0.17", "223.223.64.17"},
            {"223.223.0.18", "223.223.96.18"},
            {"223.223.0.19", "223.223.0.21"},
            {"223.223.32.21", "223.223.0.21"},
        };

        int coupled = 0;
        int total = 0;
        for (String[] p : pairs) {
            int h64 = HashUtils.nativeHash(p[1], p[0], 64, 1);
            int h32 = HashUtils.nativeHash(p[1], p[0], 32, 1);
            boolean eq = (h32 == Math.floorMod(h64, 32));
            System.out.println("sip=" + p[0] + " dip=" + p[1]
                + " h64=" + h64 + " h32=" + h32
                + " h64%32=" + Math.floorMod(h64, 32)
                + " " + (eq ? "COUPLED" : "independent"));
            if (eq) coupled++;
            total++;
        }
        System.out.println("Coupled: " + coupled + "/" + total);
    }
}
