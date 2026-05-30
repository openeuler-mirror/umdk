/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

package com.umdk.snc;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SncServiceTest {

    @Test
    public void testProcess() {
        SncService app = new SncService();
        String result = app.process("test");
        assertEquals("Processed: test", result);
    }
}
