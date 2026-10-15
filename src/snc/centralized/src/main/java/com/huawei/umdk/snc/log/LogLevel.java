/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.log;

public enum LogLevel {
    DEBUG("debug"),
    INFO("info"),
    WARN("warn"),
    ERROR("error");

    private final String value;

    LogLevel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
