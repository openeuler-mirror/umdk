/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value format + timestamp + MgmtInfo mask
 */
package com.huawei.umdk.snc.log;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import com.huawei.umdk.snc.entity.MgmtInfo;

public class Logger {
    private static volatile LogCallback callback;

    private final String tag;

    private static final String MASKED = "***";
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public Logger(Class<?> clazz) {
        this.tag = clazz.getSimpleName();
    }

    public static void registerLogCallback(LogCallback callback) {
        Logger.callback = callback;
    }

    private String spliceLogInfo(String format , Object... args){
        String body = (args == null || args.length == 0) ? format : String.format(format, args);
        return (prefix() + " " + body);
    }


    public static String mask(MgmtInfo info) {
        if (info == null) {
            return "null";
        }
        return "MgmtInfo(ip=" + MASKED + ", port=" + MASKED + ", username=" + MASKED + ", password=" + MASKED + ")";
    }


    public static String mask(String value) {
        return value == null ? "null" : MASKED;
    }

    private String prefix() {
        return "[" + LocalDateTime.now().format(TIME_FMT) + "] [" + tag + "]";
    }

    private String sanitize(Object value) {
        if (value instanceof MgmtInfo) {
            return mask((MgmtInfo) value);
        }
        if (value == null) {
            return "null";
        }
        return String.valueOf(value);
    }

    private void log(LogLevel level, String msg) {
        if (callback != null) {
            callback.log(level, msg);
        }
    }

    public void debug(String format , Object... args) {
        log(LogLevel.DEBUG, spliceLogInfo(format , args));
    }

    public void info(String format , Object... args) {
        log(LogLevel.INFO, spliceLogInfo(format , args));
    }

    public void warn(String format , Object... args) {
        log(LogLevel.WARN, spliceLogInfo(format , args));
    }

    public void error(String format , Object... args) {
        log(LogLevel.ERROR, spliceLogInfo(format , args));
    }
}
