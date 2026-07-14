/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.exception;

public class SNCException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SNCException() {
        super();
    }

    public SNCException(String message) {
        super(message);
    }

    public SNCException(String message, Throwable cause) {
        super(message, cause);
    }
}
