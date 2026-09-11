/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: snc exception test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.exception;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SNCException")
class SNCExceptionTest {

    @Test
    @DisplayName("Default constructor")
    void defaultConstructor() {
        SNCException e = new SNCException();
        assertNull(e.getMessage());
        assertNull(e.getCause());
    }

    @Test
    @DisplayName("Constructor with message")
    void constructorWithMessage() {
        SNCException e = new SNCException("test error");
        assertEquals("test error", e.getMessage());
        assertNull(e.getCause());
    }

    @Test
    @DisplayName("Constructor with message and cause")
    void constructorWithMessageAndCause() {
        Throwable cause = new RuntimeException("root");
        SNCException e = new SNCException("test error", cause);
        assertEquals("test error", e.getMessage());
        assertSame(cause, e.getCause());
    }

    @Test
    @DisplayName("Is RuntimeException")
    void isRuntimeException() {
        SNCException e = new SNCException();
        assertInstanceOf(RuntimeException.class, e);
    }
}
