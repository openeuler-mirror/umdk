/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: snc state exception test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.exception;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SNCStateException")
class SNCStateExceptionTest {

    @Test
    @DisplayName("Default constructor")
    void defaultConstructor() {
        SNCStateException e = new SNCStateException();
        assertNull(e.getMessage());
        assertNull(e.getCause());
    }

    @Test
    @DisplayName("Constructor with message")
    void constructorWithMessage() {
        SNCStateException e = new SNCStateException("state error");
        assertEquals("state error", e.getMessage());
    }

    @Test
    @DisplayName("Constructor with message and cause")
    void constructorWithMessageAndCause() {
        Throwable cause = new RuntimeException("root");
        SNCStateException e = new SNCStateException("state error", cause);
        assertEquals("state error", e.getMessage());
        assertSame(cause, e.getCause());
    }

    @Test
    @DisplayName("Is SNCException")
    void isSNCException() {
        SNCStateException e = new SNCStateException();
        assertInstanceOf(SNCException.class, e);
    }
}
