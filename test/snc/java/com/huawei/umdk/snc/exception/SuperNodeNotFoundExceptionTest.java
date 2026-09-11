/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: super node not found exception test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.exception;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SuperNodeNotFoundException")
class SuperNodeNotFoundExceptionTest {

    @Test
    @DisplayName("Default constructor")
    void defaultConstructor() {
        SuperNodeNotFoundException e = new SuperNodeNotFoundException();
        assertNull(e.getMessage());
        assertNull(e.getCause());
    }

    @Test
    @DisplayName("Constructor with message")
    void constructorWithMessage() {
        SuperNodeNotFoundException e = new SuperNodeNotFoundException("not found");
        assertEquals("not found", e.getMessage());
    }

    @Test
    @DisplayName("Constructor with message and cause")
    void constructorWithMessageAndCause() {
        Throwable cause = new RuntimeException("root");
        SuperNodeNotFoundException e = new SuperNodeNotFoundException("not found", cause);
        assertEquals("not found", e.getMessage());
        assertSame(cause, e.getCause());
    }

    @Test
    @DisplayName("Is SNCException")
    void isSNCException() {
        SuperNodeNotFoundException e = new SuperNodeNotFoundException();
        assertInstanceOf(SNCException.class, e);
    }
}
