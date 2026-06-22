/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: server test
 * Create: 2026-01-29
 */

// Package base contains the error functions for AIGW.
package base

import (
	"testing"
)


func TestAIGWErrorCode(t *testing.T) {
	tests := []struct {
		code     AIGWErrorCode
		expected string
	}{
		{AIGW_SUCCESS, "Operation succeeded"},
		{AIGW_ERR_INVALID_PARAM, "Invalid input parameter (e.g., NULL pointer, out of range)"},
		{AIGW_ERR_TIMEOUT, "Operation timed out"},
		{AIGW_ERR_NOT_FOUND, "Requested resource not found"},
		{AIGW_ERR_NO_MEMORY, "Memory allocation failed"},
		{AIGW_ERR_INTERNAL, "Internal error in AIGW component"},
		{AIGW_ERR_NO_SPACE, "No space to hold data"},
		{AIGW_ERR_COMP_NOT_INIT, "Comp is not init"},
		{AIGW_ERR_INVALID_STATE, "Invalid state in AIGW component"},
		{999, "unknown AIGW error code: 999"},
	}

	for _, tt := range tests {
		got := tt.code.Error()
		if got != tt.expected {
			t.Errorf("Error code %d: got %q, want %q", tt.code, got, tt.expected)
		}
	}
}

func TestErrorCodeValues(t *testing.T) {
	codes := map[AIGWErrorCode]int{
		AIGW_SUCCESS:           0,
		AIGW_ERR_INVALID_PARAM: -1,
		AIGW_ERR_TIMEOUT:       -2,
		AIGW_ERR_NOT_FOUND:     -3,
		AIGW_ERR_NO_MEMORY:     -4,
		AIGW_ERR_INTERNAL:      -5,
		AIGW_ERR_NO_SPACE:      -6,
		AIGW_ERR_COMP_NOT_INIT: -7,
		AIGW_ERR_INVALID_STATE: -8,
	}

	for code, expected := range codes {
		if int(code) != expected {
			t.Errorf("Code %s: got %d, want %d", code.Error(), code, expected)
		}
	}
}