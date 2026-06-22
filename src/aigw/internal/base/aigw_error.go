/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: definitions of types for AIGW core.
 * Create: 2026-01-29
 */

// Package base contains the error functions for AIGW.
package base

import "fmt"

// AIGWErrorCode is consistent with CGO, detailed logs are printed when an internal error occurs.
type AIGWErrorCode int

const (
	// AIGW_SUCCESS operation succeeded, value is 0
	AIGW_SUCCESS AIGWErrorCode = -iota
	// AIGW_ERR_INVALID_PARAM invalid input parameter, value is -1
	AIGW_ERR_INVALID_PARAM
	// AIGW_ERR_TIMEOUT operation timed out, value is -2.
	AIGW_ERR_TIMEOUT
	// AIGW_ERR_NOT_FOUND requested resource not found, value is -3
	AIGW_ERR_NOT_FOUND
	// AIGW_ERR_NO_MEMORY memory allocation failed, value is -4
	AIGW_ERR_NO_MEMORY
	// AIGW_ERR_INTERNAL internal error in AIGW component, value is -5
	AIGW_ERR_INTERNAL
	// AIGW_ERR_NO_SPACE no space to hold data, value is -6
	AIGW_ERR_NO_SPACE
	// AIGW_ERR_COMP_NOT_INIT comp is not init, value is -7
	AIGW_ERR_COMP_NOT_INIT
	// AIGW_ERR_INVALID_STATE comp is invalid state, value is -8
	AIGW_ERR_INVALID_STATE
)

var errorMessages = map[AIGWErrorCode]string{
	AIGW_SUCCESS:           "Operation succeeded",
	AIGW_ERR_INVALID_PARAM: "Invalid input parameter (e.g., NULL pointer, out of range)",
	AIGW_ERR_TIMEOUT:       "Operation timed out",
	AIGW_ERR_NOT_FOUND:     "Requested resource not found",
	AIGW_ERR_NO_MEMORY:     "Memory allocation failed",
	AIGW_ERR_INTERNAL:      "Internal error in AIGW component",
	AIGW_ERR_NO_SPACE:      "No space to hold data",
	AIGW_ERR_COMP_NOT_INIT: "Comp is not init",
	AIGW_ERR_INVALID_STATE: "Invalid state in AIGW component",
}

// Error is AIGWErrorCode and error in the AIGW
func (e AIGWErrorCode) Error() string {
	if msg, exists := errorMessages[e]; exists {
		return msg
	}
	return fmt.Sprintf("unknown AIGW error code: %d", int(e))
}