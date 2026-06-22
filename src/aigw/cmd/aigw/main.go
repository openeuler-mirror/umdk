/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: this file provides the main function for AIGW.
 * Create: 2025-05-13
 */

// Package main is the entrance of AIGW.
package main

import (
	"fmt"

	"huawei.com/aigw/internal/server"
)

func main() {
	if err := server.Execute(); err != nil {
		fmt.Printf("[ERROR] Run AIGW failed, err: %v\n", err)
		server.PrintUsage()
	}
}
