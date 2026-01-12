/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package main is the entrance of AIGW.
 * Create: 2025-5-13
 */
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