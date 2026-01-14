//go:build !linux

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in non linux platform
 * Create: 2025-5-13
 */

// Package log rotate
package log

import "os"

func chown(name string, info os.FileInfo) error {
	return nil
}
