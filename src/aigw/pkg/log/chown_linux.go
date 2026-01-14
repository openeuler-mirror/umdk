/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in linux platform
 * Create: 2025-5-13
 */

// Package log rotate
package log

import (
	"errors"
	"os"
	"syscall"
)

func chown(name string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("assert *syscall.Stat_t failed")
	}
	return os.Chown(name, int(stat.Uid), int(stat.Gid))
}
