/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: options for log configuration
 * Create: 2025-5-30
 */

// Package log use for init logger format
package log

import (
	"github.com/sirupsen/logrus"
)

// AigwLogOption is (an inverted) settings function on logger
type AigwLogOption func() error

// Path set log path
func Path(path string) AigwLogOption {
	return func() error {
		config.Directory = path
		return nil
	}
}

// Level set default log level
func Level(level string) AigwLogOption {
	return func() error {
		l, e := logrus.ParseLevel(level)
		if e != nil {
			return e
		}
		config.DefaultLevel = l
		return nil
	}
}

// MaxSize set log path
func MaxSize(size int) AigwLogOption {
	return func() error {
		config.MaxSize = size
		return nil
	}
}

// MaxBackups set log path
func MaxBackups(num int) AigwLogOption {
	return func() error {
		config.MaxBackups = num
		return nil
	}
}

// ConsoleEnabled set log path
func ConsoleEnabled() AigwLogOption {
	return func() error {
		config.ConsoleloggerEnabled = true
		return nil
	}
}
