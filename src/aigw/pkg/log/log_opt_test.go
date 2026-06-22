/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: options test for log configuration
 * Create: 2025-7-26
 */

// Package log use for init logger format
package log

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestPath tests the Path function
func TestPath(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"/var/log", "/var/log"},
		{"./logs", "./logs"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			opt := Path(tc.input)
			err := opt()
			if err != nil {
				t.Errorf("Path(%q) returned an error: %v", tc.input, err)
			}
			if config.Directory != tc.expected {
				t.Errorf("Path(%q) = %v, want %v", tc.input, config.Directory, tc.expected)
			}
		})
	}
}

// TestLevel tests the Level function
func TestLevel(t *testing.T) {
	testCases := []struct {
		input    string
		expected logrus.Level
	}{
		{"info", logrus.InfoLevel},
		{"debug", logrus.DebugLevel},
		{"error", logrus.ErrorLevel},
		{"warn", logrus.WarnLevel},
		{"fatal", logrus.FatalLevel},
		{"panic", logrus.PanicLevel},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			opt := Level(tc.input)
			err := opt()
			if err != nil {
				t.Errorf("Level(%q) returned an error: %v", tc.input, err)
			}
			if config.DefaultLevel != tc.expected {
				t.Errorf("Level(%q) = %v, want %v", tc.input, config.DefaultLevel, tc.expected)
			}
		})
	}
}

// TestMaxSize tests the MaxSize function
func TestMaxSize(t *testing.T) {
	testCases := []struct {
		input    int
		expected int
	}{
		{0, 0},
		{10, 10},
		{100, 100},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %d", tc.input), func(t *testing.T) {
			opt := MaxSize(tc.input)
			err := opt()
			if err != nil {
				t.Errorf("MaxSize(%d) returned an error: %v", tc.input, err)
			}
			if config.MaxSize != tc.expected {
				t.Errorf("MaxSize(%d) = %v, want %v", tc.input, config.MaxSize, tc.expected)
			}
		})
	}
}

// TestMaxBackupsOption tests the MaxBackups function
func TestMaxBackupsOption(t *testing.T) {
	testCases := []struct {
		input    int
		expected int
	}{
		{0, 0},
		{5, 5},
		{10, 10},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %d", tc.input), func(t *testing.T) {
			opt := MaxBackups(tc.input)
			err := opt()
			if err != nil {
				t.Errorf("MaxBackups(%d) returned an error: %v", tc.input, err)
			}
			if config.MaxBackups != tc.expected {
				t.Errorf("MaxBackups(%d) = %v, want %v", tc.input, config.MaxBackups, tc.expected)
			}
		})
	}
}

// TestConsoleEnabled tests the ConsoleEnabled function
func TestConsoleEnabled(t *testing.T) {
	opt := ConsoleEnabled()
	err := opt()
	if err != nil {
		t.Errorf("ConsoleEnabled() returned an error: %v", err)
	}
	if !config.ConsoleloggerEnabled {
		t.Errorf("ConsoleEnabled() = %v, want %v", config.ConsoleloggerEnabled, true)
	}
}
