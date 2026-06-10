/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: log test
 * Create: 2025-7-26
 */

// Package log use for init logger format
package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	defaultLogTestPath = "/tmp/aigw"
	defaultPerm        = 0755
)

func TestSetLogLevel(t *testing.T) {
	err := SetLogLevel("info")
	assert.NoError(t, err)
	assert.Equal(t, logrus.InfoLevel, logger.Level)

	err = SetLogLevel("debug")
	assert.NoError(t, err)
	assert.Equal(t, logrus.DebugLevel, logger.Level)

	err = SetLogLevel("invalid")
	assert.Error(t, err)
}

func TestNewRollingWriter(t *testing.T) {
	// Test with default configuration
	config1 := Config{
		Directory:  defaultLogTestPath,
		Filename:   "test.log",
		MaxSize:    5,
		MaxBackups: 10,
	}
	writer := newRollingWriter(config1)
	assert.NotNil(t, writer)
}

func TestInitLogger(t *testing.T) {
	err := InitLogger(Path(""))
	assert.Error(t, err)

	config = Config{
		ConsoleloggerEnabled: true,
		MaxSize:              defaultMaxSize,
		MaxBackups:           defaultBackUps,
		Directory:            defaultLogTestPath,
		DefaultLevel:         DebugLevel,
	}

	err = os.MkdirAll(defaultLogTestPath, defaultPerm)
	assert.NoError(t, err)

	// Test with custom configuration
	err = InitLogger(MaxSize(defaultMaxSize - 1))
	assert.NoError(t, err)
	assert.Equal(t, logrus.DebugLevel, logger.Level)
	assert.Equal(t, "debug", logger.Level.String())

	// Check if the custom log file exists
	_, err = os.Stat(filepath.Join(defaultLogTestPath, config.Filename))
	assert.NoError(t, err)

	// Clean up
	err = os.RemoveAll(defaultLogTestPath)
	assert.NoError(t, err)
}
