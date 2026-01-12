/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: zk log implements zk.Logger interface using logrus logger
 * Create: 2025-07-21
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"huawei.com/aigw/pkg/log"
)

// zkLogger implements zk.Logger interface using logrus logger
type zkLogger struct {
}

// Printf forwards ZooKeeper logs to logrus logger
func (l *zkLogger) Printf(format string, args ...interface{}) {
	log.Info().Msgf(format, args...)
}
