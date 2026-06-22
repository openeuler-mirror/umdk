/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: define the options for instance manager.
 * Create: 2026-03-03
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
)

// instanceManagerOption is the option for instance manager
type instanceManagerOption func(mgr *InstanceManager)

// withCrypto sets hmac and aes for manager
func withCrypto(hmacMgr *crypto.HmacManager, aesMgr *crypto.AesManager) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.hmacMgr = hmacMgr
		mgr.aesMgr = aesMgr
	}
}

// withConnectType sets instance connection type
func withConnectType(connectType string) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.insConnectType = connectType
	}
}

// withSnapShotUpdateInterval sets instance snapshot update interval
func withSnapShotUpdateInterval(interval time.Duration) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.insSnapShotFreq = interval
	}
}

// withRuntimeMode set instance manager runtime mode
func withRuntimeMode(runtimeMod base.RuntimeMode) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.runtimeMode = runtimeMod
	}
}

// withDpSize sets DP size for fine-grained load balancing.
// DP size determines how many virtual DP-aware workers per physical worker.
func withDpSize(dpSize int) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.dpSize = dpSize
	}
}

// WithSkipInstanceConnection skips connecting to instances during registration.
// This is useful for testing with mock instances that don't actually run.
func WithSkipInstanceConnection(skip bool) instanceManagerOption {
	return func(mgr *InstanceManager) {
		mgr.skipInstanceConnection = skip
	}
}
