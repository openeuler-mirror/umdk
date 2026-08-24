/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: define the options of central cache.
 * Create: 2026-02-14
 */

// Package cachecenter implements metadata operations using Redis via injected CacheDriverOps.
package cachecenter

import "time"

// ManagerOption is the option for cache manager
type ManagerOption func(mgr *CacheManager)

// WithRemoteCache sets remote cache for manager
func WithRemoteCache(remoteCache CentralCache) ManagerOption {
	return func(mgr *CacheManager) {
		mgr.remoteCache = remoteCache
	}
}

// WithRefreshInterval sets the refresh interval in ms
func WithRefreshInterval(intervalMs uint32) ManagerOption {
	return func(mgr *CacheManager) {
		if intervalMs == 0 {
			mgr.refreshInterval = defaultRefreshInterval
			return
		}
		mgr.refreshInterval = time.Duration(intervalMs) * time.Millisecond
	}
}

// WithReqTtl sets the request survival duration
func WithReqTtl(ttl time.Duration) ManagerOption {
	return func(mgr *CacheManager) {
		mgr.reqTtl = ttl
	}
}
