/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package monitor provides the management monitor client for AIGW.
 * Create: 2025-08-1
 */

// Package alarmmonitor provides the management monitor client for AIGW.
package alarmmonitor

import "huawei.com/aigw/pkg/crypto"

// AlarmClientOption is the option for ZooKeeper manager
type AlarmClientOption func(mgr *MonitorManager) error

// WithServiceAddress supplies service host ip
func WithServiceAddress(host string) AlarmClientOption {
	return func(mgr *MonitorManager) error {
		mgr.hostIP = host
		return nil
	}
}

// WithHmac add monitor hmac
func WithHmac(hm *crypto.HmacManager) AlarmClientOption {
	return func(mgr *MonitorManager) error {
		mgr.hmacMgr = hm
		return nil
	}
}
