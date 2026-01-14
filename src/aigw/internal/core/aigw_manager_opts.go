/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: AigwManager is the global manager for AIGW.
 * Create: 2025-06-05
 */

// Package core contains the core functions for AIGW.
package core

import "huawei.com/aigw/pkg/crypto"

// AIGWManagerOption AIGW ManagerOption
type AIGWManagerOption func(m *AigwManager) error

// WithHmac add aigw hmac
func WithHmac(hm *crypto.HmacManager) AIGWManagerOption {
	return func(m *AigwManager) error {
		m.HmacMgr = hm
		return nil
	}
}

// WithAes add aigw with aes
func WithAes(am *crypto.AesManager) AIGWManagerOption {
	return func(m *AigwManager) error {
		m.AesMgr = am
		return nil
	}
}
