/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: options for socket
 * Create: 2025-8-12
 */

// Package sock
package sock

import "time"

// UnixSockOption is the option for unix sock
type UnixSockOption func(s *UnixSock)

// WithConnectTimeout supplies connectTimeout
func WithConnectTimeout(t time.Duration) UnixSockOption {
	return func(s *UnixSock) {
		s.connectTimeout = t
	}
}

// WithReadTimeout supplies readTimeout
func WithReadTimeout(t time.Duration) UnixSockOption {
	return func(s *UnixSock) {
		s.readTimeout = t
	}
}
