/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Error classification and cooldown duration policy for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"context"
	"errors"
	"time"

	"huawei.com/aigw/internal/base"
)

// ErrorKind classifies a forward failure to drive failover/cooldown decisions.
type ErrorKind int

const (
	// ErrNetwork is a transport-level failure (counts, fixed cooldown, failover).
	ErrNetwork ErrorKind = iota
	// ErrServer5xx is an upstream 5xx (counts, fixed cooldown, failover).
	ErrServer5xx
	// ErrRateLimit is HTTP 429 (counts, rate-limit cooldown, failover).
	ErrRateLimit
	// ErrTimeout is HTTP 408 (counts, fixed cooldown, failover).
	ErrTimeout
	// ErrAuth is HTTP 401/403 (counts, exponential-backoff cooldown, failover).
	ErrAuth
	// ErrNotFound is HTTP 404 (failover, no count, no cooldown).
	ErrNotFound
	// ErrClient4xx is HTTP 400/422 (no failover, no count, passthrough).
	ErrClient4xx
	// ErrCanceled is a client/context cancellation (no count, exit loop).
	ErrCanceled
)

const auth401CapDuration = 8 * time.Hour

// ClassifyError maps an HTTP status code and/or transport error to an ErrorKind.
func ClassifyError(statusCode int, err error) ErrorKind {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ErrCanceled
		}
		if statusCode == 0 {
			return ErrNetwork
		}
	}
	switch {
	case statusCode == 408:
		return ErrTimeout
	case statusCode == 429:
		return ErrRateLimit
	case statusCode == 401 || statusCode == 403:
		return ErrAuth
	case statusCode == 404:
		return ErrNotFound
	case statusCode == 400 || statusCode == 422:
		return ErrClient4xx
	case statusCode >= 500:
		return ErrServer5xx
	default:
		return ErrNetwork
	}
}

// counts reports whether this kind increments consecutiveFails.
func (k ErrorKind) counts() bool {
	switch k {
	case ErrNetwork, ErrServer5xx, ErrRateLimit, ErrTimeout, ErrAuth:
		return true
	default:
		return false
	}
}

// durationFor computes the cooldown duration for a triggering failure.
// auth401Attempts is the post-increment count for ErrAuth.
func durationFor(kind ErrorKind, auth401Attempts int, cfg *base.CooldownConfig) time.Duration {
	switch kind {
	case ErrRateLimit:
		return time.Duration(cfg.RateLimitDurationSec) * time.Second
	case ErrAuth:
		d := time.Duration(cfg.Auth401FloorSec) * time.Second
		for i := 1; i < auth401Attempts; i++ {
			d *= 2
			if d >= auth401CapDuration {
				return auth401CapDuration
			}
		}
		return d
	default:
		return time.Duration(cfg.DurationSec) * time.Second
	}
}
