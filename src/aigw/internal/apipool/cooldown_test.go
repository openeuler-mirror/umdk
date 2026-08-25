/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/cooldown_test.go
package apipool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		want   ErrorKind
	}{
		{"network", 0, errors.New("dial tcp: timeout"), ErrNetwork},
		{"canceled", 0, context.Canceled, ErrCanceled},
		{"timeout408", 408, nil, ErrTimeout},
		{"ratelimit429", 429, nil, ErrRateLimit},
		{"auth401", 401, nil, ErrAuth},
		{"auth403", 403, nil, ErrAuth},
		{"notfound404", 404, nil, ErrNotFound},
		{"client400", 400, nil, ErrClient4xx},
		{"client422", 422, nil, ErrClient4xx},
		{"server500", 500, nil, ErrServer5xx},
		{"server503", 503, nil, ErrServer5xx},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ClassifyError(c.status, c.err))
		})
	}
}

func TestDurationFor(t *testing.T) {
	cfg := testCfg() // Duration=60, RateLimit=90, Auth401Floor=300
	assert.Equal(t, 60*time.Second, durationFor(ErrServer5xx, 0, cfg))
	assert.Equal(t, 60*time.Second, durationFor(ErrNetwork, 0, cfg))
	assert.Equal(t, 90*time.Second, durationFor(ErrRateLimit, 0, cfg))
	// 401 exponential: floor * 2^(attempts-1), capped at 8h
	assert.Equal(t, 5*time.Minute, durationFor(ErrAuth, 1, cfg))
	assert.Equal(t, 10*time.Minute, durationFor(ErrAuth, 2, cfg))
	assert.Equal(t, 20*time.Minute, durationFor(ErrAuth, 3, cfg))
	assert.Equal(t, 40*time.Minute, durationFor(ErrAuth, 4, cfg))
	assert.Equal(t, 80*time.Minute, durationFor(ErrAuth, 5, cfg))
	assert.Equal(t, 8*time.Hour, durationFor(ErrAuth, 99, cfg)) // capped
}
