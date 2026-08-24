/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/sliding_window_test.go
package apipool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlidingWindow_SumWithinWindow(t *testing.T) {
	w := newSlidingWindow(60)
	w.add(1000, 10)
	w.add(1010, 20)
	assert.Equal(t, 30, w.sum(1030))
}

func TestSlidingWindow_EvictsExpired(t *testing.T) {
	w := newSlidingWindow(60)
	w.add(1000, 10) // expires at 1060
	w.add(1050, 20)
	// now=1061: first event (ts=1000) is older than 60s -> evicted
	assert.Equal(t, 20, w.sum(1061))
}

func TestSlidingWindow_EmptyIsZero(t *testing.T) {
	w := newSlidingWindow(60)
	assert.Equal(t, 0, w.sum(1000))
}
