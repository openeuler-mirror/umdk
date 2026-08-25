/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Concurrency-safe random source shared by selection strategies.
 * Create: 2026-06-10
 */

package apipool

import (
	"math/rand"
	"sync"
)

// safeRand wraps a *rand.Rand with a mutex. A single strategy instance is shared
// across concurrent request goroutines, and *rand.Rand is not safe for concurrent
// use, so every draw is serialized. Seed is injectable for deterministic tests.
type safeRand struct {
	mu sync.Mutex
	r  *rand.Rand
}

func newSafeRand(seed int64) *safeRand {
	return &safeRand{r: rand.New(rand.NewSource(seed))}
}

func (s *safeRand) Intn(n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r.Intn(n)
}

func (s *safeRand) Float64() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r.Float64()
}
