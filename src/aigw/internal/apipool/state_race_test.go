/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/state_race_test.go
package apipool

import (
	"sync"
	"testing"
	"time"
)

func TestState_ConcurrentAccess(t *testing.T) {
	s := NewState(testCfg())
	keys := []StateKey{
		{Provider: "openai", KeyFingerprint: "a"},
		{Provider: "openai", KeyFingerprint: "b"},
	}
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			k := keys[g%len(keys)]
			for i := 0; i < 100; i++ {
				s.RecordSuccess(k, i%2 == 0, 10*time.Millisecond, 5)
				s.RecordFailure(k, ErrServer5xx)
				_ = s.IsAvailable(k)
				_ = s.RemainingTPM(k, 1000)
				_ = s.RemainingRPM(k, 500)
				_ = s.AvgLatency(k, true)
			}
		}(g)
	}
	wg.Wait()
}
