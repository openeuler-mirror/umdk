/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_rate_limit_aware.go
package apipool

import "math/rand"

type rateLimitAware struct {
	state     *State
	threshold int
	rng       *safeRand
}

func newRateLimitAware(state *State, opts map[string]any) *rateLimitAware {
	return &rateLimitAware{
		state:     state,
		threshold: optInt(opts, "rpmThreshold", 10),
		rng:       newSafeRand(rand.Int63()),
	}
}

func (s *rateLimitAware) Name() string { return "rate-limit-aware" }

func (s *rateLimitAware) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	best := avail[0]
	bestRem := s.state.RemainingRPM(best.StateKey(), best.RPM)
	anyAbove := bestRem >= s.threshold
	for _, d := range avail[1:] {
		rem := s.state.RemainingRPM(d.StateKey(), d.RPM)
		if rem >= s.threshold {
			anyAbove = true
		}
		if rem > bestRem {
			best, bestRem = d, rem
		}
	}
	if !anyAbove {
		return avail[s.rng.Intn(len(avail))]
	}
	return best
}
