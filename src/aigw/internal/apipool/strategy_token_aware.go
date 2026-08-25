/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_token_aware.go
package apipool

import "math/rand"

type tokenAware struct {
	state     *State
	threshold int
	rng       *safeRand
}

func newTokenAware(state *State, opts map[string]any) *tokenAware {
	return &tokenAware{
		state:     state,
		threshold: optInt(opts, "tokenThreshold", 1000),
		rng:       newSafeRand(rand.Int63()),
	}
}

func (s *tokenAware) Name() string { return "token-aware" }

func (s *tokenAware) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	best := avail[0]
	bestRem := s.state.RemainingTPM(best.StateKey(), best.TPM)
	anyAboveThreshold := bestRem >= s.threshold
	for _, d := range avail[1:] {
		rem := s.state.RemainingTPM(d.StateKey(), d.TPM)
		if rem >= s.threshold {
			anyAboveThreshold = true
		}
		if rem > bestRem {
			best, bestRem = d, rem
		}
	}
	if !anyAboveThreshold {
		return avail[s.rng.Intn(len(avail))] // degrade to shuffle
	}
	return best
}
