/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Adaptive weighted-scoring strategy for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"math"
	"math/rand"
)

const adaptiveLatencyBaselineSec = 1.0

type adaptive struct {
	state                           *State
	wHealth, wToken, wRPM, wLatency float64
	rng                             *safeRand
}

func newAdaptive(state *State, opts map[string]any) *adaptive {
	var weights map[string]any
	if opts != nil {
		if w, ok := opts["weights"].(map[string]any); ok {
			weights = w
		}
	}
	return &adaptive{
		state:    state,
		wHealth:  optFloat(weights, "health", 1.0),
		wToken:   optFloat(weights, "token", 0.5),
		wRPM:     optFloat(weights, "rpm", 0.3),
		wLatency: optFloat(weights, "latency", 0.2),
		rng:      newSafeRand(rand.Int63()),
	}
}

func (s *adaptive) Name() string { return "adaptive" }

func (s *adaptive) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	var best *Deployment
	bestScore := math.Inf(-1)
	ties := 0
	for _, d := range avail {
		score := s.score(d, ctx)
		switch {
		case score > bestScore:
			best, bestScore, ties = d, score, 1
		case score == bestScore:
			ties++
			if s.rng.Intn(ties) == 0 { // reservoir tie-break
				best = d
			}
		}
	}
	return best
}

func (s *adaptive) score(d *Deployment, ctx *Context) float64 {
	k := d.StateKey()
	healthScore := 1.0 // filtered to HEALTHY already; reserved for extension

	tokenScore := 1.0
	if d.TPM > 0 {
		tokenScore = math.Min(1.0, float64(s.state.RemainingTPM(k, d.TPM))/float64(d.TPM))
	}
	rpmScore := 1.0
	if d.RPM > 0 {
		rpmScore = math.Min(1.0, float64(s.state.RemainingRPM(k, d.RPM))/float64(d.RPM))
	}
	latencyScore := 1.0 / (1.0 + s.state.AvgLatency(k, ctx.Stream)/adaptiveLatencyBaselineSec)

	return s.wHealth*healthScore + s.wToken*tokenScore + s.wRPM*rpmScore + s.wLatency*latencyScore
}
