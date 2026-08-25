/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/strategy_lowest_latency.go
package apipool

import "math/rand"

type lowestLatency struct {
	state            *State
	explorationRatio float64
	rng              *safeRand
}

func newLowestLatency(state *State, opts map[string]any) *lowestLatency {
	return &lowestLatency{
		state:            state,
		explorationRatio: optFloat(opts, "explorationRatio", 0.1),
		rng:              newSafeRand(rand.Int63()),
	}
}

func (s *lowestLatency) Name() string { return "lowest-latency" }

func (s *lowestLatency) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	if s.rng.Float64() < s.explorationRatio {
		return avail[s.rng.Intn(len(avail))]
	}
	best := avail[0]
	bestLat := s.state.AvgLatency(best.StateKey(), ctx.Stream)
	for _, d := range avail[1:] {
		lat := s.state.AvgLatency(d.StateKey(), ctx.Stream)
		if lat < bestLat {
			best, bestLat = d, lat
		}
	}
	return best
}
