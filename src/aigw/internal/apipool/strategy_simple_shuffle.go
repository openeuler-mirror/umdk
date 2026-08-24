/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Simple-shuffle strategy: random selection among healthy deployments.
 * Create: 2026-06-09
 */

package apipool

import "math/rand"

type simpleShuffle struct {
	state *State
	rng   *safeRand
}

func newSimpleShuffle(state *State) *simpleShuffle {
	return &simpleShuffle{state: state, rng: newSafeRand(rand.Int63())}
}

func (s *simpleShuffle) Name() string { return "simple-shuffle" }

func (s *simpleShuffle) Select(deployments []*Deployment, ctx *Context) *Deployment {
	avail := filterAvailable(s.state, deployments)
	if len(avail) == 0 {
		return nil
	}
	return avail[s.rng.Intn(len(avail))]
}
