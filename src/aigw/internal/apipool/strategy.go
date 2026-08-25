/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Strategy interface, shared helpers, and factory for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import "fmt"

// Context carries per-request hints for strategy selection.
type Context struct {
	Model     string
	Messages  []map[string]any
	PromptLen int  // reserved; first version strategies do not read it
	Stream    bool // selects TTFT vs total latency signal
}

// Strategy selects one deployment from a candidate list.
type Strategy interface {
	Name() string
	Select(deployments []*Deployment, ctx *Context) *Deployment
}

// filterAvailable returns deployments whose shared state is HEALTHY.
func filterAvailable(state *State, deps []*Deployment) []*Deployment {
	out := make([]*Deployment, 0, len(deps))
	for _, d := range deps {
		if state.IsAvailable(d.StateKey()) {
			out = append(out, d)
		}
	}
	return out
}

func optFloat(opts map[string]any, key string, def float64) float64 {
	if opts == nil {
		return def
	}
	if v, ok := opts[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}

func optInt(opts map[string]any, key string, def int) int {
	return int(optFloat(opts, key, float64(def)))
}

// CreateStrategy builds a strategy by name, sharing the given State.
// Additional strategy cases are appended by later tasks.
func CreateStrategy(name string, state *State, opts map[string]any) (Strategy, error) {
	switch name {
	case "simple-shuffle":
		return newSimpleShuffle(state), nil
	case "lowest-latency":
		return newLowestLatency(state, opts), nil
	case "token-aware":
		return newTokenAware(state, opts), nil
	case "rate-limit-aware":
		return newRateLimitAware(state, opts), nil
	case "adaptive":
		return newAdaptive(state, opts), nil
	default:
		return nil, fmt.Errorf("apipool: unknown strategy %q", name)
	}
}
