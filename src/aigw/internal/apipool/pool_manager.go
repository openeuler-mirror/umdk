/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ApiPoolManager wires deployments, shared State, strategy and adapters.
 * Create: 2026-06-09
 */

package apipool

import (
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

const (
	defaultMaxFailoverEndpoints  = 3
	defaultMaxRetriesPerEndpoint = 2
)

// ApiPoolManager selects provider deployments for one model and records results
// into the shared State.
type ApiPoolManager struct {
	model       string
	deployments []*Deployment
	state       *State
	strategy    Strategy
	registry    *Registry

	maxFailover int
}

// NewApiPoolManager builds a pool manager from config, sharing the given State.
func NewApiPoolManager(model string, cfg *base.ProviderPoolConfig, state *State, registry *Registry) (*ApiPoolManager, error) {
	deps := make([]*Deployment, 0, len(cfg.Deployments))
	for _, dc := range cfg.Deployments {
		if _, err := registry.Get(dc.Provider); err != nil {
			return nil, err
		}
		verify := true
		if dc.VerifySSL != nil {
			verify = *dc.VerifySSL
		}
		modelName := model
		if dc.Model != "" {
			modelName = dc.Model
		}
		deps = append(deps, &Deployment{
			ID:               dc.ID,
			ModelName:        modelName,
			APIKey:           dc.APIKey,
			APIBase:          dc.APIBase,
			Provider:         dc.Provider,
			TPM:              dc.TPM,
			RPM:              dc.RPM,
			Tags:             dc.Tags,
			Timeout:          time.Duration(dc.Timeout) * time.Second,
			VerifySSL:        verify,
			AuthHeaderName:   dc.AuthHeaderName,
			AuthHeaderPrefix: dc.AuthHeaderPrefix,
		})
	}

	strat, err := CreateStrategy(cfg.Strategy, state, cfg.StrategyOptions)
	if err != nil {
		return nil, err
	}

	maxFailover := defaultMaxFailoverEndpoints
	if cfg.Retry != nil && cfg.Retry.MaxFailoverEndpoints > 0 {
		maxFailover = cfg.Retry.MaxFailoverEndpoints
	}

	return &ApiPoolManager{
		model:       model,
		deployments: deps,
		state:       state,
		strategy:    strat,
		registry:    registry,
		maxFailover: maxFailover,
	}, nil
}

// MaxFailoverEndpoints returns the cap on cross-endpoint failover attempts.
func (p *ApiPoolManager) MaxFailoverEndpoints() int { return p.maxFailover }

// Select picks a deployment via the configured strategy, or nil if none available.
func (p *ApiPoolManager) Select(ctx *Context) *Deployment {
	dep := p.strategy.Select(p.deployments, ctx)
	p.logSelection(ctx, len(p.deployments), dep)
	return dep
}

// SelectExcept picks a deployment skipping any StateKey already tried.
func (p *ApiPoolManager) SelectExcept(ctx *Context, exclude map[StateKey]bool) *Deployment {
	candidates := make([]*Deployment, 0, len(p.deployments))
	for _, d := range p.deployments {
		if !exclude[d.StateKey()] {
			candidates = append(candidates, d)
		}
	}
	dep := p.strategy.Select(candidates, ctx)
	p.logSelection(ctx, len(candidates), dep)
	return dep
}

// logSelection emits a debug trace of a strategy selection result. It never logs
// the raw API key — only the deployment ID, provider and key fingerprint. The
// state reads are skipped entirely unless debug logging is active.
func (p *ApiPoolManager) logSelection(ctx *Context, candidates int, dep *Deployment) {
	if !log.DebugEnabled() {
		return
	}
	if dep == nil {
		log.Debug().Msgf("apipool[%s]: strategy %T selected none from %d candidate(s)",
			p.model, p.strategy, candidates)
		return
	}
	k := dep.StateKey()
	log.Debug().Msgf("apipool[%s]: strategy %T selected id=%s provider=%s fp=%s remTPM=%d remRPM=%d avgLatMs=%.0f status=%v from %d candidate(s)",
		p.model, p.strategy, dep.ID, dep.Provider, k.KeyFingerprint,
		p.state.RemainingTPM(k, dep.TPM), p.state.RemainingRPM(k, dep.RPM),
		p.state.AvgLatency(k, ctx.Stream)*1000, p.state.Status(k), candidates)
}

// GetAdapter returns the adapter for a provider.
func (p *ApiPoolManager) GetAdapter(provider string) (Adapter, error) {
	return p.registry.Get(provider)
}

// OnSuccess records a non-streaming success (total latency).
func (p *ApiPoolManager) OnSuccess(dep *Deployment, latency time.Duration, tokens int) {
	p.state.RecordSuccess(dep.StateKey(), false, latency, tokens)
}

// OnStreamSuccess records a streaming completion's tokens only (RPM already counted by OnFirstChunk).
func (p *ApiPoolManager) OnStreamSuccess(dep *Deployment, tokens int) {
	p.state.AddTokens(dep.StateKey(), tokens)
}

// OnFirstChunk records the streaming TTFT and counts the request (single RPM increment).
func (p *ApiPoolManager) OnFirstChunk(dep *Deployment, ttft time.Duration) {
	p.state.RecordSuccess(dep.StateKey(), true, ttft, 0)
}

// OnFailure classifies and records a failure into the shared State.
func (p *ApiPoolManager) OnFailure(dep *Deployment, statusCode int, err error) ErrorKind {
	kind := ClassifyError(statusCode, err)
	p.state.RecordFailure(dep.StateKey(), kind)
	return kind
}
