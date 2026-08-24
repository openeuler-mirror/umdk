/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Provider adapters (URL build + auth injection) for the provider pool.
 * Create: 2026-06-09
 */

package apipool

import (
	"fmt"
	"net/http"
	"strings"
)

// Adapter builds the upstream URL and injects auth headers for a deployment.
type Adapter interface {
	BuildURL(dep *Deployment, route string, stream bool) string
	InjectAuth(headers http.Header, dep *Deployment)
}

// Registry maps a provider identifier to an Adapter.
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

// Register adds or replaces an adapter for a provider name.
func (r *Registry) Register(name string, a Adapter) {
	r.adapters[name] = a
}

// Get returns the adapter for a provider, or an error if unregistered.
func (r *Registry) Get(provider string) (Adapter, error) {
	a, ok := r.adapters[provider]
	if !ok {
		return nil, fmt.Errorf("apipool: unknown provider %q", provider)
	}
	return a, nil
}

// NewDefaultRegistry registers all first-version OpenAI-compatible providers.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	for _, p := range []string{"openai", "vllm", "deepseek", "siliconflow", "custom"} {
		r.Register(p, newOpenAICompatAdapter(p))
	}
	r.Register("dashscope", &dashscopeAdapter{openAICompatAdapter{provider: "dashscope"}})
	r.Register("zhipu", &zhipuAdapter{openAICompatAdapter{provider: "zhipu"}})
	return r
}

// openAICompatAdapter covers providers whose API equals OpenAI's: {APIBase}{route}.
type openAICompatAdapter struct {
	provider string
}

func newOpenAICompatAdapter(provider string) *openAICompatAdapter {
	return &openAICompatAdapter{provider: provider}
}

func (a *openAICompatAdapter) BuildURL(dep *Deployment, route string, _ bool) string {
	return dep.APIBase + route
}

func (a *openAICompatAdapter) InjectAuth(headers http.Header, dep *Deployment) {
	if dep.AuthHeaderName != "" {
		val := dep.APIKey
		if dep.AuthHeaderPrefix != "" {
			val = dep.AuthHeaderPrefix + " " + dep.APIKey
		}
		headers.Set(dep.AuthHeaderName, val)
		return
	}
	headers.Set("Authorization", "Bearer "+dep.APIKey)
}

// dashscopeAdapter prefixes the route with /compatible-mode.
type dashscopeAdapter struct {
	openAICompatAdapter
}

func (a *dashscopeAdapter) BuildURL(dep *Deployment, route string, _ bool) string {
	return dep.APIBase + "/compatible-mode" + route
}

// zhipuAdapter targets Zhipu BigModel, whose apiBase already carries the
// version segment (/api/paas/v4) and exposes chat at /chat/completions with no
// /v1 prefix, so the leading /v1 in the shared route is stripped.
type zhipuAdapter struct {
	openAICompatAdapter
}

func (a *zhipuAdapter) BuildURL(dep *Deployment, route string, _ bool) string {
	return dep.APIBase + strings.TrimPrefix(route, "/v1")
}
