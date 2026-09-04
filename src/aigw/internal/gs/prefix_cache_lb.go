/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: schedule implementation.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for aigw.
package gs

import (
	"context"
	"sort"
	"strings"

	"huawei.com/aigw/internal/kvevents"
	"huawei.com/aigw/internal/prefixcache"
	"huawei.com/aigw/internal/renderclient"
	"huawei.com/aigw/pkg/log"
)

type prefixCacheLoadBalancer struct {
	baseLoadBalancer

	modelName      string
	prefixCacheMgr prefixcache.PrefixCacheManager
	renderClient   *renderclient.RenderClient
	fallbackLB     loadBalancer
}

func newPrefixCacheLB(metricProvider MetricProvider, params *AlgorithmParams) (*prefixCacheLoadBalancer, error) {
	log.Info().Msg("[prefixCache] Init prefixCache loadbalancer.")

	pcConfig := prefixcache.ApplyJSONDefaults(params.PrefixCacheConfig)
	if params.BlockSize > 0 {
		pcConfig.BlockSize = params.BlockSize
	}

	kveventsConfig := kvevents.DefaultKVEventsManagerConfig()
	if params.KVEventsConfig.EndpointTemplate != "" {
		kveventsConfig.EndpointTemplate = params.KVEventsConfig.EndpointTemplate
	}
	var extraHandlers []kvevents.EventHandler
	if params.KvcSessionMgr != nil {
		// Phase 2: fan out kvevents to both prefixcache and the per-model KvcSessionManager.
		extraHandlers = append(extraHandlers, params.KvcSessionMgr.AsKveventsHandler())
	}
	pcMgr, err := prefixcache.NewPrefixCacheManager(pcConfig, kveventsConfig, extraHandlers...)
	if err != nil {
		log.Warn().Msgf("[prefixCache] failed to create prefix cache manager: %v", err)
		return nil, err
	}

	fallback, err := newLeastConnLB(metricProvider, params)
	if err != nil {
		log.Warn().Msgf("[prefixCache] failed to create fallback LB: %v", err)
	}

	return &prefixCacheLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{
			metricProvider:   metricProvider,
			instanceRoleType: params.InstanceRoleType,
		},
		prefixCacheMgr: pcMgr,
		fallbackLB:     fallback,
	}, nil
}

func (lb *prefixCacheLoadBalancer) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	readyInstances, err := lb.getReadyInstances(request.CandidateInstanceIDs)
	if err != nil {
		log.Error().Msgf("[prefixCache] failed to get ready instances: %v", err)
		return lb.fallback(request, options)
	}

	if len(readyInstances) == 0 {
		log.Debug().Msg("[prefixCache] no ready instances")
		return lb.fallback(request, options)
	}

	// Merge two loops into one: build readyInstanceNames and urlToInstanceName simultaneously
	readyInstanceNames := make([]string, 0, len(readyInstances))
	urlToInstanceName := make(map[string]string, len(readyInstances))
	for _, url := range readyInstances {
		if instanceName, ok := lb.prefixCacheMgr.GetInstanceNameByUrl(url); ok {
			readyInstanceNames = append(readyInstanceNames, instanceName)
			urlToInstanceName[url] = instanceName
		} else {
			log.Debug().Msgf("[prefixCache] no instance name mapping for URL %s", url)
		}
	}

	if len(readyInstanceNames) == 0 {
		log.Debug().Msg("[prefixCache] no ready instances after URL->name mapping, using original URLs")
		readyInstanceNames = readyInstances
		// Rebuild urlToInstanceName using original URLs for consistency
		urlToInstanceName = make(map[string]string, len(readyInstances))
		for _, url := range readyInstances {
			urlToInstanceName[url] = url
		}
	}

	modelName := lb.modelName
	if modelName == "" {
		modelName = "default"
	}

	var tokenIDs []int64 // chat-template domain (render)
	var usePrefixCache bool

	if lb.renderClient != nil && request.Request != nil {
		log.Debug().Msg("[prefixCache] branch: using render client for tokenization")
		messages := lb.buildChatMessages(request.Request)
		// Forward the inbound Authorization header to the render endpoint.
		authHeader := request.Headers["Authorization"]
		tokenIDs, err = lb.prefixCacheMgr.Tokenize(context.Background(), modelName, messages, authHeader)
		if err != nil || len(tokenIDs) == 0 {
			log.Error().Msgf("[prefixCache] branch: render tokenization failed: %v, tokenIDs=%v", err, tokenIDs)
		} else {
			usePrefixCache = true
		}

		// Content-domain tokenization (TokenizePrompt via /tokenize) is
		// bypassed: matching runs on the render (chat-template) domain only.
		// We do NOT hit /tokenize per request. buildContentText/
		// TokenizePrompt/mergeMatched are retained as API for when each
		// worker's reported domain is known; re-enable then and key AddPrefix
		// by the worker's reported domain instead of request-matched percent.
	}

	var matched map[string]int
	var matchLength int

	if usePrefixCache {
		// Single-domain matching on the chat-template (render) domain. The
		// dual-domain merge (mergeMatched) is bypassed: cross-domain match-
		// percentage comparison is not meaningful (template and content
		// domains produce different token counts and block alignments), and
		// we lack the signal for which domain each worker actually reports.
		matched, matchLength, err = lb.prefixCacheMgr.MatchPrefix(
			modelName,
			-1,
			tokenIDs,
			readyInstanceNames,
		)
		if err != nil {
			log.Error().Msgf("[prefixCache] branch: template-domain prefix match failed: %v", err)
		}
	} else if request.Request != nil {
		log.Debug().Msgf("[prefixCache] branch: using text-based fallback prefix match, readyInstanceNames=%v", readyInstanceNames)
		matched, matchLength, err = lb.prefixCacheMgr.MatchPrefixByText(
			modelName,
			-1,
			request.Request.Prompt,
			readyInstanceNames,
		)
	}

	if len(matched) > 0 {
		targetInstance := lb.selectFromMatched(readyInstances, matched, urlToInstanceName)
		if targetInstance != nil {
			log.Debug().Msgf("[prefixCache] branch: selected target instance %s", targetInstance.InsUrl)
			// Get instance name for AddPrefix - use URL -> instance name mapping
			addPrefixInstanceName := targetInstance.InsUrl
			if name, ok := urlToInstanceName[targetInstance.InsUrl]; ok {
				addPrefixInstanceName = name
			}
			if len(tokenIDs) > 0 {
				log.Debug().Msgf("[prefixCache] branch: adding prefix to instance %s (url=%s), tokenIDs=%v",
					addPrefixInstanceName, targetInstance.InsUrl, tokenIDs)
				lb.prefixCacheMgr.AddPrefix(
					modelName,
					-1,
					addPrefixInstanceName,
					tokenIDs,
				)
			}

			log.Debug().Msgf("[prefixCache] req %v scheduled to %s with matchLen %d",
				request.Request.ReqId, targetInstance.InsUrl, matchLength)

			return &ScheduleResult{
				ResultType:     DispatchRequest,
				PrefillUrl:     targetInstance.InsUrl,
				DecodeUrl:      "",
				TokenIds:       "",
				PrefillGroupID: targetInstance.GroupID,
				DecodeGroupID:  "",
			}
		} else {
			log.Debug().Msg("[prefixCache] branch: no valid target instance from matched")
		}
	} else {
		log.Debug().Msg("[prefixCache] branch: no prefix match found")
	}

	log.Debug().Msg("[prefixCache] branch: falling back to LB")
	return lb.fallback(request, options)
}

func (lb *prefixCacheLoadBalancer) fallback(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	if lb.fallbackLB == nil {
		log.Debug().Msg("[prefixCache] fallback LB not available")
		return createEmptyScheduleResult()
	}

	return lb.fallbackLB.schedule(request, options)
}

func (lb *prefixCacheLoadBalancer) selectFromMatched(instances []string, matched map[string]int, urlToInstanceName map[string]string) *InstanceMetric {
	type instanceScore struct {
		metric       *InstanceMetric
		instanceName string
		matchPercent int
	}

	scores := make([]instanceScore, 0, len(matched))

	metrics, err := lb.metricProvider.GetInstanceMetrics(instances, lb.buildQueryOptions(nil))
	if err != nil || len(metrics) == 0 {
		log.Warn().Msgf("[prefixCache] selectFromMatched: no metrics found for instances: %v", instances)
		return nil
	}

	// matched key is instanceName (e.g., "worker-19000")
	// metrics InsUrl is URL (e.g., "127.0.0.1:19000")
	// Use the pre-built urlToInstanceName map passed from schedule() to avoid redundant lookups
	for _, m := range metrics {
		instanceName, ok := urlToInstanceName[m.InsUrl]
		if !ok {
			log.Debug().Msgf("[prefixCache] selectFromMatched: no instance name mapping for url %s", m.InsUrl)
			continue
		}

		matchPercent, hasMatch := matched[instanceName]
		if !hasMatch {
			log.Debug().Msgf("[prefixCache] selectFromMatched: instance %s (url=%s) not in matched map",
				instanceName, m.InsUrl)
			continue
		}

		log.Debug().Msgf("[prefixCache] selectFromMatched: matched instance %s (url=%s) with %d%%",
			instanceName, m.InsUrl, matchPercent)

		scores = append(scores, instanceScore{
			metric:       m,
			instanceName: instanceName,
			matchPercent: matchPercent,
		})
	}

	if len(scores) == 0 {
		log.Info().Msgf("[prefixCache] selectFromMatched: no matching instances found")
		return nil
	}

	//when the matchPercent of instances are same, choose the lower ReqNum one
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].matchPercent != scores[j].matchPercent {
			return scores[i].matchPercent > scores[j].matchPercent
		}
		return scores[i].metric.ReqNum < scores[j].metric.ReqNum
	})

	log.Info().Msgf("[prefixCache] selectFromMatched: selected instance %s with %d%% match",
		scores[0].instanceName, scores[0].matchPercent)
	return scores[0].metric
}

func (lb *prefixCacheLoadBalancer) getReadyInstances(candidateIDs []string) ([]string, error) {
	metrics, err := lb.metricProvider.GetInstanceMetrics(candidateIDs, lb.buildQueryOptions(nil))
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(metrics))
	for _, m := range metrics {
		result = append(result, m.InsUrl)
	}

	return result, nil
}

func (lb *prefixCacheLoadBalancer) buildChatMessages(request *LlmRequest) []prefixcache.ChatMessage {
	if request == nil {
		return nil
	}

	messages := make([]prefixcache.ChatMessage, 0, 1)

	if request.Prompt != "" {
		// Reverse parse: "role:content " -> role, content
		// This reverses the processMessages format: role + ":" + content + " "
		prompt := strings.TrimSpace(request.Prompt)
		idx := strings.Index(prompt, ":")
		if idx > 0 {
			role := prompt[:idx]
			content := prompt[idx+1:]
			messages = append(messages, prefixcache.ChatMessage{
				Role:    role,
				Content: content,
			})
		} else {
			messages = append(messages, prefixcache.ChatMessage{
				Role:    "user",
				Content: prompt,
			})
		}
	}

	return messages
}

// buildContentText joins message contents in the raw content domain (no chat
// template). Workers whose KV events report raw content tokens tokenize this
// exact text.
func (lb *prefixCacheLoadBalancer) buildContentText(messages []prefixcache.ChatMessage) string {
	if len(messages) == 0 {
		return ""
	}

	parts := make([]string, 0, len(messages))
	for _, msg := range messages {
		if strings.TrimSpace(msg.Content) == "" {
			continue
		}
		parts = append(parts, msg.Content)
	}
	return strings.Join(parts, "\n")
}

// mergeMatched merges matches from both token domains, keeping the higher
// match percent per instance and recording which domain's tokenIDs were used
// so AddPrefix can extend the table in the correct domain.
func mergeMatched(
	templateMatched map[string]int, templateIDs []int64,
	contentMatched map[string]int, contentIDs []int64,
) (map[string]int, map[string][]int64) {
	merged := make(map[string]int, len(templateMatched)+len(contentMatched))
	domainTokens := make(map[string][]int64)

	for inst, pct := range templateMatched {
		merged[inst] = pct
		domainTokens[inst] = templateIDs
	}
	for inst, pct := range contentMatched {
		if cur, ok := merged[inst]; !ok || pct > cur {
			merged[inst] = pct
			domainTokens[inst] = contentIDs
		}
	}

	return merged, domainTokens
}

func (lb *prefixCacheLoadBalancer) SetRenderClient(client *renderclient.RenderClient) {
	lb.renderClient = client
	if lb.prefixCacheMgr != nil {
		lb.prefixCacheMgr.SetRenderClient(client)
	}
}

func (lb *prefixCacheLoadBalancer) SetModelName(modelName string) {
	lb.modelName = modelName
}

// PrefixCacheCapable is implemented by load balancers that support prefix caching.
// This interface allows GlobalSchedulerManager to access the prefix cache manager
// without directly depending on the prefixCacheLoadBalancer implementation.
type PrefixCacheCapable interface {
	GetPrefixCacheManager() prefixcache.PrefixCacheManager
}

func (lb *prefixCacheLoadBalancer) GetPrefixCacheManager() prefixcache.PrefixCacheManager {
	return lb.prefixCacheMgr
}

func (lb *prefixCacheLoadBalancer) Stop() {
	if lb.prefixCacheMgr != nil {
		lb.prefixCacheMgr.Stop()
	}
}
