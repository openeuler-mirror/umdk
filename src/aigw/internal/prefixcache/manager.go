/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Prefix cache manager.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"context"
	"sync"

	"huawei.com/aigw/internal/kvevents"
	"huawei.com/aigw/internal/renderclient"
	"huawei.com/aigw/pkg/log"
)

type PrefixCacheManager interface {
	MatchPrefix(modelName string, loraID int64, promptTokenIDs []int64, readyInstances []string) (
		matchedInstances map[string]int, matchLength int, err error)

	MatchPrefixByText(modelName string, loraID int64, promptText string, readyInstances []string) (
		matchedInstances map[string]int, matchLength int, err error)

	AddPrefix(modelName string, loraID int64, instanceName string, promptTokenIDs []int64) error

	RemoveInstance(instanceName string) error

	// Tokenize tokenizes messages via the render (chat-template) domain.
	// authHeader is forwarded to the render endpoint (vLLM --api-key); "" = none.
	Tokenize(ctx context.Context, modelName string, messages []ChatMessage, authHeader string) ([]int64, error)

	// TokenizePrompt tokenizes a raw prompt (content domain).
	// authHeader has the same semantics as Tokenize.
	TokenizePrompt(ctx context.Context, modelName, prompt, authHeader string) ([]int64, error)

	GetStats() PrefixCacheStats

	OnBlockStored(event kvevents.BlockStored) error
	OnBlockRemoved(event kvevents.BlockRemoved) error
	OnAllBlocksCleared(event kvevents.AllBlocksCleared) error

	SubscribeInstance(instanceName, instanceIP, instancePort, modelName string) error
	UnsubscribeInstance(instanceName string)

	SetRenderClient(client *renderclient.RenderClient)
	Stop()

	// GetInstanceNameByUrl returns the instance name for a given URL (ip:port format).
	// This is used by selectFromMatched to correctly map between URL and instance name.
	GetInstanceNameByUrl(url string) (string, bool)
}

type ChatMessage = renderclient.ChatMessage

type prefixCacheManager struct {
	config       Config
	syncTable    *SyncPrefixTable
	kvEventsMgr  *kvevents.KVEventsManager
	renderClient *renderclient.RenderClient

	mu sync.RWMutex

	fallbackStringMatching bool

	// urlToInstanceName maps URL (ip:port) to instance name.
	// Used by selectFromMatched to correctly map between URL and instance name.
	urlToInstanceName map[string]string
}

func NewPrefixCacheManager(
	config Config,
	kvEventsConfig kvevents.KVEventsManagerConfig,
	extraKveventsHandlers ...kvevents.EventHandler,
) (PrefixCacheManager, error) {
	m := &prefixCacheManager{
		config:                 config,
		fallbackStringMatching: config.FallbackStringMatching,
	}

	m.syncTable = NewSyncPrefixTable(config, nil)

	// Phase 2: fan out kvevents to prefixcache + any extra handlers (e.g. KvcSessionManager).
	handler := kvevents.EventHandler(m)
	if len(extraKveventsHandlers) > 0 {
		all := append([]kvevents.EventHandler{handler}, extraKveventsHandlers...)
		handler = kvevents.NewMultiHandler(all...)
	}
	m.kvEventsMgr = kvevents.NewKVEventsManager(handler, kvEventsConfig)

	log.Info().Msgf("[prefixcache] manager created: blockSize=%d", config.BlockSize)

	return m, nil
}

func (m *prefixCacheManager) Start() error {
	if m.kvEventsMgr != nil && m.kvEventsMgr.IsEnabled() {
		log.Info().Msg("[prefixcache] starting KV Events manager")
	}
	return nil
}

func (m *prefixCacheManager) Stop() {
	if m.kvEventsMgr != nil {
		m.kvEventsMgr.Stop()
	}
	if m.syncTable != nil {
		m.syncTable.Close()
	}
	log.Info().Msg("[prefixcache] manager stopped")
}

func (m *prefixCacheManager) MatchPrefix(
	modelName string,
	loraID int64,
	promptTokenIDs []int64,
	readyInstances []string,
) (map[string]int, int, error) {
	if len(promptTokenIDs) == 0 {
		return map[string]int{}, 0, nil
	}

	readyMap := make(map[string]struct{})
	for _, inst := range readyInstances {
		readyMap[inst] = struct{}{}
	}

	matched, hashes := m.syncTable.MatchPrefixFromTokenIDs(modelName, loraID, promptTokenIDs, readyMap)

	matchLength := len(hashes) * m.config.BlockSize
	return matched, matchLength, nil
}

func (m *prefixCacheManager) MatchPrefixByText(
	modelName string,
	loraID int64,
	promptText string,
	readyInstances []string,
) (map[string]int, int, error) {
	if !m.fallbackStringMatching || len(promptText) == 0 {
		return map[string]int{}, 0, nil
	}

	readyMap := make(map[string]struct{})
	for _, inst := range readyInstances {
		readyMap[inst] = struct{}{}
	}

	matched, hashes := m.syncTable.MatchPrefixByText(modelName, loraID, promptText, readyMap)

	matchLength := len(hashes) * m.config.BlockSize
	return matched, matchLength, nil
}

func (m *prefixCacheManager) AddPrefix(
	modelName string,
	loraID int64,
	instanceName string,
	promptTokenIDs []int64,
) error {
	if len(promptTokenIDs) == 0 {
		return nil
	}

	return m.syncTable.AddPrefixFromTokenIDs(modelName, loraID, instanceName, promptTokenIDs)
}

func (m *prefixCacheManager) RemoveInstance(instanceName string) error {
	return m.syncTable.RemoveInstance("", -1, instanceName)
}

func (m *prefixCacheManager) Tokenize(ctx context.Context, modelName string, messages []ChatMessage, authHeader string) ([]int64, error) {
	if m.renderClient == nil {
		return nil, nil
	}

	return m.renderClient.RenderChat(ctx, modelName, messages, authHeader)
}

// TokenizePrompt tokenizes a raw prompt in the content domain (no chat
// template). Some workers' KV events report raw content tokens rather than
// chat-template tokens; this provides the matching domain for those workers.
func (m *prefixCacheManager) TokenizePrompt(ctx context.Context, modelName, prompt, authHeader string) ([]int64, error) {
	if m.renderClient == nil {
		return nil, nil
	}

	return m.renderClient.TokenizePrompt(ctx, modelName, prompt, authHeader)
}

func (m *prefixCacheManager) GetStats() PrefixCacheStats {
	if m.syncTable == nil {
		return PrefixCacheStats{}
	}
	return m.syncTable.GetStats()
}

func (m *prefixCacheManager) OnBlockStored(event kvevents.BlockStored) error {
	return m.syncTable.ProcessBlockStored(event)
}

func (m *prefixCacheManager) OnBlockRemoved(event kvevents.BlockRemoved) error {
	return m.syncTable.ProcessBlockRemoved(event)
}

func (m *prefixCacheManager) OnAllBlocksCleared(event kvevents.AllBlocksCleared) error {
	log.Info().Msgf("[prefixcache] OnAllBlocksCleared: instance=%s, model=%s",
		event.InstanceName, event.ModelName)
	return m.syncTable.RemoveInstanceFromAllContexts(event.InstanceName)
}

func (m *prefixCacheManager) SubscribeInstance(instanceName, instanceIP, instancePort, modelName string) error {
	// Build URL from ip:port
	url := instanceIP + ":" + instancePort

	m.mu.Lock()
	// Maintain url -> instanceName mapping
	if m.urlToInstanceName == nil {
		m.urlToInstanceName = make(map[string]string)
	}
	m.urlToInstanceName[url] = instanceName
	m.mu.Unlock()

	if m.kvEventsMgr == nil {
		return nil
	}
	return m.kvEventsMgr.SubscribeInstance(instanceName, instanceIP, modelName)
}

func (m *prefixCacheManager) UnsubscribeInstance(url string) {
	log.Info().Msgf("[prefixcache] UnsubscribeInstance: url=%s", url)

	// Convert URL to instanceName
	var instanceName string
	m.mu.RLock()
	if name, ok := m.urlToInstanceName[url]; ok {
		instanceName = name
		log.Info().Msgf("[prefixcache] UnsubscribeInstance: resolved URL %s to instanceName %s", url, instanceName)
	} else {
		instanceName = url // Fallback to using URL as instanceName
		log.Warn().Msgf("[prefixcache] UnsubscribeInstance: URL %s not found in mapping, using URL as instanceName", url)
	}
	m.mu.RUnlock()

	m.mu.Lock()
	// Remove from URL mapping
	for mappedUrl, name := range m.urlToInstanceName {
		if name == instanceName {
			delete(m.urlToInstanceName, mappedUrl)
			log.Info().Msgf("[prefixcache] UnsubscribeInstance: removed URL mapping %s -> %s", mappedUrl, name)
		}
	}
	m.mu.Unlock()

	// Clean up prefixStore entries for this instance
	if m.syncTable != nil {
		if err := m.syncTable.RemoveInstanceFromAllContexts(instanceName); err != nil {
			log.Error().Msgf("[prefixcache] UnsubscribeInstance: failed to clean prefixStore: %v", err)
		}
	}

	if m.kvEventsMgr != nil {
		m.kvEventsMgr.UnsubscribeInstance(instanceName)
	}
}

func (m *prefixCacheManager) SetRenderClient(client *renderclient.RenderClient) {
	m.renderClient = client
}

func (m *prefixCacheManager) GetInstanceNameByUrl(url string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.urlToInstanceName == nil {
		return "", false
	}
	name, ok := m.urlToInstanceName[url]
	return name, ok
}
