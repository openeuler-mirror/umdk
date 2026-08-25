/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Synchronized prefix hash table for distributed prefix cache.
 * Create: 2026-05-21
 */

package prefixcache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"huawei.com/aigw/internal/kvevents"
	"huawei.com/aigw/pkg/log"
)

type SyncPrefixTable struct {
	config Config

	seed                  uint64
	maxContexts           int
	maxPrefixesPerContext int
	blockSize             int

	contextMap   sync.Map
	contextCount atomic.Int32

	evictionInterval time.Duration
	evictionDuration time.Duration
	evictionRunning  atomic.Bool
	stopCh           chan struct{}
	wg               sync.WaitGroup

	blockIndexMu sync.RWMutex
	blockIndex   map[int64][]ModelContext

	redisSync *RedisSync

	hasher *hasher
}

func NewSyncPrefixTable(config Config, redisSync *RedisSync) *SyncPrefixTable {
	// Use configured seed if provided, otherwise generate random
	var seed uint64
	if config.Seed != 0 {
		seed = config.Seed
		log.Info().Msgf("[prefixcache] using configured seed: %d", seed)
	} else {
		seed = generateSeed()
		log.Info().Msgf("[prefixcache] generated random seed: %d", seed)
	}

	s := &SyncPrefixTable{
		config:                config,
		seed:                  seed,
		maxContexts:           config.MaxContexts,
		maxPrefixesPerContext: config.MaxPrefixesPerContext,
		blockSize:             config.BlockSize,
		evictionInterval:      config.EvictionInterval,
		evictionDuration:      config.EvictionDuration,
		stopCh:                make(chan struct{}),
		blockIndex:            make(map[int64][]ModelContext),
		redisSync:             redisSync,
		hasher:                newHasher(seed, config.BlockSize),
	}

	s.wg.Add(1)
	go s.evictionWorker()

	log.Info().Msgf("[prefixcache] initialized: blockSize=%d, maxContexts=%d, maxPrefixes=%d, seed=%d",
		config.BlockSize, config.MaxContexts, config.MaxPrefixesPerContext, seed)

	return s
}

func (s *SyncPrefixTable) MatchPrefix(
	modelName string,
	loraID int64,
	tokens []byte,
	readyInstances map[string]struct{},
) (map[string]int, []uint64) {
	ctx := ModelContext{ModelName: modelName, LoraID: normalizeLoraID(loraID)}

	prefixHashes := s.hasher.getPrefixHashes(tokens)
	if log.DebugEnabled() {
		log.Debug().Msgf("[prefixcache] MatchPrefix: modelName=%s, loraID=%d, tokens len=%d, prefixHashes=%v",
			modelName, loraID, len(tokens), prefixHashes)
	}
	value, exists := s.contextMap.Load(ctx)
	if !exists {
		log.Debug().Msgf("[prefixcache] MatchPrefix: no context found for modelName=%s", modelName)
		return map[string]int{}, prefixHashes
	}

	contextData := value.(*ContextData)
	prefixStore := contextData.prefixStore
	prefixStore.lastAccess = time.Now().Unix()

	if log.DebugEnabled() {
		// Log stored prefix hashes for debugging
		storedHashes := make([]uint64, 0)
		for hash := range prefixStore.prefixMap {
			storedHashes = append(storedHashes, hash)
		}
		log.Debug().Msgf("[prefixcache] MatchPrefix: context found, stored hashes=%v", storedHashes)
	}

	matchedInstances := map[string]int{}

	for i, prefixHash := range prefixHashes {
		pods, exists := prefixStore.prefixMap[prefixHash]
		if !exists || len(pods) == 0 {
			break
		}

		matchPercent := (i + 1) * 100 / len(prefixHashes)

		hasMatch := false
		for instanceName := range pods {
			if _, isReady := readyInstances[instanceName]; isReady {
				matchedInstances[instanceName] = matchPercent
				hasMatch = true
			}
		}

		if !hasMatch {
			break
		}
	}

	return matchedInstances, prefixHashes
}

func (s *SyncPrefixTable) GetPrefixHashesFromTokenIDs(tokenIDs []int64) []uint64 {
	tokens := TokenIDsToBytes(tokenIDs)
	return s.hasher.getPrefixHashes(tokens)
}

func (s *SyncPrefixTable) ProcessBlockStored(event kvevents.BlockStored) error {
	if len(event.BlockHashes) == 0 {
		return nil
	}

	ctx := ModelContext{
		ModelName: event.ModelName,
		LoraID:    normalizeLoraID(event.LoraID),
	}

	contextData := s.getOrCreateContextData(ctx)

	contextData.mappingMu.Lock()

	hashMapping := contextData.hashMapping
	prefixUpdates := make([]struct {
		hash     uint64
		instance string
	}, 0)

	// Track the last computed AIGW hash for chain building
	// Python sends blocks in order, each block's xxhash = hash(prev_block_hash + block_tokens)
	// We need to maintain the same chain in Go
	var lastAigwHash = s.seed

	for i, engineBlockHash := range event.BlockHashes {
		log.Debug().Msgf("[prefixcache] ProcessBlockStored: block %d, engineBlockHash=%d", i, engineBlockHash)

		if existingHash, exists := hashMapping.engineToAigw[engineBlockHash]; exists {
			log.Debug().Msgf("[prefixcache] ProcessBlockStored: block %d, using existing mapping: engine=%d -> aigw=%d",
				i, engineBlockHash, existingHash)
			// Use existing hash as the last hash for chain continuity
			lastAigwHash = existingHash
			prefixUpdates = append(prefixUpdates, struct {
				hash     uint64
				instance string
			}{existingHash, event.InstanceName})
			continue
		}

		// Use the parent hash from the previous block in the chain
		// This matches Python's behavior where each block's xxhash uses the previous block's hash as parent
		parentAigwHash := lastAigwHash

		blockTokens := s.getBlockTokens(event.TokenIDs, i)
		if log.DebugEnabled() {
			log.Debug().Msgf("[prefixcache] ProcessBlockStored: block %d, parentAigwHash=%d (last=%d), blockTokensHex=%s",
				i, parentAigwHash, lastAigwHash, fmt.Sprintf("%x", blockTokens))
		}
		aigwHash := s.hasher.computeHash(parentAigwHash, blockTokens)

		hashMapping.engineToAigw[engineBlockHash] = aigwHash
		lastAigwHash = aigwHash // Update for next block in chain
		prefixUpdates = append(prefixUpdates, struct {
			hash     uint64
			instance string
		}{aigwHash, event.InstanceName})

		s.updateBlockIndex(engineBlockHash, ctx, true)
	}

	contextData.mappingMu.Unlock()

	if len(prefixUpdates) > 0 {
		contextData.prefixMu.Lock()
		for _, update := range prefixUpdates {
			log.Debug().Msgf("[prefixcache] ProcessBlockStored: adding hash=%d to instance=%s",
				update.hash, update.instance)
			s.addPrefixToInstanceLocked(contextData.prefixStore, update.hash, update.instance)
		}
		contextData.prefixMu.Unlock()
	}

	return nil
}

func (s *SyncPrefixTable) ProcessBlockRemoved(event kvevents.BlockRemoved) error {
	if len(event.BlockHashes) == 0 {
		return nil
	}

	ctx := ModelContext{
		ModelName: event.ModelName,
		LoraID:    normalizeLoraID(event.LoraID),
	}

	value, exists := s.contextMap.Load(ctx)
	if !exists {
		if log.DebugEnabled() {
			log.Debug().Msgf("[prefixcache] ProcessBlockRemoved: context not found for ctx=%+v", ctx)
		}
		return nil
	}

	contextData := value.(*ContextData)

	contextData.mappingMu.Lock()
	toRemove := make(map[uint64]bool)

	matchedCount := 0
	for _, engineBlockHash := range event.BlockHashes {
		if aigwHash, exists := contextData.hashMapping.engineToAigw[engineBlockHash]; exists {
			toRemove[aigwHash] = true
			delete(contextData.hashMapping.engineToAigw, engineBlockHash)
			matchedCount++
		} else if log.DebugEnabled() {
			log.Debug().Msgf("[prefixcache] ProcessBlockRemoved: engineBlockHash=%d not found in engineToAigw", engineBlockHash)
		}
		s.updateBlockIndex(engineBlockHash, ctx, false)
	}
	contextData.mappingMu.Unlock()

	if log.DebugEnabled() {
		log.Debug().Msgf("[prefixcache] ProcessBlockRemoved: matched %d/%d blocks, toRemove len=%d",
			matchedCount, len(event.BlockHashes), len(toRemove))
	}

	if len(toRemove) > 0 {
		contextData.prefixMu.Lock()
		for aigwHash := range toRemove {
			delete(contextData.prefixStore.prefixMap, aigwHash)
			contextData.prefixStore.totalPrefixes--
		}
		contextData.prefixMu.Unlock()
	}

	return nil
}

func (s *SyncPrefixTable) AddPrefix(
	modelName string,
	loraID int64,
	instanceName string,
	prefixHashes []uint64,
) error {
	ctx := ModelContext{
		ModelName: modelName,
		LoraID:    normalizeLoraID(loraID),
	}

	contextData := s.getOrCreateContextData(ctx)

	contextData.prefixMu.Lock()
	defer contextData.prefixMu.Unlock()

	prefixStore := contextData.prefixStore
	now := time.Now().Unix()
	prefixStore.lastAccess = now

	for _, prefixHash := range prefixHashes {
		if prefixStore.totalPrefixes >= int64(s.maxPrefixesPerContext) {
			break
		}

		instances, exists := prefixStore.prefixMap[prefixHash]
		if !exists {
			instances = make(map[string]*InstanceInfo)
			prefixStore.prefixMap[prefixHash] = instances
			prefixStore.totalPrefixes++
		}

		if info, exists := instances[instanceName]; exists {
			info.LastAccessTime = now
		} else {
			instances[instanceName] = &InstanceInfo{
				InstanceName:   instanceName,
				LastAccessTime: now,
			}
		}
	}

	return nil
}

func (s *SyncPrefixTable) RemoveInstance(modelName string, loraID int64, instanceName string) error {
	ctx := ModelContext{
		ModelName: modelName,
		LoraID:    normalizeLoraID(loraID),
	}

	value, exists := s.contextMap.Load(ctx)
	if !exists {
		return nil
	}

	contextData := value.(*ContextData)
	contextData.prefixMu.Lock()
	defer contextData.prefixMu.Unlock()

	prefixStore := contextData.prefixStore
	for prefixHash, instances := range prefixStore.prefixMap {
		delete(instances, instanceName)
		if len(instances) == 0 {
			delete(prefixStore.prefixMap, prefixHash)
			prefixStore.totalPrefixes--
		}
	}

	return nil
}

// RemoveInstanceFromAllContexts removes an instance from all model contexts.
// This is used for AllBlocksCleared events where ALL blocks for an instance are cleared.
func (s *SyncPrefixTable) RemoveInstanceFromAllContexts(instanceName string) error {
	log.Info().Msgf("[prefixcache] RemoveInstanceFromAllContexts: instance=%s", instanceName)

	s.contextMap.Range(func(key, value interface{}) bool {
		ctx := key.(ModelContext)
		contextData := value.(*ContextData)

		contextData.prefixMu.Lock()
		prefixStore := contextData.prefixStore
		removedCount := 0
		for prefixHash, instances := range prefixStore.prefixMap {
			if _, exists := instances[instanceName]; exists {
				delete(instances, instanceName)
				removedCount++
				if len(instances) == 0 {
					delete(prefixStore.prefixMap, prefixHash)
					prefixStore.totalPrefixes--
				}
			}
		}
		contextData.prefixMu.Unlock()

		if removedCount > 0 {
			log.Info().Msgf("[prefixcache] RemoveInstanceFromAllContexts: cleared %d prefixes from ctx=%+v",
				removedCount, ctx)
		}
		return true
	})

	return nil
}

func (s *SyncPrefixTable) getOrCreateContextData(ctx ModelContext) *ContextData {
	if value, exists := s.contextMap.Load(ctx); exists {
		return value.(*ContextData)
	}

	newContextData := &ContextData{
		prefixStore: &PrefixStore{
			prefixMap:     make(map[uint64]map[string]*InstanceInfo),
			createTime:    time.Now().Unix(),
			totalPrefixes: 0,
		},
		hashMapping: &HashMapping{
			engineToAigw: make(map[int64]uint64),
		},
	}
	newContextData.prefixStore.lastAccess = time.Now().Unix()

	actual, loaded := s.contextMap.LoadOrStore(ctx, newContextData)
	if !loaded {
		currentCount := s.contextCount.Add(1)
		if int(currentCount) > s.maxContexts {
			s.scheduleEviction()
		}
	}

	return actual.(*ContextData)
}

func (s *SyncPrefixTable) addPrefixToInstanceLocked(prefixStore *PrefixStore, prefixHash uint64, instanceName string) {
	now := time.Now().Unix()

	instances, exists := prefixStore.prefixMap[prefixHash]
	if !exists {
		instances = make(map[string]*InstanceInfo)
		prefixStore.prefixMap[prefixHash] = instances
		prefixStore.totalPrefixes++
	}

	if info, exists := instances[instanceName]; exists {
		info.LastAccessTime = now
	} else {
		instances[instanceName] = &InstanceInfo{
			InstanceName:   instanceName,
			LastAccessTime: now,
		}
	}
}

// getBlockTokens returns the block tokens at the given index.
// TokenIDs is already grouped by blockSize from msgpack_decoder.
func (s *SyncPrefixTable) getBlockTokens(tokenIDs [][]byte, blockIndex int) []byte {
	if blockIndex >= len(tokenIDs) {
		return nil
	}
	return tokenIDs[blockIndex]
}

func (s *SyncPrefixTable) updateBlockIndex(blockHash int64, ctx ModelContext, add bool) {
	s.blockIndexMu.Lock()
	defer s.blockIndexMu.Unlock()

	if add {
		contexts := s.blockIndex[blockHash]
		for _, existingCtx := range contexts {
			if existingCtx == ctx {
				return
			}
		}
		s.blockIndex[blockHash] = append(contexts, ctx)
	} else {
		contexts := s.blockIndex[blockHash]
		for i, existingCtx := range contexts {
			if existingCtx == ctx {
				s.blockIndex[blockHash] = append(contexts[:i], contexts[i+1:]...)
				if len(s.blockIndex[blockHash]) == 0 {
					delete(s.blockIndex, blockHash)
				}
				break
			}
		}
	}
}

func (s *SyncPrefixTable) scheduleEviction() {
}

func (s *SyncPrefixTable) evictionWorker() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.evictionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.performEviction()
		case <-s.stopCh:
			return
		}
	}
}

func (s *SyncPrefixTable) performEviction() {
	if !s.evictionRunning.CompareAndSwap(false, true) {
		return
	}
	defer s.evictionRunning.Store(false)

	now := time.Now().Unix()
	expiredBefore := now - int64(s.evictionDuration.Seconds())

	evictionCandidates := make([]interface{}, 0)

	s.contextMap.Range(func(key, value interface{}) bool {
		contextData := value.(*ContextData)
		if contextData.prefixStore.lastAccess < expiredBefore {
			evictionCandidates = append(evictionCandidates, key)
		}
		return true
	})

	for _, key := range evictionCandidates {
		s.contextMap.Delete(key)
		s.contextCount.Add(-1)
	}
}

func (s *SyncPrefixTable) Close() {
	close(s.stopCh)
	s.wg.Wait()
	log.Info().Msg("[prefixcache] closed")
}

func (s *SyncPrefixTable) GetStats() PrefixCacheStats {
	stats := PrefixCacheStats{
		TotalContexts: s.contextCount.Load(),
	}

	s.contextMap.Range(func(key, value interface{}) bool {
		contextData := value.(*ContextData)
		stats.TotalPrefixes += contextData.prefixStore.totalPrefixes
		stats.TotalMappings += int64(len(contextData.hashMapping.engineToAigw))
		return true
	})

	return stats
}

func (s *SyncPrefixTable) AddPrefixFromTokenIDs(
	modelName string,
	loraID int64,
	instanceName string,
	tokenIDs []int64,
) error {
	prefixHashes := s.GetPrefixHashesFromTokenIDs(tokenIDs)
	if len(prefixHashes) == 0 {
		return nil
	}
	return s.AddPrefix(modelName, loraID, instanceName, prefixHashes)
}

func (s *SyncPrefixTable) MatchPrefixFromTokenIDs(
	modelName string,
	loraID int64,
	tokenIDs []int64,
	readyInstances map[string]struct{},
) (map[string]int, []uint64) {
	tokens := TokenIDsToBytes(tokenIDs)
	return s.MatchPrefix(modelName, loraID, tokens, readyInstances)
}

func (s *SyncPrefixTable) MatchPrefixByText(
	modelName string,
	loraID int64,
	promptText string,
	readyInstances map[string]struct{},
) (map[string]int, []uint64) {
	tokens := []byte(promptText)
	return s.MatchPrefix(modelName, loraID, tokens, readyInstances)
}

func (s *SyncPrefixTable) GetPrefixHashesByText(text string) []uint64 {
	return s.hasher.getPrefixHashes([]byte(text))
}
