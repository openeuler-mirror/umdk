/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: define the functions of central cache.
 * Create: 2026-01-20
 */

// Package cachecenter provides functions of cachecenter for AIGW.
package cachecenter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

const (
	defaultRefreshInterval = 100 * time.Millisecond
	syncChanBuffer         = 2048
	syncWriteChanTimeout   = 50 * time.Millisecond
	stopWaitTimeout        = 5 * time.Second
	tombstoneTTL           = 60 * time.Second
	metricTTL              = 60 * time.Second // metric TTL
)

// timeNow returns current time in nanoseconds for version tracking
var timeNow = time.Now

// CacheManager manages cache operations
type CacheManager struct {
	modelName string
	cache     *localCache
	syncCh    chan *syncTask

	remoteCache CentralCache

	wg     *sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	refreshInterval time.Duration
	reqTtl          time.Duration // request survival duration
	activeInstances sync.Map      // instanceID -> bool
	deletedReqs     sync.Map      // map[string]DeletedRequest - tombstone set
}

// NewCacheManager creates a new cache manager
func NewCacheManager(parentCtx context.Context, modelName string, opts ...ManagerOption) *CacheManager {
	cm := &CacheManager{
		modelName: modelName,
		cache:     newLocalCache(),
		syncCh:    make(chan *syncTask, syncChanBuffer),
		wg:        new(sync.WaitGroup),

		refreshInterval: defaultRefreshInterval,
	}
	cm.ctx, cm.cancel = context.WithCancel(parentCtx)

	for _, opt := range opts {
		opt(cm)
	}
	return cm
}

// Start cache manager sync loop
func (cm *CacheManager) Start() {
	log.Info().Msg("start cache manager")
	cm.wg.Add(1)
	go cm.syncLoop()
}

// Stop cache manager
func (cm *CacheManager) Stop() {
	log.Info().Msg("stopping cache manager...")
	cm.cancel()

	done := make(chan struct{})
	go func() {
		cm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("cache manager stopped gracefully")
	case <-time.After(stopWaitTimeout):
		log.Warn().Msgf("cache manager stop timeout after %v", stopWaitTimeout)
	}
}

// RangeMetrics iterates over all metrics with a callback function
func (cm *CacheManager) RangeMetrics(fn func(instanceID string, metric *InstanceMetrics) bool) {
	cache := cm.cache.holder.Load()
	if cache == nil {
		log.Error().Msgf("[CacheManager] RangeMetrics: cache is nil")
		return
	}
	count := 0
	cache.metrics.Range(func(key, value interface{}) bool {
		instanceID, ok := key.(string)
		if !ok {
			log.Error().Msgf("invalid instance id type: %v", key)
			return true
		}
		metric, ok := value.(*InstanceMetrics)
		if !ok || metric == nil {
			log.Error().Msgf("invalid instance metric type: %v", value)
			return true
		}
		count++
		return fn(instanceID, metric)
	})
	log.Info().Msgf("[CacheManager] RangeMetrics: iterated %d instances in cache", count)
}

// EnsureInstanceMetrics ensures instance metrics exist in cache
// This is useful for SDK mode where instances are provided directly
func (cm *CacheManager) EnsureInstanceMetrics(instanceID string, role base.InstanceRole, groupID string) {
	cache := cm.cache.holder.Load()
	if cache == nil {
		log.Warn().Msgf("[CacheManager] EnsureInstanceMetrics: cache is nil for instance %s", instanceID)
		return
	}

	now := timeNow()
	// Initialize metrics if not exists
	cache.metrics.LoadOrStore(instanceID, &InstanceMetrics{
		Role:           role,
		GroupID:        groupID,
		TokenLoad:      0,
		QueueTime:      0,
		HeadReq:        nil,
		LastActiveTime: now,
	})

	// Add to activeInstances to ensure rebuildCache can update this instance
	cm.activeInstances.Store(instanceID, true)
	log.Info().Msgf("[CacheManager] EnsureInstanceMetrics: added instance %s (role=%v, groupID=%s)", instanceID, role, groupID)
}

// AddRequest add request to local cache and remote db
func (cm *CacheManager) AddRequest(info *RequestInfo) error {
	if info == nil {
		return fmt.Errorf("add request failed: info is nil")
	}
	if info.ReqId == "" {
		return fmt.Errorf("add request failed: ReqId is empty")
	}
	cache := cm.cache.holder.Load()
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}
	// update local cache
	copyInfo := *info
	copyInfo.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
	cache.requestMap.Store(info.ReqId, &copyInfo)
	instances := []string{info.PrefillInstance, info.DecodeInstance}
	for _, ins := range instances {
		if ins == "" {
			continue
		}

		role := base.PrefillRoleInstance
		if ins == info.DecodeInstance {
			role = base.DecodeRoleInstance
		}

		value, _ := cache.metrics.LoadOrStore(ins, &InstanceMetrics{
			Role:      role,
			GroupID:   info.GroupID,
			TokenLoad: 0,
			QueueTime: 0,
			HeadReq:   nil,
		})

		metric, ok := value.(*InstanceMetrics)
		if !ok || metric == nil {
			return fmt.Errorf("invalid instance metric type: %v", value)
		}

		now := timeNow()
		headReq := cm.getHeadReq(ins, "")
		metric.updateMetric(func() {
			metric.LastActiveTime = now
			if metric.Role != base.PrefillRoleInstance {
				metric.TokenLoad += info.PromptTokenLen + info.DecodeTokenLen
				return
			}

			metric.TokenLoad += info.PromptTokenLen
			metric.QueueTime += info.PredictPrefillTime
			if metric.HeadReq == nil {
				metric.HeadReq = headReq
			}
		})
	}

	// Record active instances
	cm.activeInstances.Store(info.PrefillInstance, true)

	// Async sync to remote - store in prefill instance's key
	instanceID := info.PrefillInstance

	cm.sendTask(&syncTask{
		TaskType:   TaskAddRequest,
		ModelName:  cm.modelName,
		InstanceID: instanceID,
		Info:       []*RequestInfo{&copyInfo},
	})
	return nil
}

// RemoveRequest removes a request by ID from cache and syncs deletion
func (cm *CacheManager) RemoveRequest(reqID string) error {
	cache := cm.cache.holder.Load()
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}
	value, exists := cache.requestMap.LoadAndDelete(reqID)
	if !exists {
		return fmt.Errorf("request %v not found", reqID)
	}

	req, ok := value.(*RequestInfo)
	if !ok || req == nil {
		return fmt.Errorf("invalid request info type: %v", value)
	}

	// Add to tombstone set to prevent resurrection from Redis
	cm.deletedReqs.Store(reqID, DeletedRequest{DeletedAt: timeNow().UnixNano()})

	// update metrics
	instances := []string{req.PrefillInstance, req.DecodeInstance}
	for _, ins := range instances {
		if ins == "" {
			continue
		}
		if value, ok := cache.metrics.Load(ins); ok {
			metric, ok := value.(*InstanceMetrics)
			if !ok || metric == nil {
				log.Error().Msgf("invalid instance metric type: %v", value)
				continue
			}

			headReq := cm.getHeadReq(ins, reqID)
			metric.updateMetric(func() {
				if metric.Role != base.PrefillRoleInstance {
					metric.TokenLoad -= req.PromptTokenLen + req.DecodeTokenLen
					if metric.TokenLoad < 0 {
						metric.TokenLoad = 0
					}
					return
				}

				metric.TokenLoad -= req.PromptTokenLen
				metric.QueueTime -= req.PredictPrefillTime
				if metric.TokenLoad < 0 {
					metric.TokenLoad = 0
				}
				if metric.QueueTime < 0 {
					metric.QueueTime = 0
				}
				if metric.HeadReq != nil && metric.HeadReq.ReqId == reqID {
					metric.HeadReq = headReq
				}
			})
		}
	}

	// Async notify Redis to delete - use prefill instance's key
	instanceID := req.PrefillInstance

	cm.sendTask(&syncTask{
		TaskType:   TaskDeleteRequest,
		ModelName:  cm.modelName,
		InstanceID: instanceID,
		Info:       []*RequestInfo{req},
	})
	return nil
}

// UpdateRequestOnPrefillFinished updates request status when prefill is finished and triggers next request
func (cm *CacheManager) UpdateRequestOnPrefillFinished(reqID string) error {
	cache := cm.cache.holder.Load()
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}

	// Get current request
	value, exists := cache.requestMap.Load(reqID)
	if !exists {
		return fmt.Errorf("request %v not found", reqID)
	}

	req, ok := value.(*RequestInfo)
	if !ok || req == nil {
		return fmt.Errorf("invalid request info type %v", value)
	}

	prefillIns := req.PrefillInstance
	if prefillIns == "" {
		return fmt.Errorf("req %v prefillInstance is empty, no need to update", reqID)
	}

	// Get prefill instance metrics
	value, ok = cache.metrics.Load(prefillIns)
	if !ok {
		return fmt.Errorf("instance %v metric does not exist in local cache, request %v",
			prefillIns, reqID)
	}

	metric, ok := value.(*InstanceMetrics)
	if !ok || metric == nil {
		return fmt.Errorf("invalid instance metric type: %v", value)
	}

	// Clear prefill instance for current request and find next head
	nextHead := cm.getHeadReq(prefillIns, reqID)
	req.IsPrefill = false
	updatedCurrent := *req
	updatedCurrent.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
	// Prepare update task
	updates := []*RequestInfo{&updatedCurrent}

	if nextHead != nil {
		nextHead.PrefillStartTimeMs = time.Now().UnixMilli()
		updatedNext := *nextHead
		updatedNext.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
		updates = append(updates, &updatedNext)
	}

	// Update metrics
	metric.updateMetric(func() {
		metric.TokenLoad -= req.PromptTokenLen + req.DecodeTokenLen
		metric.QueueTime -= req.PredictPrefillTime
		metric.HeadReq = nextHead
	})

	// Send sync task
	// Record active instance
	cm.activeInstances.Store(prefillIns, true)

	cm.sendTask(&syncTask{
		TaskType:   TaskUpdateRequest,
		ModelName:  cm.modelName,
		InstanceID: prefillIns,
		Info:       updates,
	})

	return nil
}

// sendTask sends a task to the sync channel.
func (cm *CacheManager) sendTask(task *syncTask) {
	if cm.remoteCache == nil {
		log.Debug().Msg("remote cache is nil, skip sending task")
		return
	}

	select {
	case cm.syncCh <- task:
		log.Debug().Msgf("task sent successfully: %v", task)
	case <-time.After(syncWriteChanTimeout):
		// Channel is full, drop oldest task
		dropped := <-cm.syncCh
		cm.syncCh <- task
		log.Warn().Msgf("sync channel full, dropped task %v for new task %v",
			dropped, task)
	}
}

// getHeadReq is lock-free method, caller must ensure concurrency safety
func (cm *CacheManager) getHeadReq(instanceID string, currentHead string) *RequestInfo {
	cache := cm.cache.holder.Load()
	if cache == nil {
		log.Error().Msgf("cache is nil")
		return nil
	}

	var head *RequestInfo
	var keysToDelete []interface{}

	cache.requestMap.Range(func(key, value interface{}) bool {
		req, ok := value.(*RequestInfo)
		if !ok || req == nil {
			log.Warn().Msgf("invalid request info: %v", value)
			keysToDelete = append(keysToDelete, key)
			return true
		}

		if req.PrefillInstance == instanceID &&
			req.PrefillInstance != "" &&
			req.ReqId != currentHead {
			if head == nil || req.TimeStamp < head.TimeStamp {
				head = req
			}
		}
		return true
	})

	if len(keysToDelete) > 0 {
		for _, key := range keysToDelete {
			cache.requestMap.Delete(key)
		}
		log.Debug().Msgf("deleted %d invalid requests", len(keysToDelete))
	}

	return head
}

// getLocalRequests returns a snapshot of all requests currently in local cache.
// This is used during incremental merge to preserve local updates that haven't
// been synced to Redis yet.
func (cm *CacheManager) getLocalRequests() map[string]*RequestInfo {
	localRequests := make(map[string]*RequestInfo)
	cache := cm.cache.holder.Load()
	if cache == nil {
		return localRequests
	}

	cache.requestMap.Range(func(key, value interface{}) bool {
		reqID, ok := key.(string)
		if !ok {
			return true
		}
		req, ok := value.(*RequestInfo)
		if !ok || req == nil {
			return true
		}
		// Store a copy to avoid concurrent modification issues
		reqCopy := *req
		localRequests[reqID] = &reqCopy
		return true
	})
	return localRequests
}

// mergeRequests merges Redis data with local data using version timestamps.
// For each request ID, the version with larger LastModifiedTime wins.
// This ensures local updates that haven't been synced to Redis are preserved.
func mergeRequests(redisData, localData map[string]*RequestInfo) []*RequestInfo {
	result := make(map[string]*RequestInfo)

	// First, add all Redis data
	for reqID, req := range redisData {
		result[reqID] = req
	}

	// Then, overlay with local data (local data is newer if timestamp differs)
	for reqID, localReq := range localData {
		if existing, ok := result[reqID]; !ok {
			// Request only exists locally (not in Redis yet)
			result[reqID] = localReq
		} else if localReq.LastModifiedTime >= existing.LastModifiedTime {
			// Local version is newer
			result[reqID] = localReq
		}
	}

	// Convert to slice
	requests := make([]*RequestInfo, 0, len(result))
	for _, req := range result {
		requests = append(requests, req)
	}
	return requests
}

// cleanupTombstones removes expired tombstones and filters tombstoned requests from redisMap
func (cm *CacheManager) cleanupTombstones(redisMap map[string]*RequestInfo) {
	cm.deletedReqs.Range(func(key, value interface{}) bool {
		reqID, ok := key.(string)
		if !ok {
			return true
		}
		dr, ok := value.(DeletedRequest)
		if !ok {
			return true
		}
		if timeNow().Sub(time.Unix(0, dr.DeletedAt)) > tombstoneTTL {
			cm.deletedReqs.Delete(key)
		} else {
			delete(redisMap, reqID)
		}
		return true
	})
}

// rebuildCache fetches data from remote db and rebuilds local cache
// with incremental merge to preserve local updates that haven't been synced yet.
func (cm *CacheManager) rebuildCache() error {
	start := time.Now()

	// Get all instance IDs from local cache metrics
	var instanceIDs []string
	cm.activeInstances.Range(func(key, value interface{}) bool {
		instanceID, ok := key.(string)
		if !ok {
			return true
		}
		instanceIDs = append(instanceIDs, instanceID)
		return true
	})

	// Use new instance-based format to fetch all requests
	instanceRequests, err := cm.remoteCache.FetchAllInstanceRequests(cm.modelName, instanceIDs)
	if err != nil {
		return fmt.Errorf("failed to fetch all instance requests for model %s: %w", cm.modelName, err)
	}

	// Merge all instance requests into a single map
	hashData := make(map[string]string)
	for _, requests := range instanceRequests {
		for reqID, jsonStr := range requests {
			hashData[reqID] = jsonStr
		}
	}

	// parse Redis data into RequestInfo list
	redisRequests, expiredRequests := parseRequests(hashData, cm.reqTtl)
	redisMap := make(map[string]*RequestInfo)
	for _, req := range redisRequests {
		redisMap[req.ReqId] = req
	}

	// Get local requests for incremental merge
	localRequests := cm.getLocalRequests()

	// Clean up expired tombstones and filter tombstoned requests from Redis
	cm.cleanupTombstones(redisMap)

	// Merge Redis data with local data, preferring newer version
	mergedRequests := mergeRequests(redisMap, localRequests)
	cm.cache.incrementalMerge(mergedRequests)
	log.Debug().Msgf("model %v rebuild metrics from cache cost %v, merged %d local + %d redis = %d total",
		cm.modelName, time.Since(start), len(localRequests), len(redisRequests), len(mergedRequests))

	// update activeInstance
	var deletedInstances []string

	// Build a set of instance IDs that have at least one local request.
	// This prevents deleting activeInstances when local requests exist but
	// sync to Redis has not completed yet.
	localInstanceSet := make(map[string]bool, len(localRequests))
	for _, req := range localRequests {
		if req.PrefillInstance != "" {
			localInstanceSet[req.PrefillInstance] = true
		}
	}

	cm.activeInstances.Range(func(key, value interface{}) bool {
		instanceID, ok := key.(string)
		if !ok {
			return true
		}
		if _, exists := instanceRequests[instanceID]; exists {
			return true
		}
		if localInstanceSet[instanceID] {
			return true
		}

		cm.activeInstances.Delete(instanceID)
		deletedInstances = append(deletedInstances, instanceID)
		return true
	})
	if len(deletedInstances) > 0 {
		log.Debug().Msgf("removed inactive instances: %v", len(deletedInstances))
	}

	// Send async delete tasks for expired requests
	if len(expiredRequests) > 0 {
		for instanceID, reqInfos := range expiredRequests {
			cm.sendTask(&syncTask{
				TaskType:   TaskDeleteRequest,
				ModelName:  cm.modelName,
				InstanceID: instanceID,
				Info:       reqInfos,
			})
		}
		log.Debug().Msgf("sent %d expired requests for async deletion", len(expiredRequests))
	}

	// Age out metrics that have been inactive for too long
	now := timeNow()
	var agedOutCount int
	cm.RangeMetrics(func(instanceID string, metric *InstanceMetrics) bool {
		if now.Sub(metric.LastActiveTime) > metricTTL {
			cache := cm.cache.holder.Load()
			if cache != nil {
				cache.metrics.Delete(instanceID)
			}
			cm.activeInstances.Delete(instanceID)
			agedOutCount++
		}
		return true
	})
	if agedOutCount > 0 {
		log.Debug().Msgf("aged out %d inactive metrics", agedOutCount)
	}

	return nil
}

// parseRequests converts Redis hash (requestID -> JSON) into []*RequestInfo
// and returns expired requests separately
func parseRequests(hash map[string]string, ttlMs time.Duration) ([]*RequestInfo, map[string][]*RequestInfo) {
	var requests []*RequestInfo
	expiredRequests := make(map[string][]*RequestInfo) // key: instanceId ; value: []*RequestInfos
	now := time.Now()

	for reqID, jsonStr := range hash {
		jsonStr = strings.TrimSpace(jsonStr)
		if jsonStr == "" {
			continue
		}
		var req RequestInfo
		req.ReqId = reqID
		if err := json.Unmarshal([]byte(jsonStr), &req); err != nil {
			log.Warn().Msgf("failed to unmarshal JSON for request %v, %v", reqID, err)
			continue
		}

		// Check if request is expired
		if now.Sub(time.UnixMilli(req.TimeStamp)) > ttlMs {
			expiredRequests[req.PrefillInstance] = append(expiredRequests[req.PrefillInstance], &req)
		} else {
			requests = append(requests, &req)
		}
	}
	return requests, expiredRequests
}

// syncLoop processes tasks from syncCh and syncs with remote db
func (cm *CacheManager) syncLoop() {
	defer cm.wg.Done()
	if cm.remoteCache == nil {
		log.Info().Msgf("remote cache is disabled, so do not start sync loop")
		return
	}

	ticker := time.NewTicker(cm.refreshInterval)
	defer ticker.Stop()

	// rebuild cache from remote firstly
	go func() {
		if err := cm.rebuildCache(); err != nil {
			log.Warn().Msgf("init local cache from remote failed, %v", err)
		}
	}()

	for {
		select {
		case task := <-cm.syncCh:
			cm.handleTask(task)
		case <-ticker.C:
			err := cm.rebuildCache()
			if err != nil {
				log.Error().Err(err).Msg("periodic rebuild cache failed")
			}
		case <-cm.ctx.Done():
			log.Info().Msg("sync loop cancelled")
			return
		}
	}
}

func (cm *CacheManager) handleTask(task *syncTask) {
	var err error
	log.Debug().Msgf("handle task %v", task)
	switch task.TaskType {
	case TaskAddRequest:
		err = cm.remoteCache.AddRequest(task.ModelName, task.InstanceID, task.Info)
	case TaskDeleteRequest:
		err = cm.remoteCache.RemoveRequest(task.ModelName, task.InstanceID, task.Info)
	case TaskUpdateRequest:
		err = cm.remoteCache.UpdateRequest(task.ModelName, task.InstanceID, task.Info)
	default:
		err = fmt.Errorf("unknown task type: %v", task.TaskType)
	}
	if err != nil {
		log.Error().Msgf("handle task failed, err: %v, task: %v", err, task)
	}
}
