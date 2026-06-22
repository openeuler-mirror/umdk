/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dispatching schedule request.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
)

const (
	emaWeight   float64 = 0.9
	defaultFreq int     = 1
)

// InstanceManager is the manager for instance
type InstanceManager struct {
	poolRWLock      sync.RWMutex
	insPool         map[string]*instance
	snapshotRWLock  sync.RWMutex
	insSnapshots    []*insSnapshot
	emaRWLock       sync.RWMutex
	emaPredictLen   map[RequestType]int // ema predicted length
	insWG           *sync.WaitGroup
	snapWG          *sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	insSnapShotFreq time.Duration
	insConnectType  string

	hmacMgr *crypto.HmacManager
	aesMgr  *crypto.AesManager

	cacheManager *cachecenter.CacheManager
	runtimeMode  base.RuntimeMode

	// DP (Data Parallel) support
	dpSize int // DP size for fine-grained load balancing

	// Skip instance connection for testing
	skipInstanceConnection bool
}

func newInstanceManager() *InstanceManager {
	ctx, cancel := context.WithCancel(context.Background())
	newManager := &InstanceManager{
		insPool:         make(map[string]*instance),
		emaPredictLen:   make(map[RequestType]int),
		insWG:           new(sync.WaitGroup),
		snapWG:          new(sync.WaitGroup),
		ctx:             ctx,
		cancel:          cancel,
		insSnapShotFreq: time.Duration(defaultFreq) * time.Second,
		hmacMgr:         crypto.NewHmacManager(nil),
		aesMgr:          crypto.NewAesManager(nil),
		insConnectType:  "sse",
	}
	return newManager
}

// NewInstanceManagerWithOptions creates new instance manager with options
func NewInstanceManagerWithOptions(cacheMgr *cachecenter.CacheManager,
	options ...instanceManagerOption) *InstanceManager {
	mgr := newInstanceManager()
	mgr.cacheManager = cacheMgr

	for _, opt := range options {
		opt(mgr)
	}

	return mgr
}

func (insManager *InstanceManager) addInstance(insUrl string, insRole base.InstanceRole, groupID string,
	statusChan chan *ControlMessage) error {
	newIns, err := newInstance(insUrl, insRole, groupID, statusChan, insManager)
	if err != nil {
		return err
	}
	insManager.poolRWLock.Lock()
	_, exists := insManager.insPool[insUrl]
	if exists {
		log.Error().Msgf("[instanceManager]instance %v already exists", insUrl)
		insManager.poolRWLock.Unlock()
		return fmt.Errorf("instance %v already exists", insUrl)
	} else {
		insManager.insPool[insUrl] = newIns
		insManager.poolRWLock.Unlock()
	}

	ok := insManager.startIns(newIns)
	if !ok {
		insManager.poolRWLock.Lock()
		delete(insManager.insPool, insUrl)
		insManager.poolRWLock.Unlock()
		return fmt.Errorf("instance %v start failed", insUrl)
	}

	log.Info().Msgf("[instanceManager]create instance %v success, the role is %v, the groupID is %v",
		insUrl, insRole, groupID)
	return nil
}

func (insManager *InstanceManager) startIns(ins *instance) bool {
	if !insManager.skipInstanceConnection {
		err := ins.connect() // connect to instance
		if err != nil {
			log.Error().Msgf("%v start error: %v", ins.insUrl, err)
			return false
		}
		insManager.insWG.Add(1)
		go ins.run(insManager.insWG) // start process connection loop
	} else {
		log.Info().Msgf("[instanceManager] skipping instance connection for %v (skipInstanceConnection=true)", ins.insUrl)
		// Don't start the run loop since there's no actual connection
		// The instance will be registered but won't process any messages
	}

	// Ensure instance metrics exist in cache manager so it's available for scheduling
	insManager.cacheManager.EnsureInstanceMetrics(ins.insUrl, ins.insRole, ins.groupID)
	log.Info().Msgf("[instanceManager] ensured metrics for instance %v (role=%v, groupID=%v)", ins.insUrl, ins.insRole, ins.groupID)
	return true
}

func (insManager *InstanceManager) removeInstance(insUrl string) bool {
	insManager.poolRWLock.Lock()
	defer insManager.poolRWLock.Unlock()

	if ins, exists := insManager.insPool[insUrl]; exists {
		ins.cancel()
		delete(insManager.insPool, insUrl)
		return true
	} else {
		log.Error().Msgf("[instanceManager]instance not exists: %v", insUrl)
		return false
	}
}

func (insManager *InstanceManager) updatePoolShot() {
	insManager.poolRWLock.RLock()
	instances := make([]*instance, 0, len(insManager.insPool))
	for _, ins := range insManager.insPool {
		instances = append(instances, ins)
	}
	insManager.poolRWLock.RUnlock()

	newInsSnapshots := make([]*insSnapshot, 0, len(instances))
	var snapshot *insSnapshot
	var instanceInfo *strings.Builder
	for _, ins := range instances {
		ins.rwLock.RLock()
		if ins.insWatcher == nil || ins.insWatcher.isHealth() {
			snapshot = ins.getSnapShot()
			newInsSnapshots = append(newInsSnapshots, snapshot)

			if instanceInfo == nil {
				instanceInfo = &strings.Builder{}
				instanceInfo.WriteString("[instanceManger] collected instance snapshots:\n")
			}
			_, _ = fmt.Fprintf(instanceInfo, " - insUrl=%v, role=%v, groupId=%v\n",
				snapshot.insUrl, snapshot.insRole.String(), snapshot.groupID)
		}
		ins.rwLock.RUnlock()
	}

	insManager.snapshotRWLock.Lock()
	insManager.insSnapshots = newInsSnapshots
	insManager.snapshotRWLock.Unlock()
	if instanceInfo != nil {
		log.Debug().Msg(instanceInfo.String())
	}

}

func (insManager *InstanceManager) snapShotLoop() {
	log.Info().Msgf("[instanceManager]start instance snapshots loop.")
	timer := time.NewTicker(insManager.insSnapShotFreq)
	defer insManager.snapWG.Done()
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			insManager.updatePoolShot()
		case <-insManager.ctx.Done():
			log.Info().Msgf("[instanceManager]end instance snapshots loop.")
			return
		}
	}

}

func (insManager *InstanceManager) getSpecifiedSnaps(role base.InstanceRole, targetGroupID string,
	excludeGroupId map[string]bool) []*insSnapshot {

	snapGroup := make([]*insSnapshot, 0)

	// First filter by targetGroupID or excludeGroupId to get candidate list
	candidates := insManager.insSnapshots
	if targetGroupID != "" {
		tempGroup := make([]*insSnapshot, 0)
		for _, snap := range insManager.insSnapshots {
			if snap.groupID == targetGroupID {
				tempGroup = append(tempGroup, snap)
			}
		}
		candidates = tempGroup
	} else if len(excludeGroupId) > 0 {
		tempGroup := make([]*insSnapshot, 0)
		for _, snap := range insManager.insSnapshots {
			if !excludeGroupId[snap.groupID] {
				tempGroup = append(tempGroup, snap)
			}
		}
		candidates = tempGroup
	}

	// Then filter by role
	// If role is invalidRoleInstance, it means any role is acceptable, return all candidates directly
	if role == base.InvalidRoleInstance {
		return candidates
	}

	// Otherwise, only return instances with the specified role
	for _, snap := range candidates {
		if snap.insRole == role {
			snapGroup = append(snapGroup, snap)
		}
	}

	return snapGroup
}

func (insManager *InstanceManager) addReq(insUrl string, req *LlmRequest) {
	insManager.poolRWLock.Lock()
	ins, exists := insManager.insPool[insUrl]
	if exists {
		// Release the pool lock before calling ins.addReq to reduce lock contention
		insManager.poolRWLock.Unlock()
		ins.addReq(req)
	} else {
		insManager.poolRWLock.Unlock()
		log.Error().Msgf("[instanceManager]Instance %v not in inspool when schedule.", insUrl)
	}
}

// AddReqToCache adds schedule result to cache
func (insManager *InstanceManager) AddReqToCache(req *LlmRequest, res *ScheduleResult) error {
	if err := insManager.cacheManager.AddRequest(&cachecenter.RequestInfo{
		ReqId:              req.ReqId,
		PrefillInstance:    res.PrefillUrl,
		DecodeInstance:     res.DecodeUrl,
		IsPrefill:          true,
		PromptTokenLen:     req.PromptLen,
		DecodeTokenLen:     req.PredictDecodeLen,
		PredictPrefillTime: req.PredictPrefillTime,
		PrefillStartTimeMs: req.PrefillTimeStampMs,
		TimeStamp:          req.TimeStamp,
	}); err != nil {
		return fmt.Errorf("failed to add request to cache, err: %v", err)
	}

	return nil
}

func (insManager *InstanceManager) start() {
	if insManager.runtimeMode == base.SdkMode {
		log.Info().Msgf("[instanceManager]sdk mode disable snapShot loop.")
		return
	}
	insManager.snapWG.Add(1)
	go insManager.snapShotLoop()
}

func (insManager *InstanceManager) stop() {
	insManager.cancel()
	insManager.snapWG.Wait()
	log.Info().Msgf("[instanceManager]end instance snapshots loop.")

	insManager.poolRWLock.Lock()
	log.Info().Msgf("[instanceManager]start to delete instance pool.")
	for _, ins := range insManager.insPool {
		if ins.cancel != nil {
			ins.cancel()
		}
	}
	insManager.insWG.Wait()
	insManager.poolRWLock.Unlock()
	log.Info().Msgf("[instanceManager]delete instance pool completed.")
}

func (insManager *InstanceManager) updateEmaPredictLen(reqType RequestType, decodeLen int) {
	var predictLen int
	insManager.emaRWLock.Lock()
	if historyDecodeLen, exists := insManager.emaPredictLen[reqType]; !exists {
		predictLen = decodeLen
		insManager.emaPredictLen[reqType] = decodeLen
	} else {
		predictLen = int(math.Round(emaWeight*float64(decodeLen) + (1-emaWeight)*float64(historyDecodeLen)))
		insManager.emaPredictLen[reqType] = predictLen
	}
	insManager.emaRWLock.Unlock()
	log.Debug().Msgf("[instanceManager]update reqType: %d ema predict decode len: %d", reqType, predictLen)
}

func (insManager *InstanceManager) predictTokensByEMA(req *LlmRequest) int {
	insManager.emaRWLock.Lock()
	decodeLen, exists := insManager.emaPredictLen[req.ReqType]
	insManager.emaRWLock.Unlock()
	if !exists {
		return req.PromptLen
	}
	return req.PromptLen + decodeLen
}

func (insManager *InstanceManager) isReqExists(reqId string) bool {
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()

	for _, ins := range insManager.insPool {
		_, exists := ins.reqSet[reqId]
		if exists {
			return true
		}
	}
	return false
}

func (insManager *InstanceManager) getInsNum() int {
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()

	return len(insManager.insPool)
}

func (insManager *InstanceManager) checkReqSurvival(duration time.Duration) {
	now := time.Now()
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()
	for _, ins := range insManager.insPool {
		var toDel []*LlmRequest
		ins.rwLock.RLock()
		for _, req := range ins.reqSet {
			if now.Sub(time.UnixMilli(req.TimeStamp)) > duration {
				toDel = append(toDel, req)
				log.Warn().Msgf("[gs]the req %v is deleted due to timeout", req.ReqId)
			}
		}
		ins.rwLock.RUnlock()
		for _, r := range toDel {
			ins.delReq(r, false)
		}
	}
}

func (insManager *InstanceManager) loadInsFromCache(instances []*RegisterInstanceMsg) {
	if insManager.cacheManager == nil {
		log.Error().Msgf("Failed to load instance from cache, cache manager is nil")
		return
	}

	idToGroup := func(insList []*RegisterInstanceMsg) map[string]string {
		m := make(map[string]string)
		for _, ins := range insList {
			instanceId := base.BuildInstanceAddress(ins.IP, ins.Port, ins.DpRank)
			m[instanceId] = ins.GroupID
		}
		return m
	}

	idMap := idToGroup(instances)

	insManager.poolRWLock.Lock()
	defer insManager.poolRWLock.Unlock()

	// clean up old instances that don't exist in the new instance list first
	for instanceId := range insManager.insPool {
		if _, exists := idMap[instanceId]; !exists {
			delete(insManager.insPool, instanceId)
		}
	}

	metrics := make(map[string]*cachecenter.InstanceMetrics)
	insManager.cacheManager.RangeMetrics(func(insId string, metric *cachecenter.InstanceMetrics) bool {
		metrics[insId] = metric
		return true
	})

	for _, ins := range instances {
		role, _ := base.ToInstanceRole(ins.Role)
		instanceId := base.BuildInstanceAddress(ins.IP, ins.Port, ins.DpRank)
		if _, exists := insManager.insPool[instanceId]; !exists {
			insManager.insPool[instanceId] = &instance{
				insUrl:      instanceId,
				headReq:     nil,
				insRole:     role,
				tokenNum:    0,
				prefillTime: 0.0,
				freeBlocks:  math.MaxInt,
				tbt:         math.Inf(-1),
				ttft:        math.Inf(-1),
				groupID:     ins.GroupID,
			}
		}
		ins := insManager.insPool[instanceId]
		if metric, exists := metrics[instanceId]; exists {
			var headReq *LlmRequest
			if metric == nil {
				log.Error().Msgf("instance %v metric from cache is nil.", instanceId)
			}
			metricCopy := metric.Copy()
			if metricCopy.HeadReq != nil {
				headReq = &LlmRequest{
					ReqId:              metricCopy.HeadReq.ReqId,
					PredictPrefillTime: metricCopy.HeadReq.PredictPrefillTime,
					PrefillTimeStampMs: metricCopy.HeadReq.PrefillStartTimeMs,
				}
			}

			// update instance metric from cache
			ins.tokenNum = metricCopy.TokenLoad
			ins.prefillTime = metricCopy.QueueTime
			ins.headReq = headReq

		} else {
			// if not exist in remote db.
			ins.tokenNum = 0
			ins.prefillTime = 0
			ins.headReq = nil
		}
	}
}

// SetDpSize sets the DP size for fine-grained load balancing.
// DP size determines how many virtual DP-aware workers are created per physical worker.
func (insManager *InstanceManager) SetDpSize(dpSize int) {
	insManager.poolRWLock.Lock()
	defer insManager.poolRWLock.Unlock()
	insManager.dpSize = dpSize
}

// GetDpSize returns the current DP size.
func (insManager *InstanceManager) GetDpSize() int {
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()
	return insManager.dpSize
}

// GetDPAwareWorkers returns all DP-aware workers for the specified role.
// Each physical instance is expanded into dpSize DP-aware workers.
func (insManager *InstanceManager) GetDPAwareWorkers(role base.InstanceRole) []*DPAwareWorker {
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()

	var workers []*DPAwareWorker
	for _, ins := range insManager.insPool {
		if ins.insRole == role || role == base.InvalidRoleInstance {
			// Create dpSize DP-aware workers for each physical instance
			for rank := 0; rank < insManager.dpSize; rank++ {
				dw := &DPAwareWorker{
					BaseURL: ins.insUrl,
					DpRank:  rank,
					DpSize:  insManager.dpSize,
					InsRole: ins.insRole,
					GroupID: ins.groupID,
				}
				workers = append(workers, dw)
			}
		}
	}
	return workers
}

// GetDPAwareSnapshot returns DP-aware snapshots for the specified role.
// Each physical instance snapshot is expanded into dpSize DP-aware snapshots.
func (insManager *InstanceManager) GetDPAwareSnapshot(role base.InstanceRole) []*DPAwareSnapshot {
	insManager.snapshotRWLock.RLock()
	defer insManager.snapshotRWLock.RUnlock()

	var snapshots []*DPAwareSnapshot
	for _, snap := range insManager.insSnapshots {
		if snap.insRole == role || role == base.InvalidRoleInstance {
			for rank := 0; rank < insManager.dpSize; rank++ {
				dpSnap := &DPAwareSnapshot{
					InsUrl:     fmt.Sprintf("%s@%d", snap.insUrl, rank),
					BaseURL:    snap.insUrl,
					DpRank:     rank,
					DpSize:     insManager.dpSize,
					FreeBlocks: snap.freeBlocks,
					TokenNum:   snap.tokenNum,
					TBT:        snap.tbt,
					TTFT:       snap.ttft,
					InsRole:    snap.insRole,
					GroupID:    snap.groupID,
				}
				snapshots = append(snapshots, dpSnap)
			}
		}
	}
	return snapshots
}
