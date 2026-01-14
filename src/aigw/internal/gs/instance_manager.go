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

	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
)

const (
	emaWeight   float64 = 0.9
	defaultFreq int     = 1
)

type instanceManager struct {
	poolRWLock      sync.RWMutex
	insPool         map[string]*instance
	snapshotRWLock  sync.RWMutex
	insSnapshots    []*insSnapshot
	emaRWLock       sync.RWMutex
	emaPredictLen   map[requestType]int // ema predicted length
	insWG           *sync.WaitGroup
	snapWG          *sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	insSnapShotFreq time.Duration
	insConnectType  string

	hmacMgr *crypto.HmacManager
	aesMgr  *crypto.AesManager
}

func newInstanceManager() *instanceManager {
	ctx, cancel := context.WithCancel(context.Background())
	newManager := &instanceManager{
		insPool:         make(map[string]*instance),
		emaPredictLen:   make(map[requestType]int),
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

func (insManager *instanceManager) addInstance(insUrl string, insRole instanceRole, groupID string,
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

func (insManager *instanceManager) startIns(ins *instance) bool {
	err := ins.connect() // connect to instance
	if err != nil {
		log.Error().Msgf("%v start error: %v", ins.insUrl, err)
		return false
	}
	insManager.insWG.Add(1)
	go ins.run(insManager.insWG) // start process connection loop
	return true
}

func (insManager *instanceManager) removeInstance(insUrl string) bool {
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

func (insManager *instanceManager) updatePoolShot() {
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

func (insManager *instanceManager) snapShotLoop() {
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

func (insManager *instanceManager) getSnapByGroupID(targetGroupID string,
	excludeGroupId map[string]bool) []*insSnapshot {
	snapGroup := make([]*insSnapshot, 0)
	if targetGroupID != "" {
		for _, snap := range insManager.insSnapshots {
			if snap.groupID == targetGroupID {
				snapGroup = append(snapGroup, snap)
			}
		}
		return snapGroup
	}
	if len(excludeGroupId) == 0 {
		return insManager.insSnapshots
	}
	for _, snap := range insManager.insSnapshots {
		if !excludeGroupId[snap.groupID] {
			snapGroup = append(snapGroup, snap)
		}
	}
	return snapGroup
}

func (insManager *instanceManager) addReq(insUrl string, req *LlmRequest) {
	insManager.poolRWLock.Lock()
	defer insManager.poolRWLock.Unlock()
	ins, exists := insManager.insPool[insUrl]
	if exists {
		ins.addReq(req)
	} else {
		log.Error().Msgf("[instanceManager]Instance %v not in inspool when schedule.", insUrl)
	}
}

func (insManager *instanceManager) start() {
	insManager.snapWG.Add(1)
	go insManager.snapShotLoop()
}

func (insManager *instanceManager) stop() {
	insManager.cancel()
	insManager.snapWG.Wait()
	log.Info().Msgf("[instanceManager]end instance snapshots loop.")

	insManager.poolRWLock.Lock()
	log.Info().Msgf("[instanceManager]start to delete instance pool.")
	for _, ins := range insManager.insPool {
		ins.cancel()
	}
	insManager.insWG.Wait()
	insManager.poolRWLock.Unlock()
	log.Info().Msgf("[instanceManager]delete instance pool completed.")
}

func (insManager *instanceManager) updateEmaPredictLen(reqType requestType, decodeLen int) {
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

func (insManager *instanceManager) predictTokensByEMA(req *LlmRequest) int {
	insManager.emaRWLock.Lock()
	decodeLen, exists := insManager.emaPredictLen[req.reqType]
	insManager.emaRWLock.Unlock()
	if !exists {
		return req.promptLen
	}
	return req.promptLen + decodeLen
}

func (insManager *instanceManager) isReqExists(reqId string) bool {
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

func (insManager *instanceManager) getInsNum() int {
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()

	return len(insManager.insPool)
}

func (insManager *instanceManager) checkReqSurvival(duration int64) {
	now := time.Now().UTC().Unix()
	insManager.poolRWLock.RLock()
	defer insManager.poolRWLock.RUnlock()
	for _, ins := range insManager.insPool {
		var toDel []*LlmRequest
		ins.rwLock.RLock()
		for _, req := range ins.reqSet {
			if now-req.timeStamp > duration {
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
