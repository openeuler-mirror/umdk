/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: inference instance management.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

type instanceRole int

const (
	mixedRoleInstance instanceRole = iota
	prefillRoleInstance
	decodeRoleInstance
	invalidRoleInstance
)

var roleToString = map[instanceRole]string{
	mixedRoleInstance:   "mixed",
	prefillRoleInstance: "prefill",
	decodeRoleInstance:  "decode",
}

var stringToRole = map[string]instanceRole{
	"mixed":   mixedRoleInstance,
	"prefill": prefillRoleInstance,
	"decode":  decodeRoleInstance,
}

func (r instanceRole) String() string {
	if s, ok := roleToString[r]; ok {
		return s
	}
	return "invalid"
}

func toInstanceRole(s string) (instanceRole, error) {
	if role, ok := stringToRole[s]; ok {
		return role, nil
	}
	return invalidRoleInstance, fmt.Errorf("%s is not a valid instance role", s)
}

type instance struct {
	insMgr         *instanceManager
	insUrl         string
	freeBlocks     int
	reqSet         map[string]*LlmRequest // record requests on the instance. k is the request ID. v is llmRequest
	prefillTokens  int
	reqNum         int
	preloadMap     map[string]int // record the forward load of each request in this instance
	tokenNum       int            // record the total number of forward tokens
	preBlocks      int            // record the total forward load
	ttft           float64        // ms
	tbt            float64        // ms
	queueLength    int            // waiting request num
	avgWaitingTime float64        // average wait time
	insRole        instanceRole
	groupID        string

	reqStatusChan chan *ControlMessage // pass prompt token to GS
	ctx           context.Context
	cancel        context.CancelFunc
	rwLock        sync.RWMutex
	insWg         *sync.WaitGroup
	insWatcher    instanceWatcher
	msgChan       chan string
}

type insSnapshot struct {
	insUrl         string
	prefillTokens  int
	freeBlocks     int
	preBlocks      int
	tokenNum       int
	ttft           float64
	tbt            float64
	queueLength    int
	avgWaitingTime float64
	reqNum         int
	insRole        instanceRole
	groupID        string
}

func (ins *instance) addReq(req *LlmRequest) {
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	ins.reqSet[req.ReqId] = req
	ins.reqNum += 1
	ins.tokenNum += req.predictTokens
	ins.prefillTokens += req.promptLen
	if ins.insRole == decodeRoleInstance {
		ins.preloadMap[req.ReqId] = req.predictBlocks
		ins.preBlocks += req.predictBlocks
	} else {
		ins.freeBlocks -= req.predictBlocks
	}
}

func (ins *instance) delReq(inReq *LlmRequest, withDraw bool) {
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	req, exists := ins.reqSet[inReq.ReqId]
	if !exists {
		log.Debug().Msgf("[instance]req %v is not in this ins", inReq.ReqId)
		return
	}
	ins.tokenNum -= req.predictTokens
	ins.prefillTokens -= req.promptLen
	if withDraw {
		ins.freeBlocks += req.predictBlocks
	}
	delete(ins.reqSet, req.ReqId)
	ins.reqNum -= 1
	_, exists = ins.preloadMap[req.ReqId]
	if exists && ins.insRole == decodeRoleInstance {
		ins.preBlocks -= req.predictBlocks
		delete(ins.preloadMap, req.ReqId)
	}
}

func newInstance(insUrl string, insRole instanceRole, groupID string, reqStatusChan chan *ControlMessage,
	insMgr *instanceManager) (*instance, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ins := &instance{
		insMgr:         insMgr,
		insUrl:         insUrl,
		freeBlocks:     0,
		preloadMap:     make(map[string]int),
		preBlocks:      0,
		tokenNum:       0,
		reqSet:         make(map[string]*LlmRequest),
		ttft:           0.0,
		tbt:            0.0,
		queueLength:    0,
		avgWaitingTime: 0.0,
		insRole:        insRole,
		ctx:            ctx,
		cancel:         cancel,
		reqStatusChan:  reqStatusChan,
		insWg:          new(sync.WaitGroup),
		msgChan:        make(chan string, chanBufferSize),
		groupID:        groupID,
	}
	var err error
	ins.insWatcher, err = ins.createWatcher()
	if err != nil {
		return nil, err
	}
	return ins, nil
}

func (ins *instance) createWatcher() (instanceWatcher, error) {
	if ins.insMgr.insConnectType == "sse" {
		return newSseWatcher(ins), nil
	} else {
		return nil, fmt.Errorf("[instance]watchType is error")
	}
}

func (ins *instance) connect() error {
	return ins.insWatcher.connectWithRetry()
}

func (ins *instance) run(insMgrWg *sync.WaitGroup) {
	defer insMgrWg.Done()
	ins.insWg.Add(1)
	go ins.insWatcher.run(ins.insWg)

	for {
		select {
		case <-ins.ctx.Done(): // cancel the connection with instance
			log.Info().Msgf("[instance]Closing connection to %v", ins.insUrl)
			ins.insWg.Wait()
			return
		case msg := <-ins.msgChan:
			ins.processInsData(msg)
		}
	}
}

func (ins *instance) mixUpdateReq(data ReqStatusData) {
	if data.Event == "KVC_GENERATED" {
		log.Debug().Msgf("[instance]the kvc of request %v is ready.", data.ReqId)
	} else if data.Event == "REQUEST_IS_FINISHED" {
		ins.rwLock.Lock()
		req, exists := ins.reqSet[data.ReqId]
		if !exists {
			log.Debug().Msgf("[instance]req %s is not in this ins", data.ReqId)
			ins.rwLock.Unlock()
			return
		}

		reqType := req.reqType
		ins.insMgr.updateEmaPredictLen(reqType, data.DecodeLen)
		ins.rwLock.Unlock()
		ins.delReq(req, false)

	} else {
		log.Debug().Msgf("[instance]reqStatus is error: %+v", data)
	}
}

func (ins *instance) prefillUpdateReq(data ReqStatusData) {
	log.Debug().Msgf("[prefill-msg] %+v", data)
	if data.Event == "KVC_GENERATED" {
		ins.rwLock.Lock()
		req, exists := ins.reqSet[data.ReqId]
		if !exists {
			log.Debug().Msgf("[instance]req %v is not in this ins", data.ReqId)
			ins.rwLock.Unlock()
			return
		}
		ins.rwLock.Unlock()
		ins.delReq(req, false)
	} else {
		log.Debug().Msgf("[instance]reqStatus is error: %v", data)
	}
}

func (ins *instance) decodeUpdateReq(data ReqStatusData) {
	if data.Event == "DECODE_RECEIVED_KVC" {
		ins.rwLock.Lock()
		preBlock, exists := ins.preloadMap[data.ReqId]
		if !exists {
			log.Debug().Msgf("[instance]req %s is not in this ins", data.ReqId)
			ins.rwLock.Unlock()
			return
		}
		ins.preBlocks -= preBlock
		delete(ins.preloadMap, data.ReqId)
		ins.rwLock.Unlock()
	} else if data.Event == "REQUEST_IS_FINISHED" {
		ins.rwLock.Lock()
		req, exists := ins.reqSet[data.ReqId]
		if !exists {
			log.Debug().Msgf("[instance]req %s is not in this ins", data.ReqId)
			ins.rwLock.Unlock()
			return
		}

		reqType := req.reqType
		ins.insMgr.updateEmaPredictLen(reqType, data.DecodeLen)
		ins.rwLock.Unlock()

		ins.delReq(req, false)

	} else {
		log.Debug().Msgf("[instance]reqStatus is error: %+v", data)
	}
}

func (ins *instance) processReqStatus(data ReqStatusData) {
	switch ins.insRole {
	case mixedRoleInstance:
		ins.mixUpdateReq(data)
	case prefillRoleInstance:
		ins.prefillUpdateReq(data)
	case decodeRoleInstance:
		ins.decodeUpdateReq(data)
	default:
		log.Error().Msgf("[instance]the role of instance is error: %v", ins.insRole)
	}
	log.Debug().Msgf("[instance]update reqStatus: %+v", data)
}

func (ins *instance) processMetric(data MetricData) {
	ins.rwLock.Lock()
	defer ins.rwLock.Unlock()
	ins.freeBlocks = data.FreeBlocks
	ins.avgWaitingTime = data.AvgWaitingTime
	ins.tbt = data.TBT
	ins.queueLength = data.QueueLength
	ins.ttft = data.TTFT
	log.Debug().Msgf("[instance]update instance: %v metric: %+v", ins.insUrl, data)
}

func (ins *instance) processInsData(jsonStr string) {
	if len(jsonStr) > utils.MaxMessageLength {
		log.Warn().Msgf("[instance]upload msg is too long")
		return
	}
	var plaintext []byte
	if ins.insMgr.aesMgr.EnableAes() {
		hexData := bytes.TrimSpace([]byte(jsonStr))
		// Decoding hexadecimal data, use aes-128-gcm
		byteData, err := hex.DecodeString(string(hexData))
		if err != nil {
			log.Error().Msgf("Error decoding hex: %v", err)
			return
		}
		plaintext, err = ins.insMgr.aesMgr.Decrypt(byteData)
	} else {
		plaintext = []byte(jsonStr)
	}

	var event InsEvent
	err := json.Unmarshal(plaintext, &event)
	if err != nil {
		log.Error().Msgf("[instance]unmarshal upload data error: %v", err)
		return
	}

	switch event.EventType {
	case "metric_event":
		var mData MetricData
		err = json.Unmarshal(event.Data, &mData)
		if err != nil {
			log.Error().Msgf("[instance]unmarshal upload data error: %v", event.Data)
			return
		}
		err = CheckMetricData(mData)
		if err != nil {
			return
		}
		ins.processMetric(mData)
	case "req_event":
		var rData ReqStatusData
		err = json.Unmarshal(event.Data, &rData)
		if err != nil {
			log.Error().Msgf("[instance]unmarshal upload data error: %v", event.Data)
			return
		}
		err = CheckReqStatusData(rData)
		if err != nil {
			return
		}
		ins.processReqStatus(rData)
	default:
		log.Debug().Msgf("[instance]unmarshal eventType error: %v", jsonStr)
	}
}

func (ins *instance) getSnapShot() *insSnapshot {
	return &insSnapshot{
		insUrl:         ins.insUrl,
		freeBlocks:     ins.freeBlocks,
		preBlocks:      ins.preBlocks,
		tokenNum:       ins.tokenNum,
		ttft:           ins.ttft,
		tbt:            ins.tbt,
		queueLength:    ins.queueLength,
		avgWaitingTime: ins.avgWaitingTime,
		reqNum:         ins.reqNum,
		insRole:        ins.insRole,
		prefillTokens:  ins.prefillTokens,
		groupID:        ins.groupID,
	}
}
