/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: schedule implementation.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for aigw.
package gs

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"huawei.com/aigw/internal/stats"
	"huawei.com/aigw/pkg/log"
)

type scheduleResult struct {
	resultType     dispatchType
	prefillUrl     string
	prefillGroupID string
	decodeUrl      string
	decodeGroupID  string
	tokenIds       string // only valid for DispatchRequest
}

type loadBalancerType int

const uint32Len = 4
const (
	loadBalancerNone loadBalancerType = iota
	loadBalancerBase
	loadBalancerRoundRobin
	loadBalancerLeastConn
	loadBalancerCapacity
	loadBalancerToken
	loadBalancerPdMixed
	loadBalancerPrefill
	loadBalancerDecode
)

var globalRandom = rand.New(rand.NewSource(time.Now().UnixNano()))

func newLoadBalancer(gs *GlobalSchedulerManager, config *AlgorithmParams) (loadBalancer, error) {
	if config.pdMode == mixedDeployment {
		return createMetaLB(config.pdMixedLB, gs.instanceManager, config)
	} else if config.pdMode == separatedDeployment {
		return newPDLoadBalancer(gs.prefillInsManager, gs.decodeInsManager, config)
	} else {
		log.Error().Msgf("[LB] error deployment")
		return nil, fmt.Errorf("error deployment")
	}
}

func createMetaLB(lbType loadBalancerType, insManager *instanceManager,
	config *AlgorithmParams) (loadBalancer, error) {
	switch lbType {
	case loadBalancerBase:
		return &baseLoadBalancer{insManager: insManager}, nil
	case loadBalancerRoundRobin:
		return newRoundRobinLB(insManager, config)
	case loadBalancerLeastConn:
		return newLeastConnLB(insManager, config)
	case loadBalancerCapacity:
		return newCapacityLB(insManager, config)
	case loadBalancerToken:
		return newTokenLB(insManager, config)
	case loadBalancerDecode:
		return newDecodeLB(insManager, config)
	default:
		log.Error().Msgf("[LB] error loadBalancerType.")
		return nil, fmt.Errorf("error loadBalancerType")
	}
}

// loadBalancer is the interface for all AIGW loadBalancers
type loadBalancer interface {
	schedule(request *ScheduleRequestMsg, groupID string, excludeGroupId map[string]bool) *scheduleResult
	withdraw(request *ScheduleRequestMsg, insUrl string)
}

type baseLoadBalancer struct {
	insManager *instanceManager
	blockSize  int
	statsFunc  func(statType stats.StatType) // record dataplane stats
}

func (b *baseLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	return
}

func (b *baseLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	instances := b.insManager.insSnapshots
	if len(instances) == 0 {
		return nil
	}

	// chose the first for simple
	selected := instances[0]

	return &scheduleResult{
		resultType: dispatchRequest,
		prefillUrl: selected.insUrl,
		decodeUrl:  "",
		tokenIds:   "",

		prefillGroupID: selected.groupID,
		decodeGroupID:  "",
	}
}

type rrLoadBalancer struct {
	baseLoadBalancer
	batchSize int
	reqCount  int
}

func newRoundRobinLB(insManager *instanceManager, params *AlgorithmParams) (*rrLoadBalancer, error) {
	log.Info().Msgf("[RR] Init RR loadbalancer.")
	if params.batchSize <= 0 {
		log.Error().Msgf("[RR] init rrLB error, batchsize is less then 0.")
		return nil, fmt.Errorf("init rrLB error, batchsize is less then 0")
	}
	return &rrLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{insManager: insManager},
		batchSize:        params.batchSize,
		reqCount:         0,
	}, nil
}

func (lb *rrLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	lb.insManager.poolRWLock.RLock()
	ins := lb.insManager.insPool[insUrl]
	lb.insManager.poolRWLock.RUnlock()
	ins.delReq(request.Request, true)
	lb.reqCount -= 1
}

func (lb *rrLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	lb.insManager.updatePoolShot()
	targetUrl := ""
	lb.insManager.snapshotRWLock.Lock()
	defer lb.insManager.snapshotRWLock.Unlock()

	insSnapGroup := lb.insManager.getSnapByGroupID(groupID, excludeGroupId)

	sort.Slice(insSnapGroup, func(i, j int) bool {
		return insSnapGroup[i].insUrl < insSnapGroup[j].insUrl
	})
	targetGroupID := ""
	for i := 0; i < len(insSnapGroup); i++ {
		idx := (lb.reqCount + i) % len(insSnapGroup)
		insSnap := insSnapGroup[idx]
		if insSnap.reqNum < lb.batchSize {
			targetUrl = insSnap.insUrl
			lb.reqCount += 1
			targetGroupID = insSnap.groupID
			lb.insManager.addReq(targetUrl, request.Request) // update instance pool
			break
		}
	}
	log.Debug().Msgf("[RR]req %v schedule to ins %v.", request.Request.ReqId, targetUrl)
	return &scheduleResult{
		resultType: dispatchRequest,
		prefillUrl: targetUrl,
		decodeUrl:  "",
		tokenIds:   "",

		prefillGroupID: targetGroupID,
		decodeGroupID:  "",
	}
}

type leastConnLoadBalancer struct {
	baseLoadBalancer
	batchSize int
}

func newLeastConnLB(insManager *instanceManager, params *AlgorithmParams) (*leastConnLoadBalancer, error) {
	log.Info().Msgf("[least] Init leastconn loadbalancer.")
	if params.batchSize <= 0 {
		log.Error().Msgf("[least] init leastconnLB error, batchsize is less then 0.")
		return nil, fmt.Errorf("init leastconnLB error, batchsize is less then 0")
	}
	return &leastConnLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{insManager: insManager},
		batchSize:        params.batchSize,
	}, nil
}

func (lb *leastConnLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	targetUrl := ""
	lb.insManager.updatePoolShot()
	lb.insManager.snapshotRWLock.Lock()
	defer lb.insManager.snapshotRWLock.Unlock()

	insSnapGroup := lb.insManager.getSnapByGroupID(groupID, excludeGroupId)

	if len(insSnapGroup) < 1 {
		log.Debug().Msg("[Least]no ins in insSnapshots when schedule")
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: targetUrl,
			decodeUrl:  "",
			tokenIds:   "",
		}
	}

	sort.Slice(insSnapGroup, func(i, j int) bool {
		return insSnapGroup[i].reqNum < insSnapGroup[j].reqNum
	})
	var tempIns *insSnapshot
	tempIns = insSnapGroup[0]
	if tempIns.reqNum >= lb.batchSize {
		tempIns = nil
	}
	targetGroupID := ""
	if tempIns != nil {
		lb.insManager.addReq(tempIns.insUrl, request.Request)
		targetUrl = tempIns.insUrl
		targetGroupID = tempIns.groupID
	}
	log.Debug().Msgf("[Least]req %v schedule to ins %v.", request.Request.ReqId, targetUrl)

	return &scheduleResult{
		resultType: dispatchRequest,
		prefillUrl: targetUrl,
		decodeUrl:  "",
		tokenIds:   "",

		prefillGroupID: targetGroupID,
		decodeGroupID:  "",
	}
}

func (lb *leastConnLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	lb.insManager.poolRWLock.RLock()
	ins := lb.insManager.insPool[insUrl]
	lb.insManager.poolRWLock.RUnlock()
	ins.delReq(request.Request, true)
}

type capacityLoadBalancer struct {
	baseLoadBalancer
	blockThreshold int
	powerOfTwo     bool
	tbtThreshold   float64
	ttftThreshold  float64
	predictType    predictorType // none/ema/lightgbm
}

func newCapacityLB(insManager *instanceManager, params *AlgorithmParams) (*capacityLoadBalancer, error) {
	log.Info().Msgf("[Capacity] Init capacityLoadBalancer.")
	if params.minBlockThreshold <= 0 || params.tbtThreshold <= 0 || params.ttftThreshold <= 0 {
		log.Error().Msgf("[Capacity] init CapacityLB error, params is less then 0.")
		return nil, fmt.Errorf("init CapacityLB error, params is less then 0")
	}
	return &capacityLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{insManager: insManager, blockSize: params.blockSize,
			statsFunc: params.statsFunc},
		blockThreshold: params.minBlockThreshold,
		powerOfTwo:     params.powerOfTwo,
		tbtThreshold:   params.tbtThreshold,  // ms
		ttftThreshold:  params.ttftThreshold, // ms
		predictType:    params.predictType,
	}, nil
}

func (lb *capacityLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	totalLength := 0 // predict length include prompt and decode
	switch lb.predictType {
	case predictTypeEma:
		totalLength = lb.insManager.predictTokensByEMA(request.Request)
	case predictTypeNone:
		totalLength = request.Request.promptLen
	case predictTypeLightgbm:
		{
			totalLength = request.Request.promptLen + request.Request.predictDecodeLen
		}
	default:
		log.Warn().Msg("error predictType, use none instead")
		totalLength = request.Request.promptLen
	}
	// round up
	request.Request.predictBlocks = (totalLength + lb.blockSize - 1) / lb.blockSize
	log.Debug().Msgf("[capacityLB]req_id: %v, totalLen: %v, predict blocks: %v;",
		request.Request.ReqId, totalLength, request.Request.predictBlocks)
	return lb.capacitySchedule(request, groupID, excludeGroupId)
}

func (lb *capacityLoadBalancer) capacitySchedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	lb.insManager.updatePoolShot()
	lb.insManager.snapshotRWLock.Lock()
	defer lb.insManager.snapshotRWLock.Unlock()

	insSnapGroup := lb.insManager.getSnapByGroupID(groupID, excludeGroupId)

	if len(insSnapGroup) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}

	// sort from largest to smallest by free blocks
	sort.Slice(insSnapGroup, func(i, j int) bool {
		return insSnapGroup[i].freeBlocks > insSnapGroup[j].freeBlocks
	})

	// isLatencyOverLimit and isInsufficientFreeBlocks indicate the reason for no available instance:
	// whether it's due to ttft\tbt limit exceeded or insufficient free blocks.
	isLatencyOverLimit := false
	isInsufficientFreeBlocks := true

	candidateIns := make([]*insSnapshot, 0, len(insSnapGroup))

	for _, ins := range insSnapGroup {
		log.Debug().Msgf("[Capacity] ins: %+v", ins)
		if ins.freeBlocks > lb.blockThreshold {
			isInsufficientFreeBlocks = false
		} else {
			break
		}

		if ins.tbt >= lb.tbtThreshold || ins.ttft >= lb.ttftThreshold {
			isLatencyOverLimit = true
			continue
		}

		candidateIns = append(candidateIns, ins)
	}
	// select one ins
	var targetIns *insSnapshot

	if len(candidateIns) > 1 && lb.powerOfTwo {
		length := len(candidateIns)
		first := globalRandom.Intn(length)
		second := globalRandom.Intn(length)
		for first == second {
			second = globalRandom.Intn(length)
		}
		if candidateIns[first].freeBlocks >= candidateIns[second].freeBlocks {
			targetIns = candidateIns[first]
		} else {
			targetIns = candidateIns[second]
		}
	} else if len(candidateIns) <= 0 {
		if isInsufficientFreeBlocks && lb.statsFunc != nil {
			lb.statsFunc(stats.CapacityLbInsufficientFreeBlocks)
		} else if isLatencyOverLimit && lb.statsFunc != nil {
			lb.statsFunc(stats.CapacityLbLatencyOverLimit)
		}
		targetIns = nil
	} else {
		targetIns = candidateIns[0]
	}

	if targetIns != nil {
		lb.insManager.addReq(targetIns.insUrl, request.Request)
		log.Debug().Msgf("[Capacity]req %v schedule to ins %v.", request.Request.ReqId, targetIns.insUrl)
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: targetIns.insUrl,
			decodeUrl:  "",
			tokenIds:   "",

			prefillGroupID: targetIns.groupID,
			decodeGroupID:  "",
		}
	} else {
		log.Debug().Msgf("[Capacity]req %v schedule to ins %v.", request.Request.ReqId, "")
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}
}

func (lb *capacityLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	lb.insManager.poolRWLock.RLock()
	ins := lb.insManager.insPool[insUrl]
	lb.insManager.poolRWLock.RUnlock()
	ins.delReq(request.Request, true)
}

type tokenLoadBalancer struct {
	baseLoadBalancer
	tbtThreshold  float64
	ttftThreshold float64
	predictType   predictorType // none/ema/lightgbm
}

func newTokenLB(insManager *instanceManager, params *AlgorithmParams) (*tokenLoadBalancer, error) {
	log.Info().Msgf("[Token] Init tokenLoadBalancer.")
	if params.tbtThreshold <= 0 || params.ttftThreshold <= 0 {
		log.Error().Msgf("[Token] init TokenLB error, params is less then 0.")
		return nil, fmt.Errorf("init TokenLB error, params is less then 0")
	}
	return &tokenLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{insManager: insManager, blockSize: params.blockSize,
			statsFunc: params.statsFunc},
		tbtThreshold:  params.tbtThreshold,  // ms
		ttftThreshold: params.ttftThreshold, // ms
		predictType:   params.predictType,
	}, nil
}

func (lb *tokenLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	totalTokenNum := 0
	switch lb.predictType {
	case predictTypeEma:
		totalTokenNum = lb.insManager.predictTokensByEMA(request.Request)
	case predictTypeNone:
		totalTokenNum = request.Request.promptLen
	case predictTypeLightgbm:
		{
			totalTokenNum = request.Request.promptLen + request.Request.predictDecodeLen
		}
	default:
		log.Warn().Msg("error predictType, use none instead")
		totalTokenNum = request.Request.promptLen
	}

	request.Request.predictTokens = totalTokenNum
	log.Debug().Msgf("[tokenLB]req_id: %v, total token number: %v.", request.Request.ReqId, totalTokenNum)
	lb.insManager.updatePoolShot()
	lb.insManager.snapshotRWLock.Lock()
	defer lb.insManager.snapshotRWLock.Unlock()

	insSnapGroup := lb.insManager.getSnapByGroupID(groupID, excludeGroupId)
	for _, s := range insSnapGroup {
		log.Debug().Msgf("[tokenLB]ins_data:  req_id: %v, ins: %v, tokennum: %v ",
			request.Request.ReqId, s.insUrl, s.tokenNum)
	}
	if len(insSnapGroup) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}
	// sort from smallest to largest by token number
	sort.Slice(insSnapGroup, func(i, j int) bool {
		return insSnapGroup[i].tokenNum < insSnapGroup[j].tokenNum
	})

	candidateIns := make([]*insSnapshot, 0, len(insSnapGroup))
	for _, ins := range insSnapGroup {
		if ins.tbt >= lb.tbtThreshold || ins.ttft >= lb.ttftThreshold {
			continue
		}
		candidateIns = append(candidateIns, ins)
	}

	// select one ins
	var targetIns *insSnapshot
	if len(candidateIns) > 0 {
		targetIns = candidateIns[0]
	} else {
		lb.statsFunc(stats.TokenLbLatencyOverLimit)
		targetIns = nil
	}

	if targetIns == nil {
		log.Debug().Msgf("[tokenLB]result:  req %v schedule to ins %v.", request.Request.ReqId, "")
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}

	lb.insManager.addReq(targetIns.insUrl, request.Request)
	log.Debug().Msgf("[tokenLB]req %v schedule to ins %v.", request.Request.ReqId, targetIns.insUrl)
	return &scheduleResult{
		resultType: dispatchRequest,
		prefillUrl: targetIns.insUrl,
		decodeUrl:  "",
		tokenIds:   "",

		prefillGroupID: targetIns.groupID,
		decodeGroupID:  "",
	}
}

func (lb *tokenLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	lb.insManager.poolRWLock.RLock()
	ins := lb.insManager.insPool[insUrl]
	lb.insManager.poolRWLock.RUnlock()
	ins.delReq(request.Request, true)
}

type decodeLoadBalancer struct {
	baseLoadBalancer
	tbtThreshold   float64
	blockThreshold int
	predictType    predictorType // none/ema/lightgbm
	powerOfTwo     bool
}

func newDecodeLB(insManager *instanceManager, params *AlgorithmParams) (*decodeLoadBalancer, error) {
	log.Info().Msgf("[decode] Init decodeLoadBalancer.")
	if params.tbtThreshold <= 0 {
		log.Error().Msgf("[decode] init decodeLB error, tbtThreshold is less than 0.")
		return nil, fmt.Errorf("init decodeLB error, tbtThreshold is less than 0")
	}
	return &decodeLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{insManager: insManager, blockSize: params.blockSize,
			statsFunc: params.statsFunc},
		tbtThreshold:   params.tbtThreshold, // ms
		blockThreshold: params.minBlockThreshold,
		predictType:    params.predictType,
		powerOfTwo:     params.powerOfTwo,
	}, nil
}

func (lb *decodeLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	totalLength := 0 // predict length include prompt and decode
	switch lb.predictType {
	case predictTypeEma:
		totalLength = lb.insManager.predictTokensByEMA(request.Request)
	case predictTypeNone:
		totalLength = request.Request.promptLen
	case predictTypeLightgbm:
		{
			totalLength = request.Request.promptLen + request.Request.predictDecodeLen
		}
	default:
		log.Warn().Msg("error predictType, use none instead")
		totalLength = request.Request.promptLen
	}
	// round up
	request.Request.predictBlocks = (totalLength + lb.blockSize - 1) / lb.blockSize
	log.Debug().Msgf("[decodeLB]req_id: %v, totalLen: %v, predict blocks: %v;",
		request.Request.ReqId, totalLength, request.Request.predictBlocks)
	lb.insManager.updatePoolShot()
	lb.insManager.snapshotRWLock.Lock()
	defer lb.insManager.snapshotRWLock.Unlock()

	insSnapGroup := lb.insManager.getSnapByGroupID(groupID, excludeGroupId)
	if len(insSnapGroup) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}
	for _, ins := range insSnapGroup {
		log.Debug().Msgf("[decodeLB] %+v", ins)
	}
	// sort from largest to smallest by pre blocks in decode instance
	sort.Slice(insSnapGroup, func(i, j int) bool {
		return insSnapGroup[i].freeBlocks-insSnapGroup[i].preBlocks >
			insSnapGroup[j].freeBlocks-insSnapGroup[j].preBlocks
	})

	isLatencyOverLimit := false
	isInsufficientFreeBlocks := true
	candidateIns := make([]*insSnapshot, 0, len(insSnapGroup))
	for _, ins := range insSnapGroup {
		if ins.freeBlocks > lb.blockThreshold {
			isInsufficientFreeBlocks = false
		} else {
			continue
		}
		if ins.tbt >= lb.tbtThreshold {
			isLatencyOverLimit = true
			continue
		}
		candidateIns = append(candidateIns, ins)
	}

	var targetIns *insSnapshot

	if len(candidateIns) > 1 && lb.powerOfTwo {
		length := len(candidateIns)
		first := globalRandom.Intn(length)
		second := globalRandom.Intn(length)
		for first == second {
			second = globalRandom.Intn(length)
		}
		if candidateIns[first].freeBlocks >= candidateIns[second].freeBlocks {
			targetIns = candidateIns[first]
		} else {
			targetIns = candidateIns[second]
		}
	} else if len(candidateIns) <= 0 {
		if isInsufficientFreeBlocks {
			lb.statsFunc(stats.CapacityLbInsufficientFreeBlocks)
		} else if isLatencyOverLimit {
			lb.statsFunc(stats.CapacityLbLatencyOverLimit)
		}
		targetIns = nil
	} else {
		targetIns = candidateIns[0]
	}

	if targetIns != nil {
		lb.insManager.addReq(targetIns.insUrl, request.Request)
		log.Debug().Msgf("[decodeLB]req %v schedule to ins %v.", request.Request.ReqId, targetIns.insUrl)
		return &scheduleResult{
			resultType:     dispatchRequest,
			prefillUrl:     targetIns.insUrl,
			decodeUrl:      "",
			tokenIds:       "",
			prefillGroupID: targetIns.groupID,
			decodeGroupID:  "",
		}
	} else {
		log.Debug().Msgf("[decodeLB]req %v schedule to ins %v.", request.Request.ReqId, "")
		return &scheduleResult{
			resultType: dispatchRequest,
			prefillUrl: "",
			decodeUrl:  "",
			tokenIds:   "",
		}
	}
}

func (lb *decodeLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	lb.insManager.poolRWLock.RLock()
	ins := lb.insManager.insPool[insUrl]
	lb.insManager.poolRWLock.RUnlock()
	ins.delReq(request.Request, true)
}

type pdLoadBalancer struct {
	prefillLB loadBalancer
	decodeLB  loadBalancer
}

func newPDLoadBalancer(pInsManager *instanceManager, dInsManager *instanceManager,
	config *AlgorithmParams) (*pdLoadBalancer, error) {
	dLB, err := createMetaLB(config.decodeLB, dInsManager, config)
	if err != nil {
		log.Error().Msgf("[PDLB]new decode scheduler error:%v", err.Error())
		return nil, err
	}

	config.predictType = predictTypeNone
	pLB, err := createMetaLB(config.prefillLB, pInsManager, config)
	if err != nil {
		log.Error().Msgf("[PDLB]new prefill scheduler error:%v", err.Error())
		return nil, err
	}
	log.Info().Msgf("[PDLB]create LB successfully, prefill is %v, decode is %v",
		config.prefillLB, config.decodeLB)
	return &pdLoadBalancer{
		prefillLB: pLB,
		decodeLB:  dLB,
	}, nil
}

func (lb *pdLoadBalancer) schedule(request *ScheduleRequestMsg, groupID string,
	excludeGroupId map[string]bool) *scheduleResult {
	usedGroupId := make(map[string]bool)
	for {
		pResult := lb.prefillLB.schedule(request, groupID, usedGroupId)
		// if there is no prefill, return
		if pResult.prefillUrl == "" {
			log.Debug().Msgf("no prefill can be selected")
			return &scheduleResult{
				resultType: dispatchRequest,
				prefillUrl: "",
				decodeUrl:  "",
				tokenIds:   "",
			}
		}

		dResult := lb.decodeLB.schedule(request, pResult.prefillGroupID, usedGroupId)
		// if there is no decode in this group, select again and exclude this group
		if dResult.prefillUrl == "" {
			log.Debug().Msgf("decode is none, withdraw the request in prefill %v", pResult.prefillUrl)
			usedGroupId[pResult.prefillGroupID] = true
			lb.prefillLB.withdraw(request, pResult.prefillUrl)
		} else {
			// if p and d both exist, return the result
			return &scheduleResult{
				resultType: dispatchRequest,
				prefillUrl: pResult.prefillUrl,
				decodeUrl:  dResult.prefillUrl,
				tokenIds:   "",
			}
		}
	}
}

func (lb *pdLoadBalancer) withdraw(request *ScheduleRequestMsg, insUrl string) {
	return
}
