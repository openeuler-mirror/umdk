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
	"math"
	"math/rand"
	"sort"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/stats"
	"huawei.com/aigw/pkg/latencyprediction"
	"huawei.com/aigw/pkg/log"
)

// ScheduleOptions contains optional parameters for scheduling
type ScheduleOptions struct {
	GroupID         string
	ExcludeGroupIDs map[string]bool
}

// ScheduleResult stands for the result of schedule
type ScheduleResult struct {
	ResultType     DispatchType
	PrefillUrl     string
	PrefillGroupID string
	DecodeUrl      string
	DecodeGroupID  string
	TokenIds       string // only valid for DispatchRequest
	DpRank         *int   // DP rank for data parallel routing (optional)
}

// LoadBalancerType is the type of load balance algorithm
type LoadBalancerType int

// definition for LoadBalancerType
const (
	LoadBalancerNone LoadBalancerType = iota
	LoadBalancerRoundRobin
	LoadBalancerLeastConn
	LoadBalancerCapacity
	LoadBalancerToken
	LoadBalancerDecode
	LoadBalancerPrefillTimeAware
	LoadBalancerConsistentHash // Consistent hash for session affinity
)

// VirtualNodesPerWorker is the number of virtual nodes per worker in consistent hash.
const VirtualNodesPerWorker = 160

var globalRandom = rand.New(rand.NewSource(time.Now().UnixNano()))

// createEmptyScheduleResult creates an empty schedule result
func createEmptyScheduleResult() *ScheduleResult {
	return &ScheduleResult{
		ResultType: DispatchRequest,
		PrefillUrl: "",
		DecodeUrl:  "",
		TokenIds:   "",
	}
}

func newLoadBalancer(metricProvider MetricProvider, config *AlgorithmParams) (loadBalancer, error) {
	// don't modify the input config
	tmpCfg := *config
	if config.PdMode == MixedDeployment {
		tmpCfg.InstanceRoleType = base.MixedRoleInstance
		return createMetaLB(config.PdMixedLB, metricProvider, &tmpCfg)
	} else if config.PdMode == SeparatedDeployment {
		return newPDLoadBalancer(metricProvider, &tmpCfg)
	} else {
		log.Error().Msgf("[LB] error deployment")
		return nil, fmt.Errorf("error deployment")
	}
}

func createMetaLB(lbType LoadBalancerType, metricProvider MetricProvider,
	config *AlgorithmParams) (loadBalancer, error) {
	switch lbType {
	case LoadBalancerRoundRobin:
		return newRoundRobinLB(metricProvider, config)
	case LoadBalancerLeastConn:
		return newLeastConnLB(metricProvider, config)
	case LoadBalancerCapacity:
		return newCapacityLB(metricProvider, config)
	case LoadBalancerToken:
		return newTokenLB(metricProvider, config)
	case LoadBalancerDecode:
		return newDecodeLB(metricProvider, config)
	case LoadBalancerPrefillTimeAware:
		return newPrefillTimeLB(metricProvider, config)
	case LoadBalancerConsistentHash:
		return newConsistentHashLB(metricProvider, config)
	default:
		log.Error().Msgf("[LB] error loadBalancerType.")
		return nil, fmt.Errorf("error loadBalancerType")
	}
}

// loadBalancer is the interface for all AIGW loadBalancers
type loadBalancer interface {
	schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult
}

type baseLoadBalancer struct {
	metricProvider MetricProvider
	blockSize      int
	statsFunc      func(statType stats.StatType) // record dataplane stats
	predictType    PredictorType                 // none/ema/lightgbm

	instanceRoleType base.InstanceRole // role type of instances used in load balancing
}

// predict length include prompt and decode
func (b *baseLoadBalancer) predictTotalTokens(request *LlmRequest) int {
	switch b.predictType {
	case PredictTypeEma:
		return b.metricProvider.PredictTokensByEMA(request)
	case PredictTypeNone:
		return request.PromptLen
	case PredictTypeLightgbm:
		return request.PromptLen + request.PredictDecodeLen
	default:
		log.Warn().Msg("error predictType, use none instead")
		return request.PromptLen
	}
}

func (b *baseLoadBalancer) buildQueryOptions(options *ScheduleOptions) *MetricQueryOptions {
	queryOptions := &MetricQueryOptions{
		Role:            &b.instanceRoleType,
		GroupID:         "",
		ExcludeGroupIDs: nil,
	}
	if options != nil {
		queryOptions.GroupID = options.GroupID
		queryOptions.ExcludeGroupIDs = options.ExcludeGroupIDs
	}
	return queryOptions
}

type rrLoadBalancer struct {
	baseLoadBalancer
	batchSize int
	reqCount  int
}

func newRoundRobinLB(metricProvider MetricProvider, params *AlgorithmParams) (*rrLoadBalancer, error) {
	log.Info().Msgf("[RR] Init RR loadbalancer.")
	if params.BatchSize <= 0 {
		log.Error().Msgf("[RR] init rrLB error, batchsize is less then 0.")
		return nil, fmt.Errorf("init rrLB error, batchsize is less then 0")
	}
	return &rrLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{metricProvider: metricProvider, instanceRoleType: params.InstanceRoleType},
		batchSize:        params.BatchSize,
		reqCount:         0,
	}, nil
}

func (lb *rrLoadBalancer) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	metrics, err := lb.metricProvider.GetInstanceMetrics(request.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[RR] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	if len(metrics) == 0 {
		log.Debug().Msg("[RR] no instances available for scheduling")
		return createEmptyScheduleResult()
	}

	// Sort by InsUrl for consistent round-robin selection
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].InsUrl < metrics[j].InsUrl
	})

	targetUrl := ""
	targetGroupID := ""
	for i := 0; i < len(metrics); i++ {
		idx := (lb.reqCount + i) % len(metrics)
		metric := metrics[idx]
		if metric.ReqNum < lb.batchSize {
			targetUrl = metric.InsUrl
			lb.reqCount += 1
			targetGroupID = metric.GroupID
			break
		}
	}
	log.Debug().Msgf("[RR]req %v schedule to ins %v.", request.Request.ReqId, targetUrl)
	return &ScheduleResult{
		ResultType: DispatchRequest,
		PrefillUrl: targetUrl,
		DecodeUrl:  "",
		TokenIds:   "",

		PrefillGroupID: targetGroupID,
		DecodeGroupID:  "",
	}
}

type leastConnLoadBalancer struct {
	baseLoadBalancer
	batchSize int
}

func newLeastConnLB(metricProvider MetricProvider, params *AlgorithmParams) (*leastConnLoadBalancer, error) {
	log.Info().Msgf("[least] Init leastconn loadbalancer.")
	if params.BatchSize <= 0 {
		log.Error().Msgf("[least] init leastconnLB error, batchsize is less then 0.")
		return nil, fmt.Errorf("init leastconnLB error, batchsize is less then 0")
	}
	return &leastConnLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{metricProvider: metricProvider, instanceRoleType: params.InstanceRoleType},
		batchSize:        params.BatchSize,
	}, nil
}

func (lb *leastConnLoadBalancer) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	metrics, err := lb.metricProvider.GetInstanceMetrics(request.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[Least] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	if len(metrics) < 1 {
		log.Debug().Msg("[Least]no ins in insSnapshots when schedule")
		return createEmptyScheduleResult()
	}

	// Sort by reqNum (smallest first)
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].ReqNum < metrics[j].ReqNum
	})

	var targetIns *InstanceMetric
	if metrics[0].ReqNum >= lb.batchSize {
		targetIns = nil
	} else {
		targetIns = metrics[0]
	}

	targetUrl := ""
	targetGroupID := ""
	if targetIns != nil {
		targetUrl = targetIns.InsUrl
		targetGroupID = targetIns.GroupID
	}
	log.Debug().Msgf("[Least]req %v schedule to ins %v.", request.Request.ReqId, targetUrl)

	return &ScheduleResult{
		ResultType: DispatchRequest,
		PrefillUrl: targetUrl,
		DecodeUrl:  "",
		TokenIds:   "",

		PrefillGroupID: targetGroupID,
		DecodeGroupID:  "",
	}
}

type capacityLoadBalancer struct {
	baseLoadBalancer
	blockThreshold int
	powerOfTwo     bool
	tbtThreshold   float64
	ttftThreshold  float64
}

func newCapacityLB(metricProvider MetricProvider, params *AlgorithmParams) (*capacityLoadBalancer, error) {
	log.Info().Msgf("[Capacity] Init capacityLoadBalancer.")
	if params.MinBlockThreshold <= 0 || params.TbtThreshold <= 0 || params.TtftThreshold <= 0 {
		log.Error().Msgf("[Capacity] init CapacityLB error, params is less then 0.")
		return nil, fmt.Errorf("init CapacityLB error, params is less then 0")
	}
	return &capacityLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{
			metricProvider: metricProvider,
			blockSize:      params.BlockSize,
			statsFunc:      params.StatsFunc,
			predictType:    params.PredictType,

			instanceRoleType: params.InstanceRoleType,
		},
		blockThreshold: params.MinBlockThreshold,
		powerOfTwo:     params.PowerOfTwo,
		tbtThreshold:   params.TbtThreshold,  // ms
		ttftThreshold:  params.TtftThreshold, // ms
	}, nil
}

func (lb *capacityLoadBalancer) schedule(requestMsg *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	request := requestMsg.Request
	totalLength := lb.predictTotalTokens(request)
	// round up
	request.PredictBlocks = (totalLength + lb.blockSize - 1) / lb.blockSize
	if lb.baseLoadBalancer.instanceRoleType == base.PrefillRoleInstance {
		request.PrefillBlocks = request.PredictBlocks
	}
	log.Debug().Msgf("[capacityLB]req_id: %v, totalLen: %v, predict blocks: %v, prefill blocks: %v",
		request.ReqId, totalLength, request.PredictBlocks, request.PrefillBlocks)

	metrics, err := lb.metricProvider.GetInstanceMetrics(requestMsg.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[capacityLB] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	if len(metrics) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return createEmptyScheduleResult()
	}

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].FreeBlocks > metrics[j].FreeBlocks
	})

	candidateIns, isLatencyOverLimit, isInsufficientFreeBlocks := lb.filterCandidateInstances(metrics)
	targetIns := lb.selectTargetInstance(candidateIns, isLatencyOverLimit, isInsufficientFreeBlocks)

	return lb.createScheduleResult(request, targetIns)
}

func (lb *capacityLoadBalancer) filterCandidateInstances(metrics []*InstanceMetric) (
	[]*InstanceMetric, bool, bool) {
	isLatencyOverLimit := false
	isInsufficientFreeBlocks := true
	candidateIns := make([]*InstanceMetric, 0, len(metrics))

	for _, ins := range metrics {
		log.Debug().Msgf("[Capacity] ins: %+v", ins)

		if !lb.hasSufficientFreeBlocks(ins) {
			break
		}
		isInsufficientFreeBlocks = false

		if lb.isLatencyOverLimit(ins) {
			isLatencyOverLimit = true
			continue
		}

		candidateIns = append(candidateIns, ins)
	}

	return candidateIns, isLatencyOverLimit, isInsufficientFreeBlocks
}

func (lb *capacityLoadBalancer) hasSufficientFreeBlocks(ins *InstanceMetric) bool {
	return ins.FreeBlocks > lb.blockThreshold
}

func (lb *capacityLoadBalancer) isLatencyOverLimit(ins *InstanceMetric) bool {
	return ins.TBT >= lb.tbtThreshold || ins.TTFT >= lb.ttftThreshold
}

func (lb *capacityLoadBalancer) selectTargetInstance(candidateIns []*InstanceMetric,
	isLatencyOverLimit, isInsufficientFreeBlocks bool) *InstanceMetric {
	if len(candidateIns) > 1 && lb.powerOfTwo {
		return lb.selectByPowerOfTwo(candidateIns)
	}

	if len(candidateIns) <= 0 {
		lb.recordNoCandidateStats(isLatencyOverLimit, isInsufficientFreeBlocks)
		return nil
	}

	return candidateIns[0]
}

func (lb *capacityLoadBalancer) selectByPowerOfTwo(candidateIns []*InstanceMetric) *InstanceMetric {
	length := len(candidateIns)
	first := globalRandom.Intn(length)
	second := globalRandom.Intn(length)
	for first == second {
		second = globalRandom.Intn(length)
	}

	if candidateIns[first].FreeBlocks >= candidateIns[second].FreeBlocks {
		return candidateIns[first]
	}
	return candidateIns[second]
}

func (lb *capacityLoadBalancer) recordNoCandidateStats(isLatencyOverLimit, isInsufficientFreeBlocks bool) {
	if lb.statsFunc == nil {
		return
	}

	if isInsufficientFreeBlocks {
		lb.statsFunc(stats.CapacityLbInsufficientFreeBlocks)
	} else if isLatencyOverLimit {
		lb.statsFunc(stats.CapacityLbLatencyOverLimit)
	}
}

func (lb *capacityLoadBalancer) createScheduleResult(request *LlmRequest,
	targetIns *InstanceMetric) *ScheduleResult {
	if targetIns != nil {
		log.Debug().Msgf("[Capacity]req %v schedule to ins %v.", request.ReqId, targetIns.InsUrl)
		return &ScheduleResult{
			ResultType:     DispatchRequest,
			PrefillUrl:     targetIns.InsUrl,
			DecodeUrl:      "",
			TokenIds:       "",
			PrefillGroupID: targetIns.GroupID,
			DecodeGroupID:  "",
		}
	}

	log.Debug().Msgf("[Capacity]req %v schedule to ins %v.", request.ReqId, "")
	return createEmptyScheduleResult()
}

type prefillTimeLoadBalancer struct {
	baseLoadBalancer
	tbtThreshold  float64
	ttftThreshold float64
	ttftPredictor latencyprediction.TTFTPrediction
}

func newPrefillTimeLB(metricProvider MetricProvider, params *AlgorithmParams) (*prefillTimeLoadBalancer, error) {
	log.Info().Msgf("[prefillTimeLB] Init prefillTimeLB.")
	if params.TbtThreshold <= 0 || params.TtftThreshold <= 0 {
		log.Error().Msgf("[prefillTimeLB] init prefillTimeLB error, params is less than 0.")
		return nil, fmt.Errorf("init prefillTimeLB error, params is less than 0")
	}

	ttftPredictor, err := latencyprediction.NewTTFTPredictor(params.PretrainTTFTPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init ttft predictor: %v, path : %v", err, params.PretrainTTFTPath)
	}

	if params.PretrainTTFTPath != "" {
		log.Info().Msgf("init ttft predictor with pretrain data, path : %v", params.PretrainTTFTPath)
	} else {
		log.Info().Msg("init ttft predictor without pretrain data")
	}

	return &prefillTimeLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{metricProvider: metricProvider, blockSize: params.BlockSize,
			statsFunc: params.StatsFunc, predictType: params.PredictType, instanceRoleType: params.InstanceRoleType},
		tbtThreshold:  params.TbtThreshold,  // ms
		ttftThreshold: params.TtftThreshold, // ms
		ttftPredictor: ttftPredictor,
	}, nil
}

func (lb *prefillTimeLoadBalancer) schedule(requestMsg *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	request := requestMsg.Request
	totalTokenNum := request.PromptLen
	request.PredictTokens = totalTokenNum
	request.PredictPrefillTime = lb.ttftPredictor.Predict(totalTokenNum, 0)
	log.Debug().Msgf("[prefillTimeLB] req %v predict ttft: %.2f", request.ReqId,
		request.PredictPrefillTime)

	metrics, err := lb.metricProvider.GetInstanceMetrics(requestMsg.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[prefillTimeLB] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	now := time.Now().UnixMilli()
	var targetIns *InstanceMetric
	minWaitTime := math.MaxFloat64

	for _, ins := range metrics {
		var needWaitingTime float64
		headReq := ins.HeadReq
		if ins.PrefillTime == 0 || headReq == nil {
			needWaitingTime = 0
		} else {
			deltaT := now - headReq.PrefillTimeStampMs
			if float64(deltaT) < headReq.PredictPrefillTime {
				needWaitingTime = ins.PrefillTime - float64(deltaT)
			} else {
				needWaitingTime = ins.PrefillTime - headReq.PredictPrefillTime
			}
		}

		if ins.TBT < lb.tbtThreshold && ins.TTFT < lb.ttftThreshold {
			if needWaitingTime < minWaitTime {
				minWaitTime = needWaitingTime
				targetIns = ins
			}
		}
		log.Debug().Msgf("[prefillTimeLB] req_id: %v, ins: %v, TotalWaitingTime: %v, ins prefillTime %v",
			request.ReqId, ins.InsUrl, needWaitingTime, ins.PrefillTime)
	}

	if targetIns == nil {
		log.Error().Msgf("[prefillTimeLB]result: req %v failed to schedule: no valid instance.",
			request.ReqId)
		return createEmptyScheduleResult()
	}

	log.Debug().Msgf("[prefillTimeLB]req %v scheduled to ins %v.", request.ReqId, targetIns.InsUrl)
	return &ScheduleResult{
		ResultType:     DispatchRequest,
		PrefillUrl:     targetIns.InsUrl,
		DecodeUrl:      "",
		TokenIds:       "",
		PrefillGroupID: targetIns.GroupID,
		DecodeGroupID:  "",
	}
}

type tokenLoadBalancer struct {
	baseLoadBalancer
	tbtThreshold  float64
	ttftThreshold float64
}

func newTokenLB(metricProvider MetricProvider, params *AlgorithmParams) (*tokenLoadBalancer, error) {
	log.Info().Msgf("[Token] Init tokenLoadBalancer.")
	if params.TbtThreshold <= 0 || params.TtftThreshold <= 0 {
		log.Error().Msgf("[Token] init TokenLB error, params is less then 0.")
		return nil, fmt.Errorf("init TokenLB error, params is less then 0")
	}
	return &tokenLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{
			metricProvider: metricProvider,
			blockSize:      params.BlockSize,
			statsFunc:      params.StatsFunc,
			predictType:    params.PredictType,

			instanceRoleType: params.InstanceRoleType,
		},
		tbtThreshold:  params.TbtThreshold,  // ms
		ttftThreshold: params.TtftThreshold, // ms
	}, nil
}

func (lb *tokenLoadBalancer) schedule(requestMsg *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	request := requestMsg.Request
	totalTokenNum := lb.predictTotalTokens(request)
	request.PredictTokens = totalTokenNum
	log.Debug().Msgf("[tokenLB]req_id: %v, total token number: %v.", request.ReqId, totalTokenNum)

	metrics, err := lb.metricProvider.GetInstanceMetrics(requestMsg.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[tokenLB] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	for _, s := range metrics {
		log.Debug().Msgf("[tokenLB]ins_data:  req_id: %v, ins: %v, tokennum: %v ",
			request.ReqId, s.InsUrl, s.TokenNum)
	}
	if len(metrics) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return &ScheduleResult{
			ResultType: DispatchRequest,
			PrefillUrl: "",
			DecodeUrl:  "",
			TokenIds:   "",
		}
	}
	// sort from smallest to largest by token number
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].TokenNum < metrics[j].TokenNum
	})

	candidateIns := make([]*InstanceMetric, 0, len(metrics))
	for _, ins := range metrics {
		if ins.TBT >= lb.tbtThreshold || ins.TTFT >= lb.ttftThreshold {
			continue
		}
		candidateIns = append(candidateIns, ins)
	}

	// select one ins
	var targetIns *InstanceMetric
	if len(candidateIns) > 0 {
		targetIns = candidateIns[0]
	} else {
		lb.statsFunc(stats.TokenLbLatencyOverLimit)
		targetIns = nil
	}

	if targetIns == nil {
		log.Debug().Msgf("[tokenLB]result:  req %v schedule to ins %v.", request.ReqId, "")
		return createEmptyScheduleResult()
	}

	log.Debug().Msgf("[tokenLB]req %v schedule to ins %v.", request.ReqId, targetIns.InsUrl)
	return &ScheduleResult{
		ResultType: DispatchRequest,
		PrefillUrl: targetIns.InsUrl,
		DecodeUrl:  "",
		TokenIds:   "",

		PrefillGroupID: targetIns.GroupID,
		DecodeGroupID:  "",
	}
}

type decodeLoadBalancer struct {
	baseLoadBalancer
	tbtThreshold   float64
	blockThreshold int
	powerOfTwo     bool
}

func newDecodeLB(metricProvider MetricProvider, params *AlgorithmParams) (*decodeLoadBalancer, error) {
	log.Info().Msgf("[decode] Init decodeLoadBalancer.")
	if params.TbtThreshold <= 0 {
		log.Error().Msgf("[decode] init decodeLB error, tbtThreshold is less than 0.")
		return nil, fmt.Errorf("init decodeLB error, tbtThreshold is less than 0")
	}
	return &decodeLoadBalancer{
		baseLoadBalancer: baseLoadBalancer{
			metricProvider: metricProvider,
			blockSize:      params.BlockSize,
			statsFunc:      params.StatsFunc,
			predictType:    params.PredictType,

			instanceRoleType: params.InstanceRoleType,
		},
		tbtThreshold:   params.TbtThreshold, // ms
		blockThreshold: params.MinBlockThreshold,
		powerOfTwo:     params.PowerOfTwo,
	}, nil
}

func (lb *decodeLoadBalancer) schedule(requestMsg *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	request := requestMsg.Request
	totalLength := lb.predictTotalTokens(request)
	// round up
	request.PredictBlocks = (totalLength + lb.blockSize - 1) / lb.blockSize
	if lb.baseLoadBalancer.instanceRoleType == base.PrefillRoleInstance {
		request.PrefillBlocks = request.PredictBlocks
	}
	log.Debug().Msgf("[decodeLB]req_id: %v, totalLen: %v, predict blocks: %v, prefill blocks: %v",
		request.ReqId, totalLength, request.PredictBlocks, request.PrefillBlocks)

	metrics, err := lb.metricProvider.GetInstanceMetrics(requestMsg.CandidateInstanceIDs, lb.buildQueryOptions(options))
	if err != nil {
		log.Error().Msgf("[decodeLB] failed to get instance metrics: %v", err)
		return createEmptyScheduleResult()
	}

	if len(metrics) < 1 {
		lb.statsFunc(stats.LbNoInstances)
		return createEmptyScheduleResult()
	}
	for _, ins := range metrics {
		log.Debug().Msgf("[decodeLB] %+v", ins)
	}
	// sort from largest to smallest by pre blocks in decode instance
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].FreeBlocks-metrics[i].PreBlocks >
			metrics[j].FreeBlocks-metrics[j].PreBlocks
	})

	isLatencyOverLimit := false
	isInsufficientFreeBlocks := true
	candidateIns := make([]*InstanceMetric, 0, len(metrics))
	for _, ins := range metrics {
		if ins.FreeBlocks > lb.blockThreshold {
			isInsufficientFreeBlocks = false
		} else {
			continue
		}
		if ins.TBT >= lb.tbtThreshold {
			isLatencyOverLimit = true
			continue
		}
		candidateIns = append(candidateIns, ins)
	}

	var targetIns *InstanceMetric

	if len(candidateIns) > 1 && lb.powerOfTwo {
		length := len(candidateIns)
		first := globalRandom.Intn(length)
		second := globalRandom.Intn(length)
		for first == second {
			second = globalRandom.Intn(length)
		}
		if candidateIns[first].FreeBlocks >= candidateIns[second].FreeBlocks {
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
		log.Debug().Msgf("[decodeLB]req %v schedule to ins %v.", request.ReqId, targetIns.InsUrl)
		return &ScheduleResult{
			ResultType:     DispatchRequest,
			PrefillUrl:     targetIns.InsUrl,
			DecodeUrl:      "",
			TokenIds:       "",
			PrefillGroupID: targetIns.GroupID,
			DecodeGroupID:  "",
		}
	} else {
		log.Debug().Msgf("[decodeLB]req %v schedule to ins %v.", request.ReqId, "")
		return createEmptyScheduleResult()
	}
}

type pdLoadBalancer struct {
	metricProvider MetricProvider
	prefillLB      loadBalancer
	decodeLB       loadBalancer
}

func newPDLoadBalancer(metricProvider MetricProvider, config *AlgorithmParams) (*pdLoadBalancer, error) {
	var dLB loadBalancer
	var err error
	if config.DecodeLB != LoadBalancerNone {
		config.InstanceRoleType = base.DecodeRoleInstance
		dLB, err = createMetaLB(config.DecodeLB, metricProvider, config)
		if err != nil {
			log.Error().Msgf("[PDLB]new decode scheduler error:%v", err.Error())
			return nil, err
		}
	}

	// Set PredictTypeNone to not contain the output length
	config.PredictType = PredictTypeNone
	config.InstanceRoleType = base.PrefillRoleInstance
	pLB, err := createMetaLB(config.PrefillLB, metricProvider, config)
	if err != nil {
		log.Error().Msgf("[PDLB]new prefill scheduler error:%v", err.Error())
		return nil, err
	}
	log.Info().Msgf("[PDLB]create LB successfully, prefill is %v, decode is %v",
		config.PrefillLB, config.DecodeLB)
	return &pdLoadBalancer{
		metricProvider: metricProvider,
		prefillLB:      pLB,
		decodeLB:       dLB,
	}, nil
}

func (lb *pdLoadBalancer) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
	usedGroupId := make(map[string]bool)
	prefillOptions := &ScheduleOptions{ExcludeGroupIDs: usedGroupId}
	if options != nil {
		prefillOptions.GroupID = options.GroupID
	}

	for {
		pResult := lb.prefillLB.schedule(request, prefillOptions)
		// if there is no prefill, return
		if pResult.PrefillUrl == "" {
			log.Debug().Msg("no prefill instance available")
			return &ScheduleResult{}
		}

		var targetD string
		var dGroupID string
		if lb.decodeLB != nil {
			decodeOptions := &ScheduleOptions{
				GroupID:         pResult.PrefillGroupID,
				ExcludeGroupIDs: usedGroupId,
			}
			dResult := lb.decodeLB.schedule(request, decodeOptions)
			targetD = dResult.PrefillUrl
			dGroupID = dResult.PrefillGroupID
			// if there is no decode in this group, select again and exclude this group
			if targetD == "" {
				log.Debug().Msgf("no decode instance in group %s, prefill %v, retrying",
					pResult.PrefillGroupID, pResult.PrefillUrl)
				usedGroupId[pResult.PrefillGroupID] = true
				continue
			}
		}

		// if decodeLB exists and p,d both exist, return the result
		// if decodeLB does not exist and p exists, return the result
		return &ScheduleResult{
			ResultType:     DispatchRequest,
			PrefillUrl:     pResult.PrefillUrl,
			DecodeUrl:      targetD,
			PrefillGroupID: pResult.PrefillGroupID,
			DecodeGroupID:  dGroupID,
		}
	}
}
