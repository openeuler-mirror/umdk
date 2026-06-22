/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Manager provides management functions for globalScheduler.
 * Create: 2025-5-13
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/stats"
	"huawei.com/aigw/internal/tokenizers"
	"huawei.com/aigw/internal/vectorizer"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/lightgbm"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	chanBufferSize      = 1024
	writeChanTimeout    = 3 * time.Second
	insSnapShotFreq     = 1 * time.Second
	predictInterval     = 200
	halfInterval        = 100
	defaultInsNumPerGs  = 128
	defaultReqLifeCycle = 10 * time.Second
)

// DeploymentPolicy is the deployment mode
type DeploymentPolicy int

// definition for DeploymentPolicy
const (
	MixedDeployment DeploymentPolicy = iota
	SeparatedDeployment
)

// String returns the description of DeploymentPolicy
func (d DeploymentPolicy) String() string {
	switch d {
	case MixedDeployment:
		return "mixed"
	case SeparatedDeployment:
		return "separated"
	default:
		return "unknown"
	}
}

// PredictorType is the type of predictor
type PredictorType int

// definition for PredictorType
const (
	PredictTypeNone PredictorType = iota
	PredictTypeEma
	PredictTypeLightgbm
)

// String returns the description of PredictorType
func (p PredictorType) String() string {
	switch p {
	case PredictTypeNone:
		return "none"
	case PredictTypeEma:
		return "ema"
	case PredictTypeLightgbm:
		return "lightgbm"
	default:
		return "unknown"
	}
}

// globalSchedulerManagerConfig describes the configuration of GS Manager.
type globalSchedulerManagerConfig struct {
	model        string
	deployPolicy DeploymentPolicy
	predictType  PredictorType

	lbConfig AlgorithmParams

	insSnapShotFreq time.Duration
	insConnectType  string
	maxInsNumPerGS  int

	tokenizationRatio float64

	reqSurvivalDuration time.Duration // the survival duration for request

	skipInstanceConnection bool // skip connecting to instances during registration
}

// GlobalSchedulerManager is the GS manager
type GlobalSchedulerManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup

	config globalSchedulerManagerConfig

	controlChannel   chan *ControlMessage
	scheduleChannel  chan *ControlMessage
	reqStatusChannel chan *ControlMessage

	hmacMgr *crypto.HmacManager
	aesMgr  *crypto.AesManager

	dispatcher      *globalScheduleDispatcher
	instanceManager *InstanceManager
	cacheManager    *cachecenter.CacheManager

	scheduler loadBalancer
	tokenizer tokenizers.Tokenizer
	lgm       *lightgbm.Booster
	stats     *stats.DataPlaneStats

	lastAccessTime time.Time // last access timestamp of this gs

	cacheDriverOps *cachecenter.CacheDriverOps
	runtimeMode    base.RuntimeMode
	metricProvider MetricProvider
}

// AlgorithmParams when pdMode=mixedDeployment, decodeScheduler is not effective
type AlgorithmParams struct {
	PdMode    DeploymentPolicy
	PdMixedLB LoadBalancerType
	PrefillLB LoadBalancerType
	DecodeLB  LoadBalancerType

	InstanceRoleType base.InstanceRole // role type of instances used in load balancing

	BlockSize         int
	BatchSize         int
	MinBlockThreshold int
	TbtThreshold      float64 // ms
	TtftThreshold     float64 // ms

	StatsFunc func(statType stats.StatType)

	PowerOfTwo  bool
	PredictType PredictorType
	// each algorithm has its own parameters
	PretrainTTFTPath string // for prefillTimeAware

	// Consistent hash parameters
	VirtualNodes int // Number of virtual nodes per worker (default: 160)
	FallbackNum  int // Number of fallback workers to try on failure (default: 3)
	DpSize       int // DP size for DP-aware workers (default: 1)
}

// NewGlobalSchedulerManager creates a new GS with options
func NewGlobalSchedulerManager(parentCtx context.Context, gsConfig *base.GlobalSchedulerConfig,
	opts ...GlobalSchedulerManagerOption) (*GlobalSchedulerManager, error) {

	manager := &GlobalSchedulerManager{
		wg: new(sync.WaitGroup),

		config: globalSchedulerManagerConfig{
			insSnapShotFreq:   insSnapShotFreq,
			tokenizationRatio: tokenizers.DefaultTokenizationRatio,
			maxInsNumPerGS:    defaultInsNumPerGs,
		},

		controlChannel:   make(chan *ControlMessage, chanBufferSize),
		scheduleChannel:  make(chan *ControlMessage, chanBufferSize),
		reqStatusChannel: make(chan *ControlMessage, chanBufferSize),

		scheduler: nil,
		stats:     stats.NewDataPlaneStats(),

		lastAccessTime: time.Now(),

		cacheDriverOps: nil,
	}
	manager.ctx, manager.cancel = context.WithCancel(parentCtx)

	if e := manager.setConfig(gsConfig); e != nil {
		return nil, e
	}

	for _, opt := range opts {
		if e := opt(manager); e != nil {
			return nil, e
		}
	}

	var cacheOptions []cachecenter.ManagerOption
	if manager.cacheDriverOps != nil {
		adp := cachecenter.NewRedisCacheCenter(manager.cacheDriverOps, int(manager.config.reqSurvivalDuration))
		cacheOptions = append(cacheOptions, cachecenter.WithRemoteCache(adp))
		cacheOptions = append(cacheOptions, cachecenter.WithRefreshInterval(gsConfig.CacheRefreshIntervalMs))
		cacheOptions = append(cacheOptions, cachecenter.WithReqTtl(manager.config.reqSurvivalDuration))
	}

	manager.cacheManager = cachecenter.NewCacheManager(manager.ctx, manager.config.model, cacheOptions...)
	manager.instanceManager = NewInstanceManagerWithOptions(manager.cacheManager,
		withCrypto(manager.hmacMgr, manager.aesMgr),
		withSnapShotUpdateInterval(manager.config.insSnapShotFreq),
		withConnectType(manager.config.insConnectType),
		withRuntimeMode(manager.runtimeMode),
		WithSkipInstanceConnection(manager.config.skipInstanceConnection),
	)

	// Create MetricProvider based on runtime mode
	var metricProvider MetricProvider
	if manager.runtimeMode == base.ServiceMode {
		metricProvider = NewInstanceMetricProvider(manager.instanceManager)
	} else {
		metricProvider = NewCacheMetricProvider(manager.cacheManager)
	}
	manager.metricProvider = metricProvider

	gsLB, err := newLoadBalancer(metricProvider, &manager.config.lbConfig)
	if err != nil {
		return nil, err
	}
	manager.scheduler = gsLB

	manager.dispatcher = newGlobalScheduleDispatcher(manager.ctx)

	return manager, nil
}

func (m *GlobalSchedulerManager) setConfig(gsConfig *base.GlobalSchedulerConfig) error {
	lbCfg := &gsConfig.LoadBalancer
	// set mandatory options
	options := []GlobalSchedulerManagerOption{
		WithModel(gsConfig.Model),
		WithDeploymentPolicy(gsConfig.DeployPolicy),
		WithSLOThreshold(gsConfig.MaxTimeToFirstToken, gsConfig.MaxTimeBetweenTokens),
		WithLBType(lbCfg.Mixed, lbCfg.Prefill, lbCfg.Decode),
		WithAlgorithmThreshold(lbCfg.ReservedBlockNumber, lbCfg.BatchSize, lbCfg.PowerOfTwo, gsConfig.BlockSize),
		WithInsConnectType(gsConfig.InsConnectType),
		WithPretrainTTFTPath(lbCfg.PretrainTTFTPath),
	}

	for _, opt := range options {
		if e := opt(m); e != nil {
			return e
		}
	}

	// Set skipInstanceConnection from config
	m.config.skipInstanceConnection = gsConfig.SkipInstanceConnection
	log.Info().Msgf("[GSManager] skipInstanceConnection = %v", m.config.skipInstanceConnection)

	m.config.lbConfig.StatsFunc = func(statType stats.StatType) {
		m.stats.Record(statType)
	}

	return nil
}

// LastAccessAt returns gs last accessed time
func (m *GlobalSchedulerManager) LastAccessAt() time.Time {
	return m.lastAccessTime
}

// Access update lastAccessTime when gs is accessed
func (m *GlobalSchedulerManager) Access() {
	m.lastAccessTime = time.Now()
}

// Start the GS
func (m *GlobalSchedulerManager) Start() error {
	log.Info().Msgf("starting global scheduler, model %v.", m.config.model)

	m.instanceManager.start()
	m.cacheManager.Start()
	m.dispatcher.start()

	m.wg.Add(1)
	go m.controlLoop()

	m.wg.Add(1)
	go m.scheduleLoop()

	m.wg.Add(1)
	go m.reqManagerLoop()

	log.Info().Msgf("start GlobalScheduler successfully, model %v.", m.config.model)
	return nil
}

// Stop the GS
func (m *GlobalSchedulerManager) Stop() {
	log.Info().Msgf("start to stop GlobalScheduler, model %v.", m.config.model)

	m.cancel()
	m.wg.Wait()

	if m.dispatcher != nil {
		m.dispatcher.stop()
	}

	m.cacheManager.Stop()

	if m.instanceManager != nil {
		m.instanceManager.stop()
	}

	log.Info().Msgf("stop GlobalScheduler successfully, model %v.", m.config.model)
}

// GetStats Get the stats of GlobalSchedulerManager
func (m *GlobalSchedulerManager) GetStats() map[string]uint64 {
	return m.stats.GetStatsMap()
}

func (m *GlobalSchedulerManager) registerInstance(ctrlMsg *ControlMessage) {
	var err error
	defer func() { ctrlMsg.Response <- err }()

	if m.GetInsNum() >= m.config.maxInsNumPerGS {
		err = fmt.Errorf("the number of instance exceeds the maximum limit of gs(%v)",
			m.config.maxInsNumPerGS)
		log.ErrorAlarmMsgf(log.PerGSInstanceLimitExceeded, log.Report, fmt.Sprintf("%v", err))
		return
	}
	registerMsg, ok := ctrlMsg.Request.(*RegisterInstanceMsg)
	if !ok {
		err = fmt.Errorf("invalid register instance msg, req %v", ctrlMsg.Request)
		return
	}

	role, err := base.ToInstanceRole(registerMsg.Role)
	if err != nil {
		return
	}

	if m.config.deployPolicy == SeparatedDeployment && registerMsg.GroupID == "" {
		err = fmt.Errorf("groupId can't be empty in separated")
		return
	}

	switch role {
	case base.MixedRoleInstance:
		if m.config.deployPolicy != MixedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add mixed", m.config.deployPolicy)
			break
		}
	case base.PrefillRoleInstance:
		if m.config.deployPolicy != SeparatedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add prefill", m.config.deployPolicy)
			break
		}
	case base.DecodeRoleInstance:
		if m.config.deployPolicy != SeparatedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add decode", m.config.deployPolicy)
			break
		}
	default:
		err = fmt.Errorf("register instance failed, error ins role %v", role)
	}
	if err != nil {
		log.Error().Msgf("%v", err)
		return
	}

	insAddr := base.BuildInstanceAddress(registerMsg.IP, registerMsg.Port, registerMsg.DpRank)
	err = m.instanceManager.addInstance(insAddr, role, registerMsg.GroupID, m.reqStatusChannel)
	if err != nil {
		log.Error().Msgf("%v", err)
		return
	}
	m.instanceManager.updatePoolShot()

	log.Info().Msgf("instance %s registered successfully", registerMsg.Name)
}

func (m *GlobalSchedulerManager) unregisterInstance(ctrlMsg *ControlMessage) {
	var err error
	defer func() { ctrlMsg.Response <- err }()

	unregisterMsg, ok := ctrlMsg.Request.(*UnregisterInstanceMsg)
	if !ok {
		err = fmt.Errorf("invalid unregister instance msg, req %v", ctrlMsg.Request)
		return
	}

	insAddr := base.BuildInstanceAddress(unregisterMsg.IP, unregisterMsg.Port, unregisterMsg.DpRank)
	removed := m.instanceManager.removeInstance(insAddr)
	if !removed {
		log.Error().Msgf("instance %s not found", insAddr)
		err = fmt.Errorf("instance %s not found", insAddr)
		return
	}
	m.instanceManager.updatePoolShot()

	log.Info().Msgf("instance (%v:%v) unregistered successfully", unregisterMsg.IP, unregisterMsg.Port)
}

// PutControlMessage sends control message to GS.
func (m *GlobalSchedulerManager) PutControlMessage(ctrMsg *ControlMessage) {
	select {
	case m.controlChannel <- ctrMsg:
	case <-time.After(writeChanTimeout):
		log.Error().Msgf("GS putControlMessage timeout, control message %v", ctrMsg)
		ctrMsg.Response <- fmt.Errorf("putControlMessage timeout, control message %v", ctrMsg)
	case <-m.ctx.Done():
		log.Warn().Msgf("GS putControlMessage cancelled")
		ctrMsg.Response <- nil
	}
}

func (m *GlobalSchedulerManager) controlLoop() {
	defer m.wg.Done()
	for {
		select {
		case ctrlMsg := <-m.controlChannel:
			switch request := ctrlMsg.Request.(type) {
			case *RegisterInstanceMsg:
				go m.registerInstance(ctrlMsg)

			case *UnregisterInstanceMsg:
				go m.unregisterInstance(ctrlMsg)

			default:
				log.Warn().Msgf("unknown control message type: %v", request)
				ctrlMsg.Response <- fmt.Errorf("unknown control message type: %v", request)
			}
		case <-m.ctx.Done():
			log.Info().Msg("stop GS control loop")
			return
		}
	}
}

// PutScheduleMessage sends schedule message to GS.
func (m *GlobalSchedulerManager) PutScheduleMessage(ctrMsg *ControlMessage) {
	select {
	case m.scheduleChannel <- ctrMsg:
	case <-time.After(writeChanTimeout):
		log.Error().Msgf("GS PutScheduleMessage timeout, control message %v", ctrMsg)
		ctrMsg.Response <- fmt.Errorf("GS PutScheduleMessage timeout, control message %v", ctrMsg)
	case <-m.ctx.Done():
		log.Info().Msgf("GS putScheduleMessage cancelled")
		ctrMsg.Response <- nil
	}
}

func (m *GlobalSchedulerManager) recordScheduleStats(result *ScheduleResult) {
	if result.PrefillUrl != "" {
		m.stats.Record(stats.ScheduleSuccess)
		return
	}
	m.stats.Record(stats.ScheduleFailure)
}

// handleSchedule handles schedule request with context cancellation check.
func (m *GlobalSchedulerManager) handleSchedule(msg *ControlMessage) {
	switch request := msg.Request.(type) {
	case *ScheduleRequestMsg:
		// check if context has been canceled
		if request.ReqCTX != nil {
			select {
			case <-request.ReqCTX.Done():
				log.Debug().Msgf("request %v cancelled, skip processing", request.Request.ReqId)
				msg.Response <- fmt.Errorf("request cancelled due to timeout")
				return
			default:
			}
		}

		result := m.scheduler.schedule(request, nil)
		m.recordScheduleStats(result)

		// Add request to metric provider after scheduling
		if result.PrefillUrl != "" {
			if err := m.metricProvider.AddRequest(request.Request, &InstanceContext{
				InstanceID:       result.PrefillUrl,
				GroupID:          result.PrefillGroupID,
				DecodeInstanceID: result.DecodeUrl,
			}); err != nil {
				msg.Response <- fmt.Errorf("failed to add request to provider with err: %v", err)
				return
			}
		}

		dispatchMsg := &ControlMessage{
			Request: &ExecuteDispatchMsg{
				Result: result,
			},
			Response: msg.Response,
		}

		m.dispatcher.dispatchChan <- dispatchMsg

		// clear request after schedule
		request.Request.Prompt = ""
		request.Request.PromptToken = nil
	default:
		log.Warn().Msgf("unknown schedule message type: %v", request)
		msg.Response <- fmt.Errorf("unknown schedule message type: %v", request)
	}
}

// Type of request event
const (
	EventDecodeReceivedKVC = "DECODE_RECEIVED_KVC"
	EventRequestIsFinished = "REQUEST_IS_FINISHED"
)

// HandleReqEvent handle request event
func (m *GlobalSchedulerManager) HandleReqEvent(reqId, eventDesc string) error {
	switch eventDesc {
	case EventDecodeReceivedKVC:
		if err := m.onPrefillFinished(reqId); err != nil {
			return fmt.Errorf("handle %s event failed for reqId=%s, err: %v", EventDecodeReceivedKVC, reqId, err)
		}
	case EventRequestIsFinished:
		if err := m.onDecodeFinished(reqId); err != nil {
			return fmt.Errorf("handle %s event failed for reqId=%s, err: %v", EventRequestIsFinished, reqId, err)
		}
	default:
		return fmt.Errorf("invalid event type %v for reqId=%s", eventDesc, reqId)
	}
	return nil
}

func (m *GlobalSchedulerManager) onPrefillFinished(reqId string) error {
	return m.cacheManager.UpdateRequestOnPrefillFinished(reqId)
}

func (m *GlobalSchedulerManager) onDecodeFinished(reqId string) error {
	return m.cacheManager.RemoveRequest(reqId)
}

// LoadInstanceFromCache loads instance from local cache
func (m *GlobalSchedulerManager) LoadInstanceFromCache(instances []*RegisterInstanceMsg) {
	start := time.Now()

	m.instanceManager.loadInsFromCache(instances)

	log.Debug().Msgf("gs %v load instance from cache cost %v", m.config.model, time.Since(start))
}

func (m *GlobalSchedulerManager) scheduleLoop() {
	defer m.wg.Done()
	for {
		select {
		case msg := <-m.scheduleChannel:
			m.handleSchedule(msg)
		case <-m.ctx.Done():
			log.Info().Msg("stop GS schedule loop")
			return
		}
	}
}

type preprocessResult struct {
	tokenizerError error
	predictError   error
}

func (m *GlobalSchedulerManager) executeTokenizer(req *LlmRequest, result *preprocessResult, preWg *sync.WaitGroup) {
	log.Debug().Msgf("start to execute tokenizer")
	start := time.Now()

	defer preWg.Done()

	if m.tokenizer == nil {
		runeCount := utf8.RuneCountInString(req.Prompt)
		req.PromptLen = int(m.config.tokenizationRatio * float64(runeCount))
		req.ReqType = GetRequestType(req.PromptLen)
		result.tokenizerError = nil
		log.Debug().Msgf("req %v, promptLen %v,  ratio %v", req.ReqId, req.PromptLen, m.config.tokenizationRatio)
		return
	}

	tokenIds, err := m.tokenizer.Encode(req.Prompt)
	if err != nil {
		log.Debug().Msgf("failed to encode in tokenizer, err: %v", err)
		result.tokenizerError = err
		m.stats.Record(stats.TokenizerEncodeError)
	} else {
		if tokenIds != nil {
			req.SetPromptAttrs(tokenIds)
			log.Debug().Msgf("[tokenizer] req %v has %v tokens", req.ReqId, len(tokenIds))
			result.tokenizerError = nil
		} else {
			result.tokenizerError = fmt.Errorf("empty token ids")
			m.stats.Record(stats.TokenizerEncodeError)
		}
	}

	log.Debug().Msgf("execute tokenizer finished, cost: %v", time.Since(start))
}

func (m *GlobalSchedulerManager) executePredict(req *LlmRequest, result *preprocessResult, preWg *sync.WaitGroup) {
	log.Debug().Msgf("start to execute prediction")
	start := time.Now()
	defer preWg.Done()
	prompt := req.Prompt
	words := vectorizer.SplitToCharsWithFilter(prompt)
	input, err := vectorizer.PredictTfidf(words)
	if err != nil {
		result.predictError = err
		m.stats.Record(stats.LightGbmVectorizeError)
	}
	preds, err := m.lgm.Predict(input)
	if err != nil {
		result.predictError = err
		m.stats.Record(stats.LightGbmPredictError)
	}
	decodeLen := utils.IndexOfMaxFloat(preds)*predictInterval + halfInterval
	req.PredictDecodeLen = decodeLen
	result.predictError = nil
	log.Debug().Msgf("execute prediction finished, decodeLen %v, cost time: %v", decodeLen, time.Since(start))
}

// PreprocessForSchedule will do some preprocesses for schedule, for example, tokenizer and
// lightGBM prediction if enabled will be done.
func (m *GlobalSchedulerManager) PreprocessForSchedule(req *LlmRequest) error {
	log.Debug().Msgf("start to preprocess for schedule")
	if m.instanceManager.isReqExists(req.ReqId) {
		log.Warn().Msgf("request id is repeat!: %v", req.ReqId)
		return fmt.Errorf("request id is repeat!: %v", req.ReqId)
	}
	preWg := new(sync.WaitGroup)

	result := &preprocessResult{
		tokenizerError: nil,
		predictError:   nil,
	}

	start := time.Now()
	preWg.Add(1)
	go m.executeTokenizer(req, result, preWg)

	if m.config.predictType == PredictTypeLightgbm {
		preWg.Add(1)
		go m.executePredict(req, result, preWg)
	}

	preWg.Wait()
	log.Debug().Msgf("preprocess for schedule finished, cost time: %v", time.Since(start))

	// checking preprocess result
	if result.tokenizerError != nil || result.predictError != nil {
		return fmt.Errorf("failed to preprocess, tokenizer err: %v, predict err: %v",
			result.tokenizerError, result.predictError)
	}

	return nil
}

// GetInsNum get the number of instances in the instance pool
func (m *GlobalSchedulerManager) GetInsNum() int {
	return m.instanceManager.getInsNum()
}

func (m *GlobalSchedulerManager) checkReqSurvival() {
	m.instanceManager.checkReqSurvival(m.config.reqSurvivalDuration)
}

func (m *GlobalSchedulerManager) reqManagerLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(defaultReqLifeCycle)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.checkReqSurvival()
		case <-m.ctx.Done():
			log.Info().Msgf("stop checkReqSurvival")
			return
		}
	}
}

// CheckReqExists Check Req Exists or not
func (m *GlobalSchedulerManager) CheckReqExists(reqId string) bool {
	if m.instanceManager == nil {
		return true
	}

	return m.instanceManager.isReqExists(reqId)
}

// EnsureInstanceMetrics ensures instance metrics exist in cache
// This is useful for SDK mode where instances are provided directly
func (m *GlobalSchedulerManager) EnsureInstanceMetrics(instanceID string, role base.InstanceRole, groupID string) {
	m.cacheManager.EnsureInstanceMetrics(instanceID, role, groupID)
}
