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
	"net"
	"sync"
	"time"

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

type deploymentPolicy int

const (
	mixedDeployment deploymentPolicy = iota
	separatedDeployment
)

func (d deploymentPolicy) String() string {
	switch d {
	case mixedDeployment:
		return "mixed"
	case separatedDeployment:
		return "separated"
	default:
		return "unknown"
	}
}

type predictorType int

const (
	predictTypeNone predictorType = iota
	predictTypeEma
	predictTypeLightgbm
)

func (p predictorType) String() string {
	switch p {
	case predictTypeNone:
		return "none"
	case predictTypeEma:
		return "ema"
	case predictTypeLightgbm:
		return "lightgbm"
	default:
		return "unknown"
	}
}

// globalSchedulerManagerConfig describes the configuration of GS Manager.
type globalSchedulerManagerConfig struct {
	model        string
	deployPolicy deploymentPolicy
	predictType  predictorType

	lbConfig AlgorithmParams

	insSnapShotFreq time.Duration
	hmacMgr         *crypto.HmacManager
	aesMgr          *crypto.AesManager
	insConnectType  string
}

// GlobalSchedulerManager is the GS manager
type GlobalSchedulerManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup

	config *globalSchedulerManagerConfig

	controlChannel   chan *ControlMessage
	scheduleChannel  chan *ControlMessage
	reqStatusChannel chan *ControlMessage

	dispatcher        *globalScheduleDispatcher
	instanceManager   *instanceManager
	prefillInsManager *instanceManager
	decodeInsManager  *instanceManager

	scheduler loadBalancer

	tokenizer      tokenizers.Tokenizer
	lgm            *lightgbm.Booster
	stats          *stats.DataPlaneStats
	maxInsNumPerGS int

	reqSurvivalDuration int64 // the survival duration for request, unit is second
}

// AlgorithmParams when pdMode=mixedDeployment, decodeScheduler is not effective
type AlgorithmParams struct {
	pdMode    deploymentPolicy
	pdMixedLB loadBalancerType
	prefillLB loadBalancerType
	decodeLB  loadBalancerType

	blockSize         int
	batchSize         int
	minBlockThreshold int
	tbtThreshold      float64 // ms
	ttftThreshold     float64 // ms

	statsFunc func(statType stats.StatType)

	powerOfTwo  bool
	predictType predictorType
	// each algorithm has its own parameters
}

// NewGlobalSchedulerManager creates a new GS with options
func NewGlobalSchedulerManager(parentCtx context.Context,
	opts ...GlobalSchedulerManagerOption) (*GlobalSchedulerManager, error) {

	manager := &GlobalSchedulerManager{
		wg: new(sync.WaitGroup),

		config: &globalSchedulerManagerConfig{
			model:        "",
			deployPolicy: mixedDeployment,
			predictType:  predictTypeNone,
		},

		controlChannel:   make(chan *ControlMessage, chanBufferSize),
		scheduleChannel:  make(chan *ControlMessage, chanBufferSize),
		reqStatusChannel: make(chan *ControlMessage, chanBufferSize),

		instanceManager:   newInstanceManager(),
		prefillInsManager: newInstanceManager(),
		decodeInsManager:  newInstanceManager(),
		scheduler:         nil,
		stats:             stats.NewDataPlaneStats(),
		maxInsNumPerGS:    defaultInsNumPerGs,
	}
	manager.ctx, manager.cancel = context.WithCancel(parentCtx)

	for _, opt := range opts {
		if e := opt(manager); e != nil {
			return nil, e
		}
	}

	manager.config.lbConfig.pdMode = manager.config.deployPolicy
	manager.config.lbConfig.predictType = manager.config.predictType
	manager.config.lbConfig.statsFunc = func(statType stats.StatType) {
		manager.stats.Record(statType)
	}
	manager.instanceManager.insSnapShotFreq = manager.config.insSnapShotFreq
	manager.instanceManager.aesMgr = manager.config.aesMgr
	manager.instanceManager.insConnectType = manager.config.insConnectType
	manager.instanceManager.hmacMgr = manager.config.hmacMgr

	manager.prefillInsManager.insSnapShotFreq = manager.config.insSnapShotFreq
	manager.prefillInsManager.aesMgr = manager.config.aesMgr
	manager.prefillInsManager.insConnectType = manager.config.insConnectType
	manager.prefillInsManager.hmacMgr = manager.config.hmacMgr

	manager.decodeInsManager.insSnapShotFreq = manager.config.insSnapShotFreq
	manager.decodeInsManager.aesMgr = manager.config.aesMgr
	manager.decodeInsManager.insConnectType = manager.config.insConnectType
	manager.decodeInsManager.hmacMgr = manager.config.hmacMgr

	gsLB, err := newLoadBalancer(manager, &manager.config.lbConfig)
	if err != nil {
		return nil, err
	}
	manager.scheduler = gsLB

	manager.dispatcher = newGlobalScheduleDispatcher(manager.ctx)

	return manager, nil
}

// Start the GS
func (m *GlobalSchedulerManager) Start() error {
	log.Info().Msgf("starting global scheduler, model %v.", m.config.model)

	if m.config.deployPolicy == mixedDeployment {
		m.instanceManager.start()
		log.Info().Msgf("start mixInsManager successfully, model %v.", m.config.model)
	} else if m.config.deployPolicy == separatedDeployment {
		m.prefillInsManager.start()
		log.Info().Msgf("start prefillInsManager successfully, model %v.", m.config.model)
		m.decodeInsManager.start()
		log.Info().Msgf("start decodeInsManager successfully, model %v.", m.config.model)
	} else {
		return fmt.Errorf("error deploy policy: %v", m.config.deployPolicy)
	}

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
	m.instanceManager.stop()

	log.Info().Msgf("stop GlobalScheduler successfully, model %v.", m.config.model)
}

// GetStats Get the stats of GlobalSchedulerManager
func (m *GlobalSchedulerManager) GetStats() map[string]uint64 {
	return m.stats.GetStatsMap()
}

func (m *GlobalSchedulerManager) registerInstance(ctrlMsg *ControlMessage) {
	if m.GetInsNum() >= m.maxInsNumPerGS {
		err := fmt.Errorf("the number of instance exceeds the maximum limit of gs(%v)",
			m.maxInsNumPerGS)
		log.ErrorAlarmMsgf(log.PerGSInstanceLimitExceeded, log.Report, fmt.Sprintf("%v", err))
		ctrlMsg.Response <- err
		return
	}
	registerMsg, ok := ctrlMsg.Request.(*RegisterInstanceMsg)
	if !ok {
		ctrlMsg.Response <- fmt.Errorf("invalid register instance msg, req %v", ctrlMsg.Request)
		return
	}

	role, err := toInstanceRole(registerMsg.Role)
	if err != nil {
		ctrlMsg.Response <- err
		return
	}
	ip := net.ParseIP(registerMsg.IP)
	insUrl := net.JoinHostPort(ip.String(), registerMsg.Port)

	if m.config.deployPolicy == separatedDeployment && registerMsg.GroupID == "" {
		ctrlMsg.Response <- fmt.Errorf("groupId can't be empty in separated")
		return
	}

	switch role {
	case mixedRoleInstance:
		if m.config.deployPolicy != mixedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add mixed", m.config.deployPolicy)
			break
		}
		err = m.instanceManager.addInstance(insUrl, role, registerMsg.GroupID, m.reqStatusChannel)
		m.instanceManager.updatePoolShot()
	case prefillRoleInstance:
		if m.config.deployPolicy != separatedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add prefill", m.config.deployPolicy)
			break
		}
		err = m.prefillInsManager.addInstance(insUrl, role, registerMsg.GroupID, m.reqStatusChannel)
		m.prefillInsManager.updatePoolShot()
	case decodeRoleInstance:
		if m.config.deployPolicy != separatedDeployment {
			err = fmt.Errorf("the deployPolicy of model is %v, can't add decode", m.config.deployPolicy)
			break
		}
		err = m.decodeInsManager.addInstance(insUrl, role, registerMsg.GroupID, m.reqStatusChannel)
		m.decodeInsManager.updatePoolShot()
	default:
		err = fmt.Errorf("register instance failed, error ins role %v", role)
	}
	if err != nil {
		log.Error().Msgf("%v", err)
		ctrlMsg.Response <- err
		return
	}

	log.Info().Msgf("instance %s registered successfully", registerMsg.Name)
	ctrlMsg.Response <- nil
}

func (m *GlobalSchedulerManager) unregisterInstance(ctrlMsg *ControlMessage) {
	unregisterMsg, ok := ctrlMsg.Request.(*UnregisterInstanceMsg)
	if !ok {
		ctrlMsg.Response <- fmt.Errorf("invalid unregister instance msg, req %v", ctrlMsg.Request)
		return
	}
	ip := net.ParseIP(unregisterMsg.IP)
	insUrl := net.JoinHostPort(ip.String(), unregisterMsg.Port)

	removed := false
	if m.config.deployPolicy == mixedDeployment {
		removed = m.instanceManager.removeInstance(insUrl)
	} else {
		removed = m.prefillInsManager.removeInstance(insUrl) || m.decodeInsManager.removeInstance(insUrl)
	}

	if !removed {
		log.Error().Msgf("instance %s not found", insUrl)
		ctrlMsg.Response <- fmt.Errorf("instance %s not found", insUrl)
		return
	}
	m.instanceManager.updatePoolShot()

	log.Info().Msgf("instance (%v:%v) unregistered successfully", unregisterMsg.IP, unregisterMsg.Port)
	ctrlMsg.Response <- nil
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

func (m *GlobalSchedulerManager) recordScheduleStats(result *scheduleResult) {
	var statType stats.StatType
	switch m.config.deployPolicy {
	case mixedDeployment:
		if result.prefillUrl == "" {
			statType = stats.ScheduleFailure
		} else {
			statType = stats.ScheduleSuccess
		}
	case separatedDeployment:
		if result.prefillUrl != "" && result.decodeUrl != "" {
			statType = stats.ScheduleSuccess
		} else {
			statType = stats.ScheduleFailure
		}
	default:
		statType = stats.ScheduleFailure
	}
	m.stats.Record(statType)
}

func (m *GlobalSchedulerManager) scheduleLoop() {
	defer m.wg.Done()
	for {
		select {
		case msg := <-m.scheduleChannel:
			switch request := msg.Request.(type) {
			case *ScheduleRequestMsg:
				result := m.scheduler.schedule(request, "", nil)
				m.recordScheduleStats(result)

				dispatchMsg := &ControlMessage{
					Request: &ExecuteDispatchMsg{
						Result: result,
					},
					Response: msg.Response,
				}

				m.dispatcher.dispatchChan <- dispatchMsg

				// clear request after schedule
				request.Request.Prompt = ""
				request.Request.promptToken = nil

			default:
				log.Warn().Msgf("unknown schedule message type: %v", request)
				msg.Response <- fmt.Errorf("unknown schedule message type: %v", request)
			}
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

	tokenIds, err := m.tokenizer.Encode(req.Prompt)
	if err != nil {
		log.Debug().Msgf("failed to encode in tokenizer, err: %v", err)
		result.tokenizerError = err
		m.stats.Record(stats.TokenizerEncodeError)
	} else {
		if tokenIds != nil {
			log.Debug().Msgf("[tokenizer] req %v has %v tokens", req.ReqId, len(tokenIds))
			req.SetPromptAttrs(tokenIds)
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
	req.predictDecodeLen = decodeLen
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

	if m.config.predictType == predictTypeLightgbm {
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
	if m.config.deployPolicy == mixedDeployment {
		return m.instanceManager.getInsNum()
	}

	if m.config.deployPolicy == separatedDeployment {
		return m.prefillInsManager.getInsNum() + m.decodeInsManager.getInsNum()
	}
	return 0
}

func (m *GlobalSchedulerManager) checkReqSurvival() {
	if m.config.deployPolicy == mixedDeployment {
		m.instanceManager.checkReqSurvival(m.reqSurvivalDuration)
	}
	if m.config.deployPolicy == separatedDeployment {
		m.prefillInsManager.checkReqSurvival(m.reqSurvivalDuration)
		m.decodeInsManager.checkReqSurvival(m.reqSurvivalDuration)
	}
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
	if m.config.deployPolicy == mixedDeployment {
		return m.instanceManager.isReqExists(reqId)
	}

	if m.config.deployPolicy == separatedDeployment {
		return m.prefillInsManager.isReqExists(reqId) || m.decodeInsManager.isReqExists(reqId)
	}

	return false
}
