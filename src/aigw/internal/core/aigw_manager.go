/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: AigwManager is the global manager for AIGW.
 * Create: 2025-06-05
 */

// Package core contains the core functions for AIGW.
package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/apipool"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/gs"
	"huawei.com/aigw/internal/tokenizers"
	"huawei.com/aigw/internal/vectorizer"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/lightgbm"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	waitResponseTimeout = 3 * time.Second
)

const (
	maxGroupIDLength = 256 // The Default Max Length of GroupID
)

// GetSuggestionIn specified the input parameters for GetSuggestion.
type GetSuggestionIn struct {
	UUID   string
	Prompt string
	Model  string
	// Headers and Body are used for consistent hash key extraction.
	// Headers maps HTTP header names to values (e.g., "X-Session-Id" -> "session-123").
	Headers map[string]string
	// Body contains the parsed request body fields for hash key extraction
	// (e.g., "user", "session_id", "session_params.session_id").
	Body map[string]interface{}
}

// AigwManager is the core manager of AIGW
type AigwManager struct {
	rwLock sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	config  *base.AigwConfig
	gsTable map[string]*gs.GlobalSchedulerManager

	poolTable    map[string]*apipool.ApiPoolManager
	apiPoolState *apipool.State
	registry     *apipool.Registry

	// agentRegistry tracks agent lifecycle (register/heartbeat/recover/gone) for KVC
	// management. nil when KVC disabled (SdkMode or kvc.enabled=false). Wired in H1.
	agentRegistry agentregistry.Registry

	HmacMgr        *crypto.HmacManager
	AesMgr         *crypto.AesManager
	lightgbm       *lightgbm.Booster
	tkTable        map[string]tokenizers.Tokenizer
	securitySchema string
	runtimeMode    base.RuntimeMode

	CacheDriverOps *cachecenter.CacheDriverOps
}

// NewAigwManager creates the AigwManager for AIGW.
func NewAigwManager(config *base.AigwConfig, opts ...AIGWManagerOption) (*AigwManager, error) {
	if config == nil {
		return nil, fmt.Errorf("confg is nil")
	}
	manager := &AigwManager{
		config:    config,
		gsTable:   make(map[string]*gs.GlobalSchedulerManager),
		tkTable:   make(map[string]tokenizers.Tokenizer),
		poolTable: make(map[string]*apipool.ApiPoolManager),
		registry:  apipool.NewDefaultRegistry(),
	}

	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	for _, opt := range opts {
		if e := opt(manager); e != nil {
			return nil, e
		}
	}

	return manager, nil
}

// Init the AIGW manager.
func (manager *AigwManager) Init() error {
	gsConfigs := manager.config.GsConfigs
	predictor := &manager.config.Predictor
	if predictor.PredictType == "lightgbm" {
		if err := manager.createGBM(predictor.Lightgbm.ClassifierFile, predictor.Lightgbm.VectorizerFile); err != nil {
			manager.Uninit()
			return err
		}
	}

	for _, tkCfg := range manager.config.Tokenizers {
		if err := manager.createTokenizer(tkCfg.TokenizeModelName, tkCfg.ConfigPath); err != nil {
			manager.Uninit()
			return err
		}
	}

	// Build shared provider-pool State. Cooldown config is taken from the last
	// provider pool encountered; all pools share one State (cross-pool quota).
	manager.apiPoolState = apipool.NewState(defaultCooldownConfig())

	// Phase 2: construct the AgentRegistry when KVC management is enabled (ServiceMode +
	// kvc.enabled). The registry is passed into each RegisterModel call so the per-model
	// GlobalSchedulerManager can build its KvcSessionManager. SdkMode / disabled = nil.
	if manager.runtimeMode == base.ServiceMode && manager.config.Kvc.Enabled {
		cfg := manager.config.Kvc.Agent
		manager.agentRegistry = agentregistry.NewRegistry(agentregistry.RealClock{}, agentregistry.RegistryConfig{
			HeartbeatTimeoutSec: cfg.HeartbeatTimeoutSec,
			RecoverWindowSec:    cfg.RecoverWindowSec,
			RecoverTimeoutSec:   cfg.RecoverTimeoutSec,
			GoneFinalizeSec:     cfg.GoneFinalizeSec,
			RegisterGraceSec:    cfg.RegisterGraceSec,
		})
		manager.agentRegistry.Start()
	}

	for i := range gsConfigs {
		gsc := gsConfigs[i]
		mode := gsc.Mode
		if mode == "" {
			mode = "instance"
		}
		switch mode {
		case "provider":
			if manager.runtimeMode == base.SdkMode {
				manager.Uninit()
				return fmt.Errorf("SdkMode does not support provider mode (model %q)", gsc.Model)
			}
			if gsc.ProviderPool != nil && gsc.ProviderPool.Cooldown != nil {
				manager.apiPoolState.SetCooldownConfig(gsc.ProviderPool.Cooldown)
			}
			pool, err := apipool.NewApiPoolManager(gsc.Model, gsc.ProviderPool, manager.apiPoolState, manager.registry)
			if err != nil {
				manager.Uninit()
				return err
			}
			manager.poolTable[gsc.Model] = pool
		default:
			if err := manager.RegisterModel(&gsc); err != nil {
				log.Error().Msgf("init aigw error: %v", err)
				manager.Uninit()
				return err
			}
		}
	}

	log.Info().Msgf("initialize AigwManager successfully")
	return nil
}

// Uninit the AIGW manager.
func (manager *AigwManager) Uninit() {
	log.Info().Msgf("start to uninit AigwManager")
	manager.cancel()

	for _, g := range manager.gsTable {
		g.Stop()
	}

	// Phase 2: stop the AgentRegistry (aging loop) if KVC management was enabled.
	if manager.agentRegistry != nil {
		manager.agentRegistry.Stop()
	}

	for _, tk := range manager.tkTable {
		tk.Uninit()
	}

	lightgbm.BoosterDestroy(manager.lightgbm)

	log.Info().Msgf("AigwManager uninitialized")
}

// defaultCooldownConfig returns sane defaults used until a provider pool overrides it.
func defaultCooldownConfig() *base.CooldownConfig {
	return &base.CooldownConfig{FailureThreshold: 3, DurationSec: 60, RateLimitDurationSec: 90, Auth401FloorSec: 300}
}

// GetModelMode returns "instance" or "provider" for a configured model.
func (manager *AigwManager) GetModelMode(model string) (string, error) {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	if _, ok := manager.poolTable[model]; ok {
		return "provider", nil
	}
	if _, ok := manager.gsTable[model]; ok {
		return "instance", nil
	}
	return "", fmt.Errorf("unknown model %q", model)
}

// GetApiPool returns the provider pool for a model, or nil if not a provider model.
func (manager *AigwManager) GetApiPool(model string) *apipool.ApiPoolManager {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	return manager.poolTable[model]
}

// GetContext returns the manager context.
func (manager *AigwManager) GetContext() context.Context {
	return manager.ctx
}

// GetAllStats get all GlobalSchedulerMangers' stats in the AigwManger
func (manager *AigwManager) GetAllStats() *base.AigwAllStats {
	allStats := &base.AigwAllStats{
		StatsSlice: make([]*base.StatsEntry, 0),
	}
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	for modelName, mgr := range manager.gsTable {
		se := &base.StatsEntry{
			ModelName: modelName,
			Counts:    mgr.GetStats(),
		}
		allStats.StatsSlice = append(allStats.StatsSlice, se)
	}
	return allStats
}

func (manager *AigwManager) getGsManager(key string) *gs.GlobalSchedulerManager {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	g, exists := manager.gsTable[key]
	if !exists {
		return nil
	}

	return g
}

func (manager *AigwManager) executeControlOperation(model string, request interface{}, action string) error {
	m := manager.getGsManager(model)
	if m == nil {
		return fmt.Errorf("global scheduler manager with model %v not found", model)
	}

	rsp := make(chan interface{}, 1)
	msg := &gs.ControlMessage{
		Request:  request,
		Response: rsp,
	}

	m.PutControlMessage(msg)

	select {
	case err, ok := <-rsp:
		if !ok {
			return fmt.Errorf("response channel is closed")
		}
		switch err.(type) {
		case error:
			return err.(error)
		default:
			return nil
		}
	case <-time.After(waitResponseTimeout):
		log.Error().Msgf("wait for response of %v timeout", action)
		return fmt.Errorf("wait for response of %v timeout", action)
	}
}

// RegisterInstance will register a new instance with information specified in RegisterInstanceIn
func (manager *AigwManager) RegisterInstance(in *base.RegisterInstanceIn) error {
	if err := utils.CheckStringLength(in.Name); err != nil {
		return fmt.Errorf("[register]The length of Name is invalid. %v", err)
	}
	if err := utils.CheckStringLength(in.Model); err != nil {
		return fmt.Errorf("[register]The length of Model is invalid. %v", err)
	}
	if err := utils.CheckStringLength(in.Role); err != nil {
		return fmt.Errorf("[register]The length of Role is invalid. %v", err)
	}
	if len(in.GroupID) > maxGroupIDLength {
		return fmt.Errorf("[register]The length of GroupID is invalid, too long: %d > %d",
			len(in.GroupID), maxGroupIDLength)
	}
	if err := utils.CheckIP(in.IP); err != nil {
		return fmt.Errorf("[register]IP is invalid. %v", err)
	}
	if err := utils.CheckPort(in.Port); err != nil {
		return fmt.Errorf("[register]Port is invalid. %v", err)
	}
	var currentInsNum = 0
	manager.rwLock.RLock()
	for _, v := range manager.gsTable {
		currentInsNum += v.GetInsNum()
	}
	manager.rwLock.RUnlock()
	if currentInsNum >= manager.config.Limits.TotalInsNum {
		err := fmt.Errorf("the number of instance %v exceeds the maximum limit of aigw(%v)",
			currentInsNum, manager.config.Limits.TotalInsNum)
		log.ErrorAlarmMsgf(log.GlobalGSInstancesLimitExceeded, log.Report, fmt.Sprintf("%v", err))
		return err
	}
	req := &gs.RegisterInstanceMsg{
		Name:  in.Name,
		Model: in.Model,
		IP:    in.IP,
		Port:  in.Port,
		Role:  in.Role,

		GroupID: in.GroupID,
		DpRank:  in.DpRank,
	}
	return manager.executeControlOperation(in.Model, req, "register instance")
}

// UnregisterInstance will unregister an instance with information specified in UnregisterInstanceIn
func (manager *AigwManager) UnregisterInstance(in *base.UnregisterInstanceIn) error {
	err := utils.CheckStringLength(in.Model)
	if err != nil {
		log.Error().Msgf("[unregister]The length of Model is invalid. %v", err)
		return fmt.Errorf("[unregister]The length of Model is invalid. %v", err)
	}
	err = utils.CheckIP(in.IP)
	if err != nil {
		log.Error().Msgf("[unregister]IP is invalid. %v", err)
		return fmt.Errorf("[unregister]IP is invalid. %v", err)
	}
	err = utils.CheckPort(in.Port)
	if err != nil {
		log.Error().Msgf("[unregister]Port is invalid. %v", err)
		return fmt.Errorf("[unregister]Port is invalid. %v", err)
	}

	req := &gs.UnregisterInstanceMsg{
		Model:  in.Model,
		IP:     in.IP,
		Port:   in.Port,
		DpRank: in.DpRank,
	}
	return manager.executeControlOperation(in.Model, req, "unregister instance")
}

// HandlerReqEvent handle request Event
func (mananger *AigwManager) HandlerReqEvent(model, reqId, eventDesc string) error {
	m := mananger.getGsManager(model)
	if m == nil {
		return fmt.Errorf("model %v: global scheduler not found", model)
	}
	return m.HandleReqEvent(reqId, eventDesc)
}

func (manager *AigwManager) scheduleRequest(m *gs.GlobalSchedulerManager, in *GetSuggestionIn,
	candidateInstanceIDs []string) (*base.GetSuggestionOut, error) {
	req, e1 := gs.NewLlmRequest(in.UUID, in.Prompt)
	if e1 != nil {
		return nil, e1
	}
	// do tokenization and execute lightGBM prediction
	if err := m.PreprocessForSchedule(req); err != nil {
		return nil, err
	}

	// create a context with timeout
	ctx, cancel := context.WithTimeout(manager.ctx, waitResponseTimeout)
	defer cancel()

	rsp := make(chan interface{}, 1)
	msg := &gs.ControlMessage{
		Request: &gs.ScheduleRequestMsg{
			Request:              req,
			ReqCTX:               ctx,
			CandidateInstanceIDs: candidateInstanceIDs,
			Headers:              in.Headers,
			Body:                 in.Body,
		},
		Response: rsp,
	}

	m.PutScheduleMessage(msg)

	select {
	case out, ok := <-rsp:
		if !ok {
			return nil, fmt.Errorf("timeout to get suggestion result")
		}
		switch result := out.(type) {
		case *gs.SuggestionResultMsg:
			return &base.GetSuggestionOut{
				TargetPrefillUrl: result.PrefillUrl,
				TargetDecodeUrl:  result.DecodeUrl,
				DpRank:           result.DpRank,
			}, nil
		case error:
			return nil, result
		default:
			return nil, fmt.Errorf("unexpected type of suggestion result")
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for schedule response timeout")
	}
}

// SelectOptimalNode select the optimal node
func (manager *AigwManager) SelectOptimalNode(in *GetSuggestionIn,
	instances []*gs.RegisterInstanceMsg) (*base.GetSuggestionOut, error) {
	if len(instances) > manager.config.Limits.InsNumPerModel {
		return nil, fmt.Errorf("the number of instance exceeds the maximum limit of gs(%v)",
			manager.config.Limits.InsNumPerModel)
	}
	runeCounts := utf8.RuneCountInString(in.Prompt)
	if runeCounts > manager.config.Limits.MaxPromptRunes {
		return nil, fmt.Errorf("prompt is too long, characters nums: %v", runeCounts)
	}

	m, err := manager.FindOrCreateGs(in.Model)
	if err != nil {
		return nil, fmt.Errorf("failed to get globalScheduleManager, %v", err)
	}

	// Ensure instance metrics exist in cache before scheduling
	// This is critical for SDK mode where instances are provided directly
	instanceIDs := make([]string, 0, len(instances))
	for _, instance := range instances {
		role, err := base.ToInstanceRole(instance.Role)
		if err != nil {
			log.Warn().Msgf("invalid instance role %s for %s:%s, skip initialization",
				instance.Role, instance.IP, instance.Port)
			continue
		}
		// Build instance ID with DP rank suffix if present
		instanceID := base.BuildInstanceAddress(instance.IP, instance.Port, instance.DpRank)
		m.EnsureInstanceMetrics(instanceID, role, instance.GroupID)
		instanceIDs = append(instanceIDs, instanceID)
	}
	return manager.scheduleRequest(m, in, instanceIDs)
}

// GetSuggestion sends a schedule request to AIGW, and AIGW will give schedule suggestion.
func (manager *AigwManager) GetSuggestion(in *GetSuggestionIn) (*base.GetSuggestionOut, error) {
	err := utils.CheckStringLength(in.Model)
	if err != nil {
		log.Error().Msgf("[GetSuggestion]The length of Model is invalid. %v", err)
		return nil, fmt.Errorf("[GetSuggestion]The length of Model is invalid. %v", err)
	}
	err = utils.CheckStringLength(in.UUID)
	if err != nil {
		log.Error().Msgf("[GetSuggestion]The length of UUID is invalid. %v", err)
		return nil, fmt.Errorf("[GetSuggestion]The length of UUID is invalid. %v", err)
	}
	m := manager.getGsManager(in.Model)
	if m == nil {
		return nil, fmt.Errorf("global scheduler manager with model %v not found", in.Model)
	}

	if m.CheckReqExists(in.UUID) {
		return nil, fmt.Errorf("the request %v is exists", in.UUID)
	}

	return manager.scheduleRequest(m, in, nil)
}

func (manager *AigwManager) createGBM(gbmPath string, vectorPath string) error {
	if err := vectorizer.LoadVectorizer(vectorPath); err != nil {
		log.Error().Msgf("load pretrained vectorizer failed: %v", err)
		return fmt.Errorf("load pretrained vectorizer failed: %v", err)
	}
	boosterParams := lightgbm.BoosterParams{
		ModelFile: gbmPath,
	}
	lgm, err := lightgbm.NewBooster(boosterParams)
	if err != nil {
		log.Error().Msgf("load pretrained GBM failed: %v", err)
		return fmt.Errorf("load pretrained GBM failed: %v", err)
	}
	manager.lightgbm = lgm
	return nil
}

func (manager *AigwManager) createTokenizer(tokenizeModelName string, path string) error {
	tk, err := tokenizers.NewTokenizer(tokenizeModelName)
	if err != nil {
		log.Error().Msgf("create tokenizer error: %v", err)
		return fmt.Errorf("create tokenizer error: %v", err)
	}
	if err = tk.InitFromFile(path); err != nil {
		log.Error().Msgf("load tokenizer file error: %v", err)
		return fmt.Errorf("load tokenizer file error: %v", err)
	}
	manager.tkTable[tokenizeModelName] = tk
	return nil
}

// IsEnableZK enable zk or not
func (manager *AigwManager) IsEnableZK() bool {
	if manager.config == nil {
		return false
	}

	return strings.TrimSpace(manager.config.ZkConfig.Address) != ""
}

// FindOrCreateGs retrieves the gs; if not exist, creates a new
func (manager *AigwManager) FindOrCreateGs(model string) (*gs.GlobalSchedulerManager, error) {
	manager.rwLock.Lock()
	defer manager.rwLock.Unlock()

	if g, exists := manager.gsTable[model]; exists {
		g.Access()
		return g, nil
	}

	if len(manager.gsTable) >= manager.config.Limits.ModelNum {
		var oldestId string
		var oldestTime time.Time
		for model, g := range manager.gsTable {
			if oldestId == "" || g.LastAccessAt().Before(oldestTime) {
				oldestId = model
				oldestTime = g.LastAccessAt()
			}
		}
		manager.gsTable[oldestId].Stop()
		delete(manager.gsTable, oldestId)
		log.Info().Msgf("global scheduler up to limits of %v, del oldest gs with model %v successfully",
			manager.config.Limits.ModelNum, oldestId)
	}

	log.Info().Msgf("model: %v, globalScheduler is not exist, new a one", model)
	config := NewDefaultGsConfig(model)

	g, err := gs.NewGlobalSchedulerManager(manager.ctx, config,
		gs.WithPredict(manager.config.Predictor.PredictType, nil),
		gs.WithTokenizer(nil),
		gs.WithLBType("", "prefillTimeAware", "none"),
		gs.WithSnapFreq(1),
		gs.WithInsNumLimit(manager.config.Limits.InsNumPerModel),
		gs.WithReqSurvivalDuration(time.Duration(manager.config.GlobalConfig.ReqTimeout)*time.Second),
		gs.WithTokenizationRatio(config.TokenizationRatio),
		gs.WithCacheDriverOps(manager.CacheDriverOps),
		gs.WithRuntimeMode(manager.runtimeMode),
	)
	if err != nil {
		return nil, err
	}

	if err = g.Start(); err != nil {
		return nil, err
	}
	manager.gsTable[config.Model] = g
	log.Info().Msgf("global scheduler with model %v and deploy policy %v created", config.Model,
		config.DeployPolicy)
	return g, nil
}

// RegisterModel create a gs for model
func (manager *AigwManager) RegisterModel(config *base.GlobalSchedulerConfig) error {
	if len(manager.gsTable) >= manager.config.Limits.ModelNum {
		log.ErrorAlarmMsgf(log.DataSyncModelRegistrationLimitExceeded, log.Report,
			fmt.Sprintf("the number of the models has reached the upper limit of %v",
				manager.config.Limits.ModelNum))
		return fmt.Errorf("the number of models has reached the upper limit")
	}

	// aigw support run without tokenizer, when TokenizeModelName is empty
	tk, exists := manager.tkTable[config.TokenizeModelName]
	if config.TokenizeModelName != "" && !exists {
		return fmt.Errorf("the tokenizeModelName %v is not exist", config.TokenizeModelName)
	}
	g, err := gs.NewGlobalSchedulerManager(manager.ctx, config,
		gs.WithPredict(manager.config.Predictor.PredictType, manager.lightgbm),
		gs.WithTokenizer(tk),
		gs.WithSnapFreq(manager.config.GlobalConfig.SnapshotUpdateInterval),
		gs.WithCrypto(manager.HmacMgr, manager.AesMgr),
		gs.WithInsNumLimit(manager.config.Limits.InsNumPerModel),
		gs.WithReqSurvivalDuration(time.Duration(manager.config.GlobalConfig.ReqTimeout)*time.Second),
		gs.WithTokenizationRatio(config.TokenizationRatio),
		gs.WithCacheDriverOps(manager.CacheDriverOps),
		gs.WithRuntimeMode(manager.runtimeMode),
		gs.WithKvc(manager.agentRegistry, manager.config.Kvc, agentregistry.RealClock{}),
	)
	if err != nil {
		return err
	}
	manager.rwLock.Lock()
	defer manager.rwLock.Unlock()
	if oldGs, ok := manager.gsTable[config.Model]; ok {
		oldGs.Stop()
		delete(manager.gsTable, config.Model)
		log.Info().Msgf("model %v already exist, delete it", config.Model)
	}

	log.Info().Msgf("global scheduler with model %v and deploy policy %v created", config.Model,
		config.DeployPolicy)

	if err = g.Start(); err != nil {
		return err
	}

	manager.gsTable[config.Model] = g

	return nil
}

// UnregisterModel del a gs for model
func (manager *AigwManager) UnregisterModel(model string) error {
	manager.rwLock.Lock()
	defer manager.rwLock.Unlock()
	g, exists := manager.gsTable[model]
	if !exists {
		return fmt.Errorf("del GS failed, model is not exist in AIGW")
	}
	g.Stop()
	delete(manager.gsTable, model)
	log.Info().Msgf("del global scheduler with model %v successfully", model)
	return nil
}

// GetAgentRegistry returns the AgentRegistry (nil if KVC management is disabled).
// HTTP agent lifecycle handlers (G1) use this to gate on ServiceMode + kvc.enabled.
func (manager *AigwManager) GetAgentRegistry() agentregistry.Registry {
	return manager.agentRegistry
}

// GetGsManagerByModel returns the GlobalSchedulerManager for a model (nil if absent).
func (manager *AigwManager) GetGsManagerByModel(model string) *gs.GlobalSchedulerManager {
	manager.rwLock.RLock()
	defer manager.rwLock.RUnlock()
	return manager.gsTable[model]
}

// CloseSession closes a session across all GS managers' KvcSessionManagers (session-close
// is session-scoped; the caller may not know the backing model). Session IDs are globally
// unique in practice (UUIDs), so at most one manager matches. Dispatches an evict hint.
func (manager *AigwManager) CloseSession(sessionID string) error {
	manager.rwLock.RLock()
	models := make([]string, 0, len(manager.gsTable))
	for model := range manager.gsTable {
		models = append(models, model)
	}
	manager.rwLock.RUnlock()
	for _, model := range models {
		g := manager.GetGsManagerByModel(model)
		if g == nil {
			continue
		}
		if kvcMgr := g.GetKvcSessionManager(); kvcMgr != nil {
			if err := kvcMgr.CloseSession(sessionID); err != nil {
				return err
			}
		}
	}
	return nil
}

// NewAigwManagerForTest constructs a minimal AigwManager for HTTP/KVC tests, bypassing
// the full Init() (which needs ZK/tokenizers/lightgbm). Production wiring is done by
// NewAigwManager + Init + startManagers (H1). Test-only.
func NewAigwManagerForTest(cfg *base.AigwConfig, reg agentregistry.Registry, gsTable map[string]*gs.GlobalSchedulerManager) *AigwManager {
	return &AigwManager{
		config:        cfg,
		gsTable:       gsTable,
		agentRegistry: reg,
		runtimeMode:   base.ServiceMode,
	}
}
