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

	"huawei.com/aigw/internal/base"
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

// GetSuggestionIn specified the input parameters for GetSuggestion.
type GetSuggestionIn struct {
	UUID   string
	Prompt string
	Model  string
}

// AigwManager is the core manager of AIGW
type AigwManager struct {
	rwLock sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	config  *base.AigwConfig
	gsTable map[string]*gs.GlobalSchedulerManager

	HmacMgr        *crypto.HmacManager
	AesMgr         *crypto.AesManager
	lightgbm       *lightgbm.Booster
	tkTable        map[string]tokenizers.Tokenizer
	securitySchema string
}

// NewAigwManager creates the AigwManager for AIGW.
func NewAigwManager(config *base.AigwConfig, opts ...AIGWManagerOption) (*AigwManager, error) {
	if config == nil {
		return nil, fmt.Errorf("confg is nil")
	}
	manager := &AigwManager{
		config:  config,
		gsTable: make(map[string]*gs.GlobalSchedulerManager),
		tkTable: make(map[string]tokenizers.Tokenizer),
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

	for _, config := range gsConfigs {
		err := manager.RegisterModel(&config)
		if err != nil {
			log.Error().Msgf("init aigw error: %v", err)
			manager.Uninit()
			return err
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

	for _, tk := range manager.tkTable {
		tk.Uninit()
	}

	lightgbm.BoosterDestroy(manager.lightgbm)

	log.Info().Msgf("AigwManager uninitialized")
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
		log.Error().Msgf("[register]The length of Name is invalid. %v", err)
		return fmt.Errorf("[register]The length of Name is invalid. %v", err)
	}
	if err := utils.CheckStringLength(in.Model); err != nil {
		log.Error().Msgf("[register]The length of Model is invalid. %v", err)
		return fmt.Errorf("[register]The length of Model is invalid. %v", err)
	}
	if err := utils.CheckStringLength(in.Role); err != nil {
		log.Error().Msgf("[register]The length of Role is invalid. %v", err)
		return fmt.Errorf("[register]The length of Role is invalid. %v", err)
	}
	if len(in.GroupID) > 256 {
		log.Error().Msgf("[register]The length of GroupID is invalid. %v", "too long")
		return fmt.Errorf("[register]The length of GroupID is invalid. %v", "too long")
	}
	if err := utils.CheckIP(in.IP); err != nil {
		log.Error().Msgf("[register]IP is invalid. %v", err)
		return fmt.Errorf("[register]IP is invalid. %v", err)
	}
	if err := utils.CheckPort(in.Port); err != nil {
		log.Error().Msgf("[register]Port is invalid. %v", err)
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
		Model: in.Model,
		IP:    in.IP,
		Port:  in.Port,
	}
	return manager.executeControlOperation(in.Model, req, "unregister instance")
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

	req, e1 := gs.NewLlmRequest(in.UUID, in.Prompt)
	if e1 != nil {
		return nil, e1
	}

	// do tokenization and execute lightGBM prediction
	if err := m.PreprocessForSchedule(req); err != nil {
		return nil, err
	}

	rsp := make(chan interface{}, 1)
	msg := &gs.ControlMessage{
		Request: &gs.ScheduleRequestMsg{
			Request: req,
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
			}, nil
		case error:
			return nil, result
		default:
			return nil, fmt.Errorf("unexpected type of suggestion result")
		}
	case <-time.After(waitResponseTimeout):
		return nil, fmt.Errorf("wait for schedule response of timeout")
	}
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

// RegisterModel create a gs for model
func (manager *AigwManager) RegisterModel(config *base.GlobalSchedulerConfig) error {
	if len(manager.gsTable) >= manager.config.Limits.ModelNum {
		log.ErrorAlarmMsgf(log.DataSyncModelRegistrationLimitExceeded, log.Report,
			fmt.Sprintf("the number of the models has reached the upper limit of %v",
				manager.config.Limits.ModelNum))
		return fmt.Errorf("the number of models has reached the upper limit")
	}

	tk, exists := manager.tkTable[config.TokenizeModelName]
	if !exists {
		return fmt.Errorf("the tokenizeModelName %v is not exist", config.TokenizeModelName)
	}
	g, err := gs.NewGlobalSchedulerManager(
		manager.ctx,
		gs.WithModel(config.Model),
		gs.WithDeploymentPolicy(config.DeployPolicy),
		gs.WithPredict(manager.config.Predictor.PredictType, manager.lightgbm),
		gs.WithTokenizer(tk),
		gs.WithSLOThreshold(config.MaxTimeToFirstToken, config.MaxTimeBetweenTokens),
		gs.WithAlgorithmThreshold(config.LoadBalancer.ReservedBlockNumber, config.LoadBalancer.BatchSize,
			config.LoadBalancer.PowerOfTwo, config.BlockSize),
		gs.WithLBType(config.LoadBalancer.Mixed, config.LoadBalancer.Prefill, config.LoadBalancer.Decode),
		gs.WithSnapFreq(manager.config.GlobalConfig.SnapshotUpdateInterval),
		gs.WithCrypto(manager.HmacMgr, manager.AesMgr),
		gs.WithInsConnectType(config.InsConnectType),
		gs.WithInsNumLimit(manager.config.Limits.InsNumPerModel),
		gs.WithReqSurvivalDuration(manager.config.GlobalConfig.ReqTimeout),
	)
	if err != nil {
		return err
	}
	manager.rwLock.Lock()
	defer manager.rwLock.Unlock()
	if _, ok := manager.gsTable[config.Model]; ok {

		return fmt.Errorf("model %v already exist", config.Model)
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
