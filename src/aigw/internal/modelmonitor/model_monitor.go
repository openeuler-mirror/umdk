/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package modelmonitor provides the management of model for AIGW.
 * Create: 2025-08-14
 */

// Package modelmonitor provides the management of models for AIGW.
package modelmonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

// ModelManager model manager
type ModelManager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	wg       *sync.WaitGroup
	mux      sync.RWMutex
	interval time.Duration
	gsTable  map[string]bool

	client       *http.Client
	queryURL     string
	queryTimeout time.Duration
	retryTimes   uint32

	hmacMgr  *crypto.HmacManager
	callback EventCallback
}

// NewModelManager create a ModelManager
func NewModelManager(queryURL string, callback EventCallback, hmacMgr *crypto.HmacManager, interval int) *ModelManager {
	log.Info().Msgf("init modelManager, the url is %v", queryURL)
	ctx, cancel := context.WithCancel(context.Background())
	return &ModelManager{
		gsTable:  make(map[string]bool),
		client:   &http.Client{Timeout: httpTimeOut},
		interval: time.Duration(interval) * time.Second,
		queryURL: queryURL,
		ctx:      ctx,
		cancel:   cancel,
		wg:       new(sync.WaitGroup),
		callback: callback,
		hmacMgr:  hmacMgr,
	}
}

func (m *ModelManager) addGs(data ModelData) {
	lbCfg := base.LoadBalancerConfig{
		Mixed:               "",
		Prefill:             "",
		Decode:              "",
		BatchSize:           32,
		PowerOfTwo:          false,
		ReservedBlockNumber: 20,
		MinMatchedLength:    200,
	}

	if data.DeployPolicy == "Mix" {
		lbCfg.Mixed = "capacity"
	} else if data.DeployPolicy == "Sep" {
		lbCfg.Prefill = "capacity"
		lbCfg.Decode = "decode"
	} else {
		log.Error().Msgf("add model by dataSync error: the deployPolicy is %v", data.DeployPolicy)
		return
	}

	ttft, err := strconv.ParseFloat(data.MaxTimeToFirstToken, 64)
	if err != nil {
		log.Error().Msgf("[DS]timeoutThreshForFirstToken can not convert to number")
		return
	}
	tbt, err := strconv.ParseFloat(data.MaxTimeBetweenTokens, 64)
	if err != nil {
		log.Error().Msgf("[DS]timeoutThreshBetweenTokens can not convert to number")
		return
	}
	if data.DeployPolicy == "Mix" {
		data.DeployPolicy = "mixed"
	} else if data.DeployPolicy == "Sep" {
		data.DeployPolicy = "separated"
	} else {
		log.Error().Msgf("[DS] the deployPolicy is invalid: %v", data.DeployPolicy)
		return
	}
	cfg := &base.GlobalSchedulerConfig{
		Model:                data.Model,
		BlockSize:            data.BlockSize,
		DeployPolicy:         data.DeployPolicy,
		MaxTimeBetweenTokens: tbt,
		MaxTimeToFirstToken:  ttft,
		TokenizeModelName:    data.TokenizeModelName,
		LoadBalancer:         lbCfg,
		InsConnectType:       "sse",
	}
	if err = m.callback.RegisterModelCb(cfg); err != nil {
		log.Warn().Msgf("add model error: %v", err)
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	m.gsTable[data.Model] = true
	log.Info().Msgf("add model %v successfully", data.Model)

}

func (m *ModelManager) delGs(model string) {
	err := m.callback.UnregisterModelCb(model)
	if err != nil {
		log.Warn().Msgf("del model error: %v", err)
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	delete(m.gsTable, model)
	log.Info().Msgf("del model %v successfully", model)
}

func (m *ModelManager) diff(remoteList []ModelData) ([]ModelData, []string) {
	var toAdd []ModelData
	var toDel []string

	m.mux.RLock()
	defer m.mux.RUnlock()

	remoteSet := make(map[string]struct{})
	for _, rm := range remoteList {
		remoteSet[rm.Model] = struct{}{}
		if _, ok := m.gsTable[rm.Model]; !ok {
			toAdd = append(toAdd, rm)
		}
	}

	for name := range m.gsTable {
		if _, ok := remoteSet[name]; !ok {
			toDel = append(toDel, name)
		}
	}
	return toAdd, toDel
}

func (m *ModelManager) fetchOnce() ([]ModelData, error) {
	req, err := http.NewRequest("GET", m.queryURL, nil)
	if err != nil {
		return []ModelData{}, err
	}

	if m.hmacMgr.EnableHmac() {
		if err = m.hmacMgr.AddHmacSign(req, ""); err != nil {
			return []ModelData{}, err
		}
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return []ModelData{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []ModelData{}, fmt.Errorf("bad status: %s", resp.Status)
	}

	var info DataSyncInfo
	if resp.Body == nil || resp.ContentLength == 0 {
		log.Error().Msgf("get dataSync, the body is nil")
		return []ModelData{}, nil
	}

	if resp.ContentLength > utils.MaxMessageLength {
		log.Error().Msgf("get dataSync, the body is too long")
		return []ModelData{}, fmt.Errorf("get dataSync, the body is too long")
	}

	if err = json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return []ModelData{}, err
	}
	log.Debug().Msgf("[DS] %+v", info)
	list := info.ModelList
	return list, nil
}

func (m *ModelManager) fetchRemote() []ModelData {
	m.retryTimes = 0

	for {
		select {
		case <-m.ctx.Done():
			return nil
		default:
			remoteList, err := m.fetchOnce()
			if err == nil {
				return remoteList
			}
			if m.retryTimes%logFreq == 0 {
				log.ErrorAlarmMsgf(log.DataSyncFetchFailed, log.Report,
					fmt.Sprintf("fetch data sync error: %v", err))
			}
			m.retryTimes += 1
			interval := utils.GetExpBackoffDelay(m.retryTimes, maxDelay)
			utils.SleepWithContext(m.ctx, interval)
		}
	}
}

// Start loop this model monitor
func (m *ModelManager) Start() error {
	log.Info().Msgf("start model moniter")
	models, err := m.fetchOnce()
	if err != nil {
		log.ErrorAlarmMsgf(log.DataSyncFetchFailed, log.Report, fmt.Sprintf("get dataSync failed, %v", err))
		return fmt.Errorf("get dataSync failed, %v", err)
	}
	for _, add := range models {
		if err := validateModelData(&add); err != nil {
			log.Error().Msgf("add model error, %v", err)
			continue
		}
		log.Debug().Msgf("add model: %s", add.Model)
		m.addGs(add)
	}
	m.wg.Add(1)
	go m.loop()
	log.Info().Msgf("start model moniter and init models successfully")
	return nil
}

// Stop  close loop
func (m *ModelManager) Stop() {
	log.Info().Msgf("stop model moniter")
	m.cancel()
	m.wg.Wait()
	log.Info().Msgf("stop model moniter successfully")
}

func (m *ModelManager) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			log.Info().Msgf("modelManager exit")
			return
		case <-ticker.C:
			m.updateModel()
		}
	}
}

func (m *ModelManager) updateModel() {
	remoteList := m.fetchRemote()
	if remoteList == nil {
		return
	}
	toAdd, toDel := m.diff(remoteList)

	for _, add := range toAdd {
		if err := validateModelData(&add); err != nil {
			log.Error().Msgf("add model error, %v", err)
			continue
		}
		log.Debug().Msgf("add model: %s", add.Model)
		m.addGs(add)
	}

	for _, del := range toDel {
		if err := utils.CheckStringLength(del); err != nil {
			log.Error().Msgf("del model error, %v", err)
			continue
		}
		log.Debug().Msgf("delete model: %s", del)
		m.delGs(del)
	}
}
