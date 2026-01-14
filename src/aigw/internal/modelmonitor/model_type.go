/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Package modelmonitor provides the management of model for AIGW.
 * Create: 2025-08-14
 */

// Package modelmonitor provides the management of models for AIGW.
package modelmonitor

import (
	"fmt"
	"strconv"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	dataSyncInterval = 5 * time.Second
	maxDelay         = 16
	httpTimeOut      = 1 * time.Second
	logFreq          = 5
	maxBlockSize     = 128
)

// ModelData for create a new gs
type ModelData struct {
	Model                string `json:"requestModelName"`
	TokenizeModelName    string `json:"tokenizeModelName"`
	DeployPolicy         string `json:"deployType"`
	BlockSize            int    `json:"tokensPerBlock"`
	MaxTimeToFirstToken  string `json:"timeoutThreshForFirstToken"`
	MaxTimeBetweenTokens string `json:"timeoutThreshBetweenTokens"`
}

// DataSyncInfo DataSync Info
type DataSyncInfo struct {
	ModelList []ModelData `json:"modelList"`
}

// EventCallback Event Callback in model manager
type EventCallback struct {
	RegisterModelCb   func(config *base.GlobalSchedulerConfig) error
	UnregisterModelCb func(model string) error
}

// validateModelData validate Model Data
func validateModelData(cfg *ModelData) error {
	if err := utils.CheckStringLength(cfg.Model); err != nil {
		return err
	}
	if err := utils.CheckStringLength(cfg.TokenizeModelName); err != nil {
		return err
	}
	if cfg.DeployPolicy != "Mix" && cfg.DeployPolicy != "Sep" {
		return fmt.Errorf("deploy policy must be mixed or Sep")
	}

	if cfg.BlockSize <= 0 {
		return fmt.Errorf("block size must be > 0")
	}
	ttft, err := strconv.ParseFloat(cfg.MaxTimeToFirstToken, 64)
	if err != nil {
		log.Error().Msgf("[DS]timeoutThreshForFirstToken can not convert to number")
		return fmt.Errorf("[DS]timeoutThreshForFirstToken can not convert to number")
	}
	if ttft <= 0 {
		return fmt.Errorf("timeoutThreshForFirstToken must be > 0")
	}
	tbt, err := strconv.ParseFloat(cfg.MaxTimeBetweenTokens, 64)
	if err != nil {
		log.Error().Msgf("[DS]timeoutThreshBetweenTokens can not convert to number")
		return fmt.Errorf("[DS]timeoutThreshBetweenTokens can not convert to number")
	}
	if tbt <= 0 {
		return fmt.Errorf("timeoutThreshBetweenTokens must be > 0")
	}

	return nil
}
