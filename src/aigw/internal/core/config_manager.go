/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: definitions for config manager
 * Create: 2025-06-21
 */

// Package core contains the base definitions for AIGW.
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	// defaultLogPath default AIGW log path
	defaultLogPath = "/var/log/aigw/"
	// defaultLogLevel default AIGW log level
	defaultLogLevel = "info"
	// defaultPort default AIGW HTTP server listen port
	defaultPort = "8888"
	// defaultHost default AIGW HTTP server listen host
	defaultHost = "127.0.0.1"

	// defaultZkConnectTimeout default ZooKeeper ConnectTimeout, unit is second
	defaultZkConnectTimeout = 60

	// defaultZkSessionTimeout unit is second, depends on the configuration of the server,
	// see minSessionTimeout and maxSessionTimeout of server
	defaultZkSessionTimeout = 40

	defaultSnapshotInternal = 3

	maxTotalInstanceNum = 4096
	maxConcurrency      = 512
	// default datasync max interval, the unit is second
	dataSyncMaxInterval = 600

	maxPromptRunes = 128 * 1024
	minPromptRunes = 1024
)

var validCommonLBTypes = map[string]bool{
	"roundRobin": true,
	"leastConn":  true,
	"capacity":   true,
	"token":      true,
}

var validDecodeLBTypes = map[string]bool{
	"roundRobin": true,
	"leastConn":  true,
	"capacity":   true,
	"token":      true,
	"decode":     true,
}

var validPredictorTypes = map[string]bool{
	"none":     true,
	"ema":      true,
	"lightgbm": true,
}

var validDeployPolicies = map[string]bool{
	"mixed":     true,
	"separated": true,
}

var validAclSchemes = map[string]bool{
	"default": true,
	"digest":  true,
}

var securitySchema = map[string]bool{
	"default": true,
	"mep":     true,
}

// AigwConfigManager is the manager for AIGW config.
type AigwConfigManager struct {
	config base.AigwConfig
}

// NewAigwConfigManager creates a new configManager.
func NewAigwConfigManager() *AigwConfigManager {
	return &AigwConfigManager{}
}

// GetAigwConfig returns reference of AigwConfig
func (m *AigwConfigManager) GetAigwConfig() *base.AigwConfig {
	return &m.config
}

// GetZkConfig returns reference of ZkConfig
func (m *AigwConfigManager) GetZkConfig() *base.ZookeeperConfig {
	return &m.config.ZkConfig
}

// GetMonitorConfig returns reference of MonitorConfig
func (m *AigwConfigManager) GetMonitorConfig() *base.MonitorConfig {
	return &m.config.MonitorConfig
}

// GetDataSyncConfig returns reference of DataSyncConfig
func (m *AigwConfigManager) GetDataSyncConfig() *base.DataSyncConfig {
	return &m.config.DataSyncConfig
}

func resetDefault(cfg *base.AigwConfig) {
	// checking global
	globalCfg := &cfg.GlobalConfig
	if strings.TrimSpace(globalCfg.Host) == "" {
		globalCfg.Host = defaultHost
	}
	if strings.TrimSpace(globalCfg.Port) == "" {
		globalCfg.Port = defaultPort
	}
	if strings.TrimSpace(globalCfg.LogPath) == "" {
		globalCfg.LogPath = defaultLogPath
	}
	if strings.TrimSpace(globalCfg.LogLevel) == "" {
		globalCfg.LogLevel = defaultLogLevel
	}

	// checking ZkConfig
	zkCfg := &cfg.ZkConfig
	if strings.TrimSpace(zkCfg.Address) != "" {
		if strings.TrimSpace(zkCfg.AclScheme) == "" {
			zkCfg.AclScheme = "default"
		}
		if zkCfg.ConnectTimeout == 0 {
			zkCfg.ConnectTimeout = defaultZkConnectTimeout
		}
		if zkCfg.SessionTimeout == 0 {
			zkCfg.SessionTimeout = defaultZkSessionTimeout
		}
	}
}

// LoadConfig loads the config from file
func (m *AigwConfigManager) LoadConfig(filePath string) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config base.AigwConfig
	if err := json.Unmarshal(file, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// reset value to default for some fields
	resetDefault(&config)

	m.config = config
	return nil
}

func validateLoadBalancer(gsCfg *base.GlobalSchedulerConfig) error {
	if gsCfg.DeployPolicy == "mixed" && !validCommonLBTypes[gsCfg.LoadBalancer.Mixed] {
		return fmt.Errorf("invalid loadBalanceType %q for mixed deployPolicy, model %q",
			gsCfg.LoadBalancer.Mixed, gsCfg.Model)
	}

	if gsCfg.DeployPolicy == "separated" &&
		(!validCommonLBTypes[gsCfg.LoadBalancer.Prefill] || !validDecodeLBTypes[gsCfg.LoadBalancer.Decode]) {
		return fmt.Errorf("invalid loadBalanceType %q and %q for separated deployPolicy, model %q",
			gsCfg.LoadBalancer.Prefill, gsCfg.LoadBalancer.Decode, gsCfg.Model)
	}

	if gsCfg.LoadBalancer.BatchSize <= 0 {
		return fmt.Errorf("invalid batch size value: %v, should > 0", gsCfg.LoadBalancer.BatchSize)
	}
	if gsCfg.LoadBalancer.ReservedBlockNumber <= 0 {
		return fmt.Errorf("invalid ReservedBlockNumber value: %v, should > 0",
			gsCfg.LoadBalancer.ReservedBlockNumber)
	}
	if gsCfg.LoadBalancer.MinMatchedLength <= 0 {
		return fmt.Errorf("invalid MinMatchedLength value: %v, should > 0", gsCfg.LoadBalancer.MinMatchedLength)
	}

	return nil
}

func validateInsConnectType(gsCfg *base.GlobalSchedulerConfig) error {
	if gsCfg.InsConnectType != "sse" && gsCfg.InsConnectType != "" {
		return fmt.Errorf("insConnectTpye must be sse")
	}
	return nil
}

func validateMonitorConfig(cfg *base.MonitorConfig) error {
	address := strings.TrimSpace(cfg.Address)
	alarmPath := strings.TrimSpace(cfg.AlarmPath)
	serviceName := strings.TrimSpace(cfg.ServiceName)
	version := strings.TrimSpace(cfg.Version)
	businessId := strings.TrimSpace(cfg.BusinessId)

	if address == "" {
		log.Warn().Msgf("monitor address is empty, disable monitor connection")
		return nil
	}

	if err := utils.ValidateIPPort(address); err != nil {
		return fmt.Errorf("invalid Monitor address, address %v, err: %v ", address, err)
	}

	if err := utils.ValidateMonitorAlarmPath(alarmPath); err != nil {
		return fmt.Errorf("invalid Monitor alarmPath %v, err: %v", alarmPath, err)
	}
	if err := utils.ValidateMonitorEnvFields(serviceName); err != nil {
		return fmt.Errorf("invalid Monitor serviceName %v, err: %v", serviceName, err)
	}
	if err := utils.ValidateMonitorEnvFields(version); err != nil {
		return fmt.Errorf("invalid Monitor version %v, err: %v", version, err)
	}
	if err := utils.ValidateMonitorEnvFields(businessId); err != nil {
		return fmt.Errorf("invalid Monitor businessId %v, err: %v", businessId, err)
	}

	return nil
}

func validateZookeeperConfig(cfg *base.ZookeeperConfig) error {
	if strings.TrimSpace(cfg.Address) == "" {
		log.Warn().Msgf("zookeeper address is empty, disable zookeeper connection")
		return nil
	}

	if err := utils.ValidateZooKeeperServers(cfg.Address); err != nil {
		return fmt.Errorf("invalid address of ZooKeeper, address %v, err: %v", cfg.Address, err)
	}
	if strings.TrimSpace(cfg.AclScheme) != "" {
		if !validAclSchemes[cfg.AclScheme] {
			return fmt.Errorf("invalid aclScheme: %v", cfg.AclScheme)
		}
	}
	if err := utils.ValidateZooKeeperPath(cfg.InferenceInstancePath); err != nil {
		return fmt.Errorf("invalid InferenceInstancePath, err: %v", err)
	}
	if err := utils.ValidateZooKeeperPath(cfg.ScheduleServicePath); err != nil {
		return fmt.Errorf("invalid ScheduleServicePath, err: %v", err)
	}

	if cfg.ConnectTimeout < 0 {
		return fmt.Errorf("invalid connectTimeout value, it should be >= 0")
	}
	if cfg.SessionTimeout < 0 {
		return fmt.Errorf("invalid sessionTimeout value, it should be >= 0")
	}

	if cfg.EnableTls {
		if !utils.FileExist(cfg.CaFile) || !utils.FileExist(cfg.CrtFile) {
			return fmt.Errorf("tls file not exist")
		}
		if err := utils.CheckStringLength(cfg.ServerName); err != nil {
			return err
		}
	} else {
		log.Warn().Msgf("[TLS] zookeeper not enable TLS")
	}

	return nil
}

func validatePredictorConfig(cfg *base.PredictorConfig) error {
	if !validPredictorTypes[cfg.PredictType] {
		return fmt.Errorf("invalid predictType: %v", cfg.PredictType)
	}

	if cfg.PredictType == "lightgbm" {
		if _, err := utils.ValidateFilePath(cfg.Lightgbm.ClassifierFile); err != nil {
			return fmt.Errorf("invalid ClassifierFile, err: %v", err)
		}
		if _, err := utils.ValidateFilePath(cfg.Lightgbm.VectorizerFile); err != nil {
			return fmt.Errorf("invalid VectorizerFile, err: %v", err)
		}
	}
	return nil
}

func validateGlobalSchedulersConfig(gsConfigs []base.GlobalSchedulerConfig) error {
	for _, scheduler := range gsConfigs {
		log.Info().Msgf("checking global scheduler config, model %v", scheduler.Model)
		if scheduler.BlockSize <= 0 {
			return fmt.Errorf("invalid block size value: %v, should > 0", scheduler.BlockSize)
		}

		if !validDeployPolicies[scheduler.DeployPolicy] {
			return fmt.Errorf("invalid deployPolicy: %v, model %v", scheduler.DeployPolicy, scheduler.Model)
		}

		ttft := scheduler.MaxTimeToFirstToken
		if ttft <= 0 {
			return fmt.Errorf("invalid ttft SLO %v, value should > 0", ttft)
		}
		tbt := scheduler.MaxTimeBetweenTokens
		if tbt <= 0 {
			return fmt.Errorf("invalid tbt SLO %v, value should > 0", tbt)
		}

		if err := validateLoadBalancer(&scheduler); err != nil {
			return err
		}
		if err := validateInsConnectType(&scheduler); err != nil {
			return err
		}
		if err := utils.CheckStringLength(scheduler.TokenizeModelName); err != nil {
			return fmt.Errorf("tokenizeModelName error: %v", err)
		}
		if err := utils.CheckStringLength(scheduler.Model); err != nil {
			return fmt.Errorf("model error: %v", err)
		}
		log.Info().Msgf("finished to check global scheduler config, model %v", scheduler.Model)

	}

	return nil
}

func validateGlobalConfig(cfg *base.GlobalConfig) error {
	if err := utils.CheckIP(cfg.Host); err != nil {
		return fmt.Errorf("host in config file is invalid, err: %v", err)
	}
	if err := utils.CheckPort(cfg.Port); err != nil {
		return fmt.Errorf("port in config file is invalid, err: %v", err)
	}

	if strings.TrimSpace(cfg.CryptoSock) != "" {
		if err := utils.CheckUnixDomainSocket(cfg.CryptoSock); err != nil {
			return fmt.Errorf("crypto sock in config file is invalid, err: %v", err)
		}
	}

	if cfg.SnapshotUpdateInterval <= 0 {
		return fmt.Errorf("invalid snapshot update interval value: %v, value should > 0",
			cfg.SnapshotUpdateInterval)
	}
	_, exists := securitySchema[cfg.SecuritySchema]
	if !exists {
		return fmt.Errorf("invalid securitySchema, should be default or mep")
	}

	if cfg.ReqTimeout <= 0 {
		return fmt.Errorf("invalid ReqTimeout,  value should > 0")
	}

	return nil
}

func validateTokenizerConfig(cfg *base.TokenizerConfig) error {
	if err := utils.CheckStringLength(cfg.TokenizeModelName); err != nil {
		return fmt.Errorf("tokenizeModelName in tokenizerConfig file is invalid, err: %v", err)
	}
	if _, err := utils.ValidateFilePath(cfg.ConfigPath); err != nil {
		return fmt.Errorf("configPath in tokenizerConfig file is invalid, err: %v", err)
	}
	if cfg.TokenizerType != "huggingfaceTokenizers" {
		return fmt.Errorf("tokenizerType in tokenizerConfig file only support huggingfaceTokenizers")
	}
	return nil
}

func validateLimits(config *base.Limits) error {
	if config.TotalInsNum > maxTotalInstanceNum || config.TotalInsNum < 1 {
		return fmt.Errorf("totalInsNum must be between 1 and %v", maxTotalInstanceNum)
	}
	if config.InsNumPerModel > maxConcurrency || config.InsNumPerModel < 1 {
		return fmt.Errorf("insNumPerModel must be between 1 and %v", maxConcurrency)
	}
	if config.ModelNum > maxConcurrency || config.ModelNum < 1 {
		return fmt.Errorf("modelNum must be between 1 and %v", maxConcurrency)
	}
	if config.Concurrency > maxConcurrency || config.Concurrency < 1 {
		return fmt.Errorf("concurrency must be between 1 and %v", maxConcurrency)
	}
	if config.TotalInsNum < config.InsNumPerModel {
		return fmt.Errorf("totalInsNum can not be smaller than insNumPerModel")
	}
	if config.MaxPromptRunes < minPromptRunes || config.MaxPromptRunes > maxPromptRunes {
		return fmt.Errorf("maxPromptRunes must be between %v and %v", minPromptRunes, maxPromptRunes)
	}
	return nil
}

// ValidateConfig checks the validation of config.
func (m *AigwConfigManager) ValidateConfig(config *base.AigwConfig) error {
	if err := validateMonitorConfig(&config.MonitorConfig); err != nil {
		return err
	}
	if err := validateZookeeperConfig(&config.ZkConfig); err != nil {
		return err
	}
	if err := validatePredictorConfig(&config.Predictor); err != nil {
		return err
	}
	if err := validateLimits(&config.Limits); err != nil {
		return err
	}
	if err := validateDataSyncConfig(&config.DataSyncConfig); err != nil {
		return err
	}

	gsNum := len(config.GsConfigs)
	if gsNum > 0 {
		if config.DataSyncConfig.Address != "" {
			return fmt.Errorf("dataSync address is not none, gs is disable, must be []")
		}
		if gsNum > config.Limits.ModelNum {
			return fmt.Errorf("number of GS exceeds the limit, actual %v, limit %v",
				gsNum, config.Limits.ModelNum)
		}
		if err := validateGlobalSchedulersConfig(config.GsConfigs); err != nil {
			return err
		}
	}
	if err := validateGlobalConfig(&config.GlobalConfig); err != nil {
		return err
	}

	for _, tkCfg := range config.Tokenizers {
		if err := validateTokenizerConfig(&tkCfg); err != nil {
			return err
		}
	}

	return nil
}

func validateDataSyncConfig(cfg *base.DataSyncConfig) error {
	address := strings.TrimSpace(cfg.Address)
	path := cfg.Path
	interval := cfg.Interval

	if address == "" {
		log.Warn().Msgf("dataSync address is empty, disable datasync connection")
		return nil
	}
	if err := utils.ValidateIPPort(address); err != nil {
		return fmt.Errorf("the address in datasync err: %v", err)
	}
	if err := utils.CheckStringLength(path); err != nil {
		return fmt.Errorf("the path in datasync err: %v", err)
	}
	if interval < 1 || interval > dataSyncMaxInterval {
		return fmt.Errorf("the interval in datasync is invalid, should be 1-%vs", dataSyncMaxInterval)
	}
	return nil
}

// PrintConfig shows the config
func (m *AigwConfigManager) PrintConfig() {
	configJSON, err := json.MarshalIndent(m.config, "", "  ")
	if err == nil {
		// do not print private data
		log.Debug().Msgf("current config: %v", string(configJSON))
	}
}
