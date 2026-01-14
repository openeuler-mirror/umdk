/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: definitions of types for AIGW core.
 * Create: 2025-06-11
 */

// Package base contains the core functions for AIGW.
package base

// OpenAiMessage specified the input format of OpenAI
type OpenAiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAiRequest specified the input format of OpenAI http server
type OpenAiRequest struct {
	UUID     string          `json:"uuid"`
	Model    string          `json:"model"`
	Messages []OpenAiMessage `json:"messages"`
}

// GetSuggestionOut specified the out parameters for GetSuggestion.
type GetSuggestionOut struct {
	TargetPrefillUrl string `json:"targetPrefill"`
	TargetDecodeUrl  string `json:"targetDecode"`
}

// RegisterInstanceIn specified the input parameters for RegisterInstance.
type RegisterInstanceIn struct {
	Name  string `json:"name"`
	Model string `json:"model"`
	IP    string `json:"instanceIp"`
	Port  string `json:"port"`
	Role  string `json:"role"`

	GroupID string `json:"groupID"`
}

// UnregisterInstanceIn specified the input parameters for UnregisterInstance.
type UnregisterInstanceIn struct {
	Model string `json:"model"`
	IP    string `json:"instanceIp"`
	Port  string `json:"port"`
}

// ZookeeperConfig struct contains configuration details for Zookeeper
type ZookeeperConfig struct {
	Address               string `json:"address"`
	AclScheme             string `json:"aclScheme"`
	ConnectTimeout        int    `json:"connectTimeout"`
	SessionTimeout        int    `json:"sessionTimeout"`
	InferenceInstancePath string `json:"inferenceInstancePath"`
	ScheduleServicePath   string `json:"scheduleServicePath"`
	EnableTls             bool   `json:"enableTls"`
	CaFile                string `json:"tlsCaFile"`
	CrtFile               string `json:"tlsCrtFile"`
	ServerName            string `json:"tlsServerName"`
}

// MonitorConfig struct contains configuration detail for Monitor
type MonitorConfig struct {
	Address     string `json:"address"`
	AlarmPath   string `json:"alarmPath"`
	ServiceName string `json:"serviceName"`
	Version     string `json:"version"`
	BusinessId  string `json:"businessId"`
}

// LightgbmConfig struct contains configuration for the LightGBM
type LightgbmConfig struct {
	ClassifierFile string `json:"classifierFile"`
	VectorizerFile string `json:"vectorizerFile"`
}

// PredictorConfig struct contains configuration for the predictor
type PredictorConfig struct {
	PredictType string         `json:"predictType"`
	Lightgbm    LightgbmConfig `json:"lightgbm"`
}

// TokenizerConfig struct contains configuration for the tokenizer
type TokenizerConfig struct {
	TokenizeModelName string `json:"tokenizeModelName"`
	ConfigPath        string `json:"configPath"`
	TokenizerType     string `json:"tokenizerType"`
}

// LoadBalancerConfig struct contains configuration for the load balancer
type LoadBalancerConfig struct {
	Mixed               string `json:"mixed"`
	Prefill             string `json:"prefill"`
	Decode              string `json:"decode"`
	BatchSize           int    `json:"batchSize"`
	ReservedBlockNumber int    `json:"reservedBlockNumber"`
	MinMatchedLength    int    `json:"minMatchedLength"`
	PowerOfTwo          bool   `json:"enablePowerOfTwo"`
}

// GlobalSchedulerConfig struct contains configuration for a global scheduler
type GlobalSchedulerConfig struct {
	Model                string             `json:"model"`
	BlockSize            int                `json:"blockSize"`
	DeployPolicy         string             `json:"deployPolicy"`
	MaxTimeToFirstToken  float64            `json:"maxTimeToFirstToken"`
	MaxTimeBetweenTokens float64            `json:"maxTimeBetweenTokens"`
	TokenizeModelName    string             `json:"tokenizeModelName"`
	LoadBalancer         LoadBalancerConfig `json:"loadBalancer"`
	InsConnectType       string             `json:"instanceConnectType"`
}

// GlobalConfig is the global config of AIGW.
type GlobalConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	LogPath  string `json:"logPath"`
	LogLevel string `json:"logLevel"`

	CryptoSock             string `json:"cryptoSock"`
	SnapshotUpdateInterval int    `json:"snapshotUpdateInterval"`
	SecuritySchema         string `json:"securitySchema"`
	ReqTimeout             int64  `json:"reqTimeout"`
}

// Limits Specification Limitations
type Limits struct {
	TotalInsNum    int `json:"totalInsNum"`
	InsNumPerModel int `json:"insNumPerModel"`
	ModelNum       int `json:"modelNum"`
	Concurrency    int `json:"concurrency"`
	MaxPromptRunes int `json:"maxPromptRunes"`
}

// AigwConfig is the config for AIGW.
type AigwConfig struct {
	MonitorConfig  MonitorConfig           `json:"monitor"`
	ZkConfig       ZookeeperConfig         `json:"zookeeper"`
	DataSyncConfig DataSyncConfig          `json:"dataSync"`
	Predictor      PredictorConfig         `json:"predictor"`
	GsConfigs      []GlobalSchedulerConfig `json:"globalSchedulers"`
	Tokenizers     []TokenizerConfig       `json:"tokenizers"`
	GlobalConfig   GlobalConfig            `json:"global"`
	Limits         Limits                  `json:"limits"`
}

// AigwAllStats is the stats info for Aigw
type AigwAllStats struct {
	StatsSlice []*StatsEntry `json:"stats"`
}

// StatsEntry is the stats entry for one global scheduler
type StatsEntry struct {
	ModelName string            `json:"modelName"`
	Counts    map[string]uint64 `json:"counts"`
}

// CryptoData contains the data of crypto for AIGW
type CryptoData struct {
	ApiHmacKey        string `json:"apiHmacKey"`
	ApiAesKey         string `json:"apiAesKey"`
	InsHmacKey        string `json:"insHmacKey"`
	InsAesKey         string `json:"insAesKey"`
	MonitorHmacKey    string `json:"monitorHmacKey"`
	DataSyncHmacKey   string `json:"dataSyncHmacKey"`
	ZookeeperUser     string `json:"zookeeperUser"`
	ZookeeperPassword string `json:"zookeeperPassword"`
	ZookeeperTlsKey   string `json:"zookeeperTlsKey"`
}

// DataSyncConfig is the stats info for datasync
type DataSyncConfig struct {
	Address  string `json:"address"`
	Path     string `json:"path"`
	Interval int    `json:"interval"`
}
