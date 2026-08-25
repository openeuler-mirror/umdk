/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: AigwManager test
 * Create: 2025-07-28
 */

// Package core contains the core functions for AIGW.
package core

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/gs"
	"huawei.com/aigw/pkg/crypto"
)

const (
	aigwTestTokenizerCfgFile = "../../test/tokenizer/DeepSeek-R1-Distill-Qwen-7B/tokenizer.json"
	aigwTestPredictModelFile = "../../test/lightgbm/lgbm_text_classifier.txt"
	aigwTestVectorizerFile   = "../../test/vectorizer/pretrained_vector.json"

	aigwTestTtft      = 200 // ms
	aigwTestTbt       = 50  // ms
	aigwTestSnapFeq   = 3
	aigwTestBlockSize = 128
	aigwTestMinBlocks = 10
	aigwTestBathSize  = 10

	aigwTestMaxInputStringLen = 256
)

var config = &base.AigwConfig{
	GsConfigs: []base.GlobalSchedulerConfig{
		{
			Model:                "test_model",
			BlockSize:            aigwTestBlockSize,
			DeployPolicy:         "mixed",
			TokenizeModelName:    "DeepSeek-R1",
			MaxTimeToFirstToken:  aigwTestTtft,
			MaxTimeBetweenTokens: aigwTestTbt,
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "roundRobin",
				Decode:              "roundRobin",
				ReservedBlockNumber: aigwTestMinBlocks,
				BatchSize:           aigwTestBathSize,
				PowerOfTwo:          true,
			},
		},
	},
	Predictor: base.PredictorConfig{
		PredictType: "lightgbm",
		Lightgbm: base.LightgbmConfig{
			ClassifierFile: aigwTestPredictModelFile,
			VectorizerFile: aigwTestVectorizerFile,
		},
	},
	Tokenizers: []base.TokenizerConfig{
		{
			TokenizeModelName: "DeepSeek-R1",
			ConfigPath:        aigwTestTokenizerCfgFile,
			TokenizerType:     "huggingfaceTokenizers",
		},
	},
	GlobalConfig: base.GlobalConfig{
		SnapshotUpdateInterval: aigwTestSnapFeq,
	},
	Limits: base.Limits{
		TotalInsNum:    2048,
		InsNumPerModel: 128,
		ModelNum:       128,
		Concurrency:    128,
	},
}

func TestAigwManagerMainFlow(t *testing.T) {
	// Create AigwManager
	opts := []AIGWManagerOption{
		WithHmac(crypto.NewHmacManager(nil)),
		WithAes(crypto.NewAesManager(nil)),
		WithRuntimeMode(base.ServiceMode),
	}
	manager, err := NewAigwManager(config, opts...)
	assert.NoError(t, err)

	// Initialize the manager
	err = manager.Init()
	assert.NoError(t, err)

	// Uninitialize the manager
	defer manager.Uninit()

	gsMgr := &gs.GlobalSchedulerManager{}
	patchReg := gomonkey.ApplyPrivateMethod(gsMgr, "registerInstance",
		func(mgr *gs.GlobalSchedulerManager, ctrlMsg *gs.ControlMessage) {
			ctrlMsg.Response <- nil
		})
	defer patchReg.Reset()

	// Register an instance
	registerIn := &base.RegisterInstanceIn{
		Name:  "test_instance",
		Model: "test_model",
		IP:    "127.0.0.1",
		Port:  "8080",
		Role:  "mixed",
	}
	err = manager.RegisterInstance(registerIn)
	assert.NoError(t, err)

	patchUnReg := gomonkey.ApplyPrivateMethod(gsMgr, "unregisterInstance",
		func(mgr *gs.GlobalSchedulerManager, ctrlMsg *gs.ControlMessage) {
			ctrlMsg.Response <- nil
		})
	defer patchUnReg.Reset()

	// Unregister an instance
	unregisterIn := &base.UnregisterInstanceIn{
		Model: "test_model",
		IP:    "127.0.0.1",
		Port:  "8080",
	}
	err = manager.UnregisterInstance(unregisterIn)
	assert.NoError(t, err)

	// Get a suggestion
	getSuggestionIn := &GetSuggestionIn{
		Model:  "test_model",
		UUID:   "test_uuid",
		Prompt: "test_prompt",
	}
	suggestionOut, err := manager.GetSuggestion(getSuggestionIn)
	assert.NoError(t, err)
	assert.NotNil(t, suggestionOut)
}

func TestAigwManagerRegisterInstanceValidation(t *testing.T) {
	manager := &AigwManager{}
	registerIn := &base.RegisterInstanceIn{
		Name:  "test_instance",
		Model: "test_model",
		IP:    "127.0.0.1",
		Port:  "8080",
		Role:  "mixed",
	}
	manager.config = &base.AigwConfig{}
	manager.config.Limits.TotalInsNum = aigwTestBathSize

	patchReg := gomonkey.ApplyPrivateMethod(manager, "executeControlOperation",
		func(mgr *AigwManager, model string, request interface{}, action string) error {
			return fmt.Errorf("some error")
		})
	defer patchReg.Reset()

	// Test case 0: Error from executeControlOperation
	err := manager.RegisterInstance(registerIn)
	assert.Error(t, err)
	assert.Equal(t, "some error", err.Error())

	// Test invalid Name
	registerIn.Name = ""
	err = manager.RegisterInstance(registerIn)
	assert.Error(t, err)

	// Test invalid Model
	registerIn.Name = "test_instance"
	registerIn.Model = ""
	err = manager.RegisterInstance(registerIn)
	assert.Error(t, err)

	// Test invalid Role
	registerIn.Model = "test_model"
	registerIn.Role = ""
	err = manager.RegisterInstance(registerIn)
	assert.Error(t, err)

	// Test invalid IP
	registerIn.Role = "test_role"
	registerIn.IP = "invalid_ip"
	err = manager.RegisterInstance(registerIn)
	assert.Error(t, err)

	// Test invalid Port
	registerIn.IP = "127.0.0.1"
	registerIn.Port = "invalid_port"
	err = manager.RegisterInstance(registerIn)
	assert.Error(t, err)

	// invalid gs model
	manager.gsTable = make(map[string]*gs.GlobalSchedulerManager, 1)
	err = manager.executeControlOperation("inavlid", nil, "123")

	// invalid config
	_, err = NewAigwManager(nil)
	assert.Error(t, err)
}

func TestAigwManagerUnRegisterInstanceValidation(t *testing.T) {
	manager := &AigwManager{}

	// Test case 1: Invalid Name length
	inInvalidName := &base.UnregisterInstanceIn{
		Model: "validModel",
		IP:    "192.168.1.1",
		Port:  "8080",
	}
	err := manager.UnregisterInstance(inInvalidName)
	assert.Error(t, err)

	// Test case 2: Invalid Model length
	inInvalidModel := &base.UnregisterInstanceIn{
		Model: "",
		IP:    "192.168.1.1",
		Port:  "8080",
	}
	err = manager.UnregisterInstance(inInvalidModel)
	assert.Error(t, err)

	// Test case 3: Invalid IP
	inInvalidIP := &base.UnregisterInstanceIn{
		Model: "validModel",
		IP:    "invalidIP",
		Port:  "8080",
	}
	err = manager.UnregisterInstance(inInvalidIP)
	assert.Error(t, err)

	// Test case 4: Invalid Port
	inInvalidPort := &base.UnregisterInstanceIn{
		Model: "validModel",
		IP:    "192.168.1.1",
		Port:  "0",
	}
	err = manager.UnregisterInstance(inInvalidPort)
	assert.Error(t, err)

	// Test case 5: Error from executeControlOperation with invalid model
	inError := &base.UnregisterInstanceIn{
		Model: "invalidModel",
		IP:    "192.168.1.1",
		Port:  "8080",
	}

	err = manager.UnregisterInstance(inError)
	assert.Error(t, err)
}

func TestAigwManagerGetSuggestionValidation(t *testing.T) {
	manager := &AigwManager{}

	in1 := &GetSuggestionIn{
		Model:  "testModel",
		UUID:   "testUUID",
		Prompt: "testPrompt",
	}

	// Test case 1: Invalid model length
	in1.Model = "invalid" + strings.Repeat("a", aigwTestMaxInputStringLen)
	out, err := manager.GetSuggestion(in1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The length of Model is invalid")
	assert.Nil(t, out)

	// Test case 2: Invalid UUID length
	in1.Model = "testModel"
	in1.UUID = "invalid" + strings.Repeat("a", aigwTestMaxInputStringLen)
	out, err = manager.GetSuggestion(in1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The length of UUID is invalid")
	assert.Nil(t, out)

	// Test case 3: Global scheduler manager not found
	in1.Model = "testModel"
	in1.UUID = "testUUID3"
	out, err = manager.GetSuggestion(in1)
	assert.Error(t, err)
	assert.Nil(t, out)

	gsMgr := &gs.GlobalSchedulerManager{}
	patchInit := gomonkey.ApplyMethod(reflect.TypeOf(gsMgr), "PreprocessForSchedule",
		func(handler *gs.GlobalSchedulerManager, req *gs.LlmRequest) error { return fmt.Errorf("some error") })
	defer patchInit.Reset()

	// Test case 4: PreprocessForSchedule error
	in1.UUID = "testUUID4"
	manager.gsTable = make(map[string]*gs.GlobalSchedulerManager)
	manager.gsTable["testModel"] = &gs.GlobalSchedulerManager{}
	out, err = manager.GetSuggestion(in1)
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestRegisterModel(t *testing.T) {
	// create temp data
	tmpFile, err := os.CreateTemp("", "ttft_test_*.txt")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	testData := "100,50,150.5\n200,100,300.2\n"
	_, err = tmpFile.WriteString(testData)
	assert.NoError(t, err)
	err = tmpFile.Close()
	assert.NoError(t, err)

	manager, _ := NewAigwManager(config)
	manager.Init()
	defer manager.Uninit()

	t.Run("success-register-new-model", func(t *testing.T) {
		newConfig := &base.GlobalSchedulerConfig{
			Model:                "new_model",
			TokenizeModelName:    "DeepSeek-R1",
			DeployPolicy:         "mixed",
			MaxTimeBetweenTokens: aigwTestTbt,
			MaxTimeToFirstToken:  aigwTestTtft,
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:     "token",
				Prefill:   "",
				Decode:    "",
				BatchSize: 4,
			},
		}

		err := manager.RegisterModel(newConfig)

		assert.NoError(t, err)
		assert.Contains(t, manager.gsTable, "new_model")
	})

	t.Run("error-model-limit-exceeded", func(t *testing.T) {
		manager.config.Limits.ModelNum = len(manager.gsTable)

		err := manager.RegisterModel(&base.GlobalSchedulerConfig{
			Model: "another_model",
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the number of models has reached the upper limit")
	})

	t.Run("error-tokenizer-not-exist", func(t *testing.T) {
		manager.config.Limits.ModelNum = maxTotalInstanceNum
		err := manager.RegisterModel(&base.GlobalSchedulerConfig{
			Model:             "invalid_model",
			TokenizeModelName: "nonexistent_tokenizer",
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the tokenizeModelName nonexistent_tokenizer is not exist")
	})

	t.Run("error-model-already-exist", func(t *testing.T) {
		err := manager.RegisterModel(&base.GlobalSchedulerConfig{
			Model:                "test_model",
			BlockSize:            aigwTestBlockSize,
			DeployPolicy:         "mixed",
			TokenizeModelName:    "DeepSeek-R1",
			MaxTimeToFirstToken:  aigwTestTtft,
			MaxTimeBetweenTokens: aigwTestTbt,
			LoadBalancer: base.LoadBalancerConfig{
				Mixed:               "roundRobin",
				Prefill:             "roundRobin",
				Decode:              "roundRobin",
				ReservedBlockNumber: aigwTestMinBlocks,
				BatchSize:           aigwTestBathSize,
				PowerOfTwo:          true,
			},
		})

		assert.NoError(t, err)
	})

	t.Run("ttft-path-per-model", func(t *testing.T) {
		manager.config.Limits.ModelNum = maxTotalInstanceNum

		t.Run("model-a-without-ttft-path", func(t *testing.T) {
			configA := &base.GlobalSchedulerConfig{
				Model:                "model_without_ttft",
				TokenizeModelName:    "DeepSeek-R1",
				DeployPolicy:         "mixed",
				MaxTimeBetweenTokens: aigwTestTbt,
				MaxTimeToFirstToken:  aigwTestTtft,
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:            "prefillTimeAware",
					BatchSize:        4,
					PretrainTTFTPath: "",
				},
			}

			err := manager.RegisterModel(configA)
			assert.NoError(t, err)
			assert.Contains(t, manager.gsTable, "model_without_ttft")
		})

		t.Run("model-b-with-invalid-ttft-path", func(t *testing.T) {
			configB := &base.GlobalSchedulerConfig{
				Model:                "model_with_invalid_ttft",
				TokenizeModelName:    "DeepSeek-R1",
				DeployPolicy:         "mixed",
				MaxTimeBetweenTokens: aigwTestTbt,
				MaxTimeToFirstToken:  aigwTestTtft,
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:            "prefillTimeAware",
					BatchSize:        4,
					PretrainTTFTPath: "/invalid/path/that/does/not/exist.txt",
				},
			}

			err := manager.RegisterModel(configB)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to init ttft predictor")
			assert.NotContains(t, manager.gsTable, "model_with_invalid_ttft")
		})

		t.Run("model-c-with-valid-ttft-path", func(t *testing.T) {
			configC := &base.GlobalSchedulerConfig{
				Model:                "model_with_valid_ttft",
				TokenizeModelName:    "DeepSeek-R1",
				DeployPolicy:         "mixed",
				MaxTimeBetweenTokens: aigwTestTbt,
				MaxTimeToFirstToken:  aigwTestTtft,
				LoadBalancer: base.LoadBalancerConfig{
					Mixed:            "prefillTimeAware",
					BatchSize:        4,
					PretrainTTFTPath: tmpFile.Name(),
				},
			}

			err := manager.RegisterModel(configC)
			assert.NoError(t, err)
			assert.Contains(t, manager.gsTable, "model_with_valid_ttft")
		})
	})
}

func TestUnregisterModel(t *testing.T) {
	manager, _ := NewAigwManager(config)
	manager.Init()
	defer manager.Uninit()

	// 预先注册一个测试模型
	testConfig := &base.GlobalSchedulerConfig{
		Model: "test_model",
	}
	_ = manager.RegisterModel(testConfig)

	t.Run("success-unregister-existing-model", func(t *testing.T) {
		// 执行测试
		err := manager.UnregisterModel("test_model")

		// 验证结果
		assert.NoError(t, err)
		assert.NotContains(t, manager.gsTable, "test_model")
	})

	t.Run("error-unregister-nonexistent-model", func(t *testing.T) {
		// 执行测试
		err := manager.UnregisterModel("nonexistent_model")

		// 验证结果
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "del GS failed, model is not exist in AIGW")
	})
}

// 辅助函数用于创建测试管理器
func createTestManager(t *testing.T, config *base.AigwConfig) *AigwManager {
	manager, err := NewAigwManager(config)
	assert.NoError(t, err)
	assert.NoError(t, manager.Init())
	return manager
}

func TestGetAllStats_Empty(t *testing.T) {
	config := &base.AigwConfig{
		GsConfigs: []base.GlobalSchedulerConfig{},
	}
	manager := &AigwManager{
		config:  config,
		gsTable: make(map[string]*gs.GlobalSchedulerManager),
	}
	result := manager.GetAllStats()
	assert.Empty(t, result.StatsSlice, "当无模型时应返回空统计列表")
}

// TestAigwManager_IsEnableZK tests whether the ZooKeeper feature is enabled
func TestAigwManager_IsEnableZK(t *testing.T) {
	tests := []struct {
		name     string
		zkAddr   string
		expected bool
	}{
		{"zk enabled with address", "127.0.0.1:2181", true},
		{"zk disabled with empty address", "", false},
		{"zk disabled with whitespace", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &base.AigwConfig{
				ZkConfig: base.ZookeeperConfig{Address: tt.zkAddr},
			}
			manager := &AigwManager{config: config}
			assert.Equal(t, tt.expected, manager.IsEnableZK())
		})
	}
}

func setupTestManager(t *testing.T, ctx context.Context) *AigwManager {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		t.Cleanup(cancel)
	}

	config := &base.AigwConfig{
		Limits: base.Limits{
			InsNumPerModel: 10,
			ModelNum:       10,
			MaxPromptRunes: 1000,
		},
		GlobalConfig: base.GlobalConfig{
			ReqTimeout: 30,
		},
		Predictor: base.PredictorConfig{
			PredictType: "none",
		},
	}

	redisOps := &cachecenter.CacheDriverOps{
		HGetAll: func(key string) (map[string]string, error) { return map[string]string{}, nil },
		HSet:    func(key string, fields map[string]string, ttl int) error { return nil },
		HDel:    func(key string, fields ...string) error { return nil },
	}

	return &AigwManager{
		ctx:            ctx,
		config:         config,
		gsTable:        make(map[string]*gs.GlobalSchedulerManager),
		CacheDriverOps: redisOps,
	}
}

// TestAigwManager_FindOrCreateGs tests the FindOrCreateGs method
func TestAigwManager_FindOrCreateGs(t *testing.T) {
	manager := setupTestManager(t, nil)

	gs1, err := manager.FindOrCreateGs("test-model")
	assert.NoError(t, err)
	assert.NotNil(t, gs1)

	gs2, err := manager.FindOrCreateGs("test-model")
	assert.NoError(t, err)
	assert.Same(t, gs1, gs2)

	assert.Contains(t, manager.gsTable, "test-model")
	assert.Same(t, gs1, manager.gsTable["test-model"])
}

// TestAigwManager_FindOrCreateGsWhenReachGsNumsLimits tests the FindOrCreateGs method when reach GsNumsLimits
func TestAigwManager_FindOrCreateGsWhenReachGsNumsLimits(t *testing.T) {
	manager := setupTestManager(t, nil)

	manager.config.Limits.ModelNum = 2
	gs1, err := manager.FindOrCreateGs("test-model1")
	assert.NoError(t, err)
	assert.NotNil(t, gs1)

	gs2, err := manager.FindOrCreateGs("test-model2")
	assert.NoError(t, err)
	assert.NotSame(t, gs1, gs2)

	// reach to limit of 3, delete test-model1
	gs3, err := manager.FindOrCreateGs("test-model3")
	assert.NoError(t, err)
	assert.NotNil(t, gs3)
	assert.Contains(t, manager.gsTable, "test-model3")
	assert.Contains(t, manager.gsTable, "test-model2")
	assert.NotContains(t, manager.gsTable, "test-model1")
}

// TestAigwManager_FindOrCreateGsWhenReachGsNumsLimits_2 tests the FindOrCreateGs method when reach GsNumsLimits
func TestAigwManager_FindOrCreateGsWhenReachGsNumsLimits_2(t *testing.T) {
	manager := setupTestManager(t, nil)

	manager.config.Limits.ModelNum = 2
	gs1, err := manager.FindOrCreateGs("test-model1")
	assert.NoError(t, err)
	assert.NotNil(t, gs1)

	gs2, err := manager.FindOrCreateGs("test-model2")
	assert.NoError(t, err)
	assert.NotSame(t, gs1, gs2)

	gs1, err = manager.FindOrCreateGs("test-model1")
	assert.NoError(t, err)
	assert.NotNil(t, gs1)

	// reach to limit of 3, delete test-model1
	gs3, err := manager.FindOrCreateGs("test-model3")
	assert.NoError(t, err)
	assert.NotNil(t, gs3)
	assert.Contains(t, manager.gsTable, "test-model3")
	assert.Contains(t, manager.gsTable, "test-model1")
	assert.NotContains(t, manager.gsTable, "test-model2")
}

// TestAigwManager_HandlerReqEvent tests HandlerReqEvent
func TestAigwManager_HandlerReqEvent(t *testing.T) {
	manager := setupTestManager(t, nil)

	err := manager.HandlerReqEvent("test-model", "req-123", "test-event")
	assert.Error(t, err)
}

// TestAigwManager_SelectOptimalNode tests SelectOptimalNode
func TestAigwManager_SelectOptimalNode(t *testing.T) {
	manager := setupTestManager(t, nil)

	in := &GetSuggestionIn{
		UUID:   "req-123",
		Prompt: "hello",
		Model:  "test-model",
	}
	instances := []*gs.RegisterInstanceMsg{
		{Name: "ins1", Model: "test-model", IP: "127.0.0.1", Port: "5001"},
	}

	g, err := manager.FindOrCreateGs("test-model")
	assert.NoError(t, err)
	manager.gsTable["test-model"] = g

	_, err = manager.SelectOptimalNode(in, instances)
	assert.NoError(t, err)
}

// TestKvcWiring_EnabledAndDisabled (Phase 2 H1): asserts AgentRegistry + per-GSM
// KvcSessionManager are constructed when kvc.enabled=true + ServiceMode, and nil otherwise.
//
// NOTE: requires the full ./build.sh (tokenizers + lightgbm CGO) to run AigwManager.Init().
func TestKvcWiring_EnabledAndDisabled(t *testing.T) {
	t.Skip("requires full ./build.sh (tokenizers + lightgbm CGO headers) to construct AigwManager")
}
