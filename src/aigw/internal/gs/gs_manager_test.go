/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: global scheduler manager test
 * Create: 2025-7-28
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/stats"
	"huawei.com/aigw/internal/tokenizers"
	"huawei.com/aigw/pkg/crypto"
)

const (
	gsTokenzerCfgFile  = "../../test/tokenizer/DeepSeek-R1-Distill-Qwen-7B/tokenizer.json"
	gsPredictModelFile = "../../test/lightgbm/lgbm_text_classifier.txt"
	gsVectorizerFile   = "../../test/vectorizer/pretrained_vector.json"

	gsWaitResponseTimeout = 1 * time.Second

	gsTestTtft      = 200 // ms
	gsTestTbt       = 50  // ms
	gsTestSnapFeq   = 3
	gsTestBlockSize = 128
	gsTestMinBlocks = 10
	gsTestBathSize  = 10

	gsTestMaxPromptRunes = 1024
)

func newTestDefaultGsConfig(model string) *base.GlobalSchedulerConfig {
	return &base.GlobalSchedulerConfig{
		Model:                model,
		BlockSize:            128,
		DeployPolicy:         "separated",
		MaxTimeToFirstToken:  1000, // ms
		MaxTimeBetweenTokens: 500,  // ms
		TokenizeModelName:    "",
		LoadBalancer: base.LoadBalancerConfig{
			Mixed:               "token",
			Prefill:             "prefillTimeAware",
			Decode:              "decode",
			BatchSize:           128,
			ReservedBlockNumber: 1,
			MinMatchedLength:    0,
			PowerOfTwo:          false,
		},
		InsConnectType:         "",
		CacheRefreshIntervalMs: 100,
	}
}

// TestDeploymentPolicyStringMixed tests the String method when the deployment policy is mixedDeployment
func TestDeploymentPolicyStringMixed(t *testing.T) {
	policy := MixedDeployment
	expected := "mixed"
	actual := policy.String()
	assert.Equal(t, expected, actual)
}

// TestDeploymentPolicyStringSeparated tests the String method when the deployment policy is separatedDeployment
func TestDeploymentPolicyStringSeparated(t *testing.T) {
	policy := SeparatedDeployment
	expected := "separated"
	actual := policy.String()
	assert.Equal(t, expected, actual)
}

// TestDeploymentPolicyStringUnknown tests the String method when the deployment policy is unknown
func TestDeploymentPolicyStringUnknown(t *testing.T) {
	policy := DeploymentPolicy(2) // An unknown deployment policy
	expected := "unknown"
	actual := policy.String()
	assert.Equal(t, expected, actual)
}

// TestPredictorTypeStringNone tests the String method when the predictor type is predictTypeNone
func TestPredictorTypeStringNone(t *testing.T) {
	predictor := PredictTypeNone
	expected := "none"
	actual := predictor.String()
	assert.Equal(t, expected, actual)
}

// TestPredictorTypeStringEma tests the String method when the predictor type is predictTypeEma
func TestPredictorTypeStringEma(t *testing.T) {
	predictor := PredictTypeEma
	expected := "ema"
	actual := predictor.String()
	assert.Equal(t, expected, actual)
}

// TestPredictorTypeStringLightgbm tests the String method when the predictor type is predictTypeLightgbm
func TestPredictorTypeStringLightgbm(t *testing.T) {
	predictor := PredictTypeLightgbm
	expected := "lightgbm"
	actual := predictor.String()
	assert.Equal(t, expected, actual)
}

// TestPredictorTypeStringUnknown tests the String method when the predictor type is unknown
func TestPredictorTypeStringUnknown(t *testing.T) {
	predictor := PredictorType(3) // An unknown predictor type
	expected := "unknown"
	actual := predictor.String()
	assert.Equal(t, expected, actual)
}

func TestGlobalSchedulerManagerControlPlane(t *testing.T) {
	// Create context
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tk, err := tokenizers.NewTokenizer("test_model")
	assert.NoError(t, err)
	err = tk.InitFromFile(gsTokenzerCfgFile)
	assert.NoError(t, err)

	cfg := newTestDefaultGsConfig("test_model")
	// Create GlobalSchedulerManager
	opts := []GlobalSchedulerManagerOption{
		WithModel("test_model"),
		WithLBType("roundRobin", "leastConn", "capacity"),
		WithDeploymentPolicy("mixed"),
		WithPredict("lightgbm", nil),
		WithTokenizer(tk),
		WithSLOThreshold(gsTestTtft, gsTestTbt),
		WithAlgorithmThreshold(gsTestMinBlocks, gsTestBathSize, true, gsTestBlockSize),
		WithSnapFreq(gsTestSnapFeq),
		WithCrypto(crypto.NewHmacManager(nil), crypto.NewAesManager(nil)),
	}
	manager, err := NewGlobalSchedulerManager(parentCtx, cfg, opts...)
	assert.NoError(t, err)

	// Start the manager
	err = manager.Start()
	assert.NoError(t, err)

	insMgr := &InstanceManager{}
	patchReg := gomonkey.ApplyPrivateMethod(insMgr, "addInstance",
		func(mgr *InstanceManager, insUrl string, insRole base.InstanceRole, statusChan chan *ControlMessage) error {
			return nil
		})
	defer patchReg.Reset()

	// Register an instance
	rsp := make(chan interface{}, 1)
	ctrlMsg := &ControlMessage{
		Request: &RegisterInstanceMsg{
			Name: "test_instance",
			IP:   "127.0.0.1",
			Port: "8080",
			Role: "mixed",
		},
		Response: rsp,
	}
	manager.PutControlMessage(ctrlMsg)
	select {
	case result, ok := <-rsp:
		if !ok {
			t.Errorf("response channel is closed")
		}
		switch result.(type) {
		case error:
			t.Fatalf("failed to reg, err: %v", result.(error))
		default:
		}
	case <-time.After(gsWaitResponseTimeout):
		t.Fatal("timeout while registering instance")
	}

	patchUnReg := gomonkey.ApplyPrivateMethod(insMgr, "removeInstance",
		func(mgr *InstanceManager, insUrl string) bool {
			return true
		})
	defer patchUnReg.Reset()

	// Unregister an instance
	rsp = make(chan interface{}, 1)
	ctrlMsg = &ControlMessage{
		Request: &UnregisterInstanceMsg{
			IP:   "127.0.0.1",
			Port: "8080",
		},
		Response: rsp,
	}
	manager.PutControlMessage(ctrlMsg)

	// wait response
	select {
	case result, ok := <-rsp:
		if !ok {
			t.Errorf("response channel is closed")
		}
		switch result.(type) {
		case error:
			t.Fatalf("failed to unreg, err: %v", result.(error))
		default:
		}
	case <-time.After(gsWaitResponseTimeout):
		t.Fatal("timeout while unregistering instance")
	}

	// Stop the manager
	manager.Stop()
}

func TestGlobalSchedulerManagerDataPlane(t *testing.T) {
	// Create context
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tk, err := tokenizers.NewTokenizer("test_model")
	assert.NoError(t, err)
	err = tk.InitFromFile(gsTokenzerCfgFile)
	assert.NoError(t, err)
	// Create GlobalSchedulerManager
	cfg := newTestDefaultGsConfig("test_model")
	opts := []GlobalSchedulerManagerOption{
		WithModel("test_model"),
		WithLBType("roundRobin", "leastConn", "capacity"),
		WithDeploymentPolicy("mixed"),
		WithPredict("lightgbm", nil),
		WithTokenizer(tk),
		WithSLOThreshold(gsTestTtft, gsTestTbt),
		WithAlgorithmThreshold(gsTestMinBlocks, gsTestBathSize, true, gsTestBlockSize),
		WithSnapFreq(gsTestSnapFeq),
		WithCrypto(crypto.NewHmacManager(nil), crypto.NewAesManager(nil)),
	}
	manager, err := NewGlobalSchedulerManager(parentCtx, cfg, opts...)
	assert.NoError(t, err)

	// Start the manager
	err = manager.Start()
	assert.NoError(t, err)

	testPrompt := strings.Repeat("t", gsTestMaxPromptRunes)
	req, e1 := NewLlmRequest("123", testPrompt)
	assert.NoError(t, e1)

	err = manager.PreprocessForSchedule(req)
	assert.NoError(t, err)

	rsp := make(chan interface{}, 1)
	msg := &ControlMessage{
		Request: &ScheduleRequestMsg{
			Request: req,
		},
		Response: rsp,
	}

	manager.PutScheduleMessage(msg)

	// wait response
	select {
	case out, ok := <-rsp:
		if !ok {
			t.Errorf("response channel is closed")
		}

		switch result := out.(type) {
		case *SuggestionResultMsg:
			assert.NotNil(t, result)
		case error:
			t.Fatalf("failed to get-suggestion, err: %v", result.(error))
		default:
			t.Fatalf("unexpected type of suggestion result")
		}
	case <-time.After(gsWaitResponseTimeout):
		t.Fatal("timeout while get-suggestion")
	}

	// Stop the manager
	manager.Stop()
}

func TestCheckReqSurvival(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := newTestDefaultGsConfig("test_model")
	opts := []GlobalSchedulerManagerOption{
		WithModel("test_model"),
		WithLBType("roundRobin", "leastConn", "capacity"),
		WithDeploymentPolicy("mixed"),
		WithPredict("lightgbm", nil),
		WithSLOThreshold(gsTestTtft, gsTestTbt),
		WithAlgorithmThreshold(gsTestMinBlocks, gsTestBathSize, true, gsTestBlockSize),
		WithSnapFreq(gsTestSnapFeq),
		WithCrypto(crypto.NewHmacManager(nil), crypto.NewAesManager(nil)),
		WithReqSurvivalDuration(10 * time.Second),
	}
	m, err := NewGlobalSchedulerManager(ctx, cfg, opts...)
	assert.NoError(t, err)

	// 注册实例
	testInsURL := "127.0.0.1:8080"
	ins := &instance{
		insUrl:   testInsURL,
		reqSet:   make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(),
	}

	m.instanceManager.insPool[testInsURL] = ins

	// 添加未超时请求
	req := &LlmRequest{
		ReqId:     "fresh-req",
		TimeStamp: time.Now().UnixMilli() - 5*1000, // 5秒前
	}
	ins.addReq(req)

	m.checkReqSurvival()
	assert.Contains(t, ins.reqSet, req.ReqId, "未超时的请求不应被删除")

	// 超时请求删除
	m.config.reqSurvivalDuration = 2 * time.Second
	m.checkReqSurvival()
	assert.NotContains(t, ins.reqSet, req.ReqId, "超时的请求应被删除")

	// 处理空请求
	m.checkReqSurvival()
	assert.Empty(t, ins.reqSet, "空集合操作后仍然为空")

	// 混合场景
	req1 := &LlmRequest{
		ReqId:     "req1",
		TimeStamp: time.Now().UnixMilli() - 5*1000, // 5秒前
	}
	ins.addReq(req)

	req2 := &LlmRequest{
		ReqId:     "req2",
		TimeStamp: time.Now().UnixMilli(), // 当前
	}
	ins.addReq(req)
	ins.addReq(req1)
	ins.addReq(req2)
	assert.Contains(t, ins.reqSet, req1.ReqId, "添加req1")
	assert.Contains(t, ins.reqSet, req2.ReqId, "添加req2")

	m.checkReqSurvival()
	assert.NotContains(t, ins.reqSet, req1.ReqId, "req1删除")
	assert.Contains(t, ins.reqSet, req2.ReqId, "req2还在")
}

func TestCheckReqExists(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := newTestDefaultGsConfig("test_model")
	opts := []GlobalSchedulerManagerOption{
		WithModel("test_model"),
		WithLBType("roundRobin", "leastConn", "capacity"),
		WithDeploymentPolicy("mixed"),
		WithPredict("lightgbm", nil),
		WithSLOThreshold(gsTestTtft, gsTestTbt),
		WithAlgorithmThreshold(gsTestMinBlocks, gsTestBathSize, true, gsTestBlockSize),
		WithSnapFreq(gsTestSnapFeq),
		WithCrypto(crypto.NewHmacManager(nil), crypto.NewAesManager(nil)),
		WithReqSurvivalDuration(10 * time.Second),
	}
	m, err := NewGlobalSchedulerManager(ctx, cfg, opts...)
	assert.NoError(t, err)

	// 注册实例
	testInsURL := "127.0.0.1:8080"
	ins := &instance{
		insUrl:   testInsURL,
		reqSet:   make(map[string]*LlmRequest),
		reqQueue: newRequestQueue(),
	}

	m.instanceManager.insPool[testInsURL] = ins

	exists := m.CheckReqExists("req1")
	assert.Equal(t, exists, false)

	req := &LlmRequest{
		ReqId:     "req1",
		TimeStamp: time.Now().UnixMilli(),
	}
	ins.addReq(req)
	exists = m.CheckReqExists("req1")
	assert.Equal(t, exists, true)
}

// TestWithCacheDriverOps test redisOps register
func TestWithCacheDriverOps(t *testing.T) {
	redisOps := &cachecenter.CacheDriverOps{}
	opt := WithCacheDriverOps(redisOps)

	gs := &GlobalSchedulerManager{}
	err := opt(gs)

	assert.NoError(t, err)
	assert.Equal(t, redisOps, gs.cacheDriverOps)
}

// TestWithTokenizationRatio test redisOps register
func TestWithTokenizationRatio(t *testing.T) {
	ratio := tokenizers.DefaultTokenizationRatio
	opt := WithTokenizationRatio(ratio)

	gs := &GlobalSchedulerManager{}
	err := opt(gs)

	assert.NoError(t, err)
	assert.Equal(t, ratio, gs.config.tokenizationRatio)
}

// TestWithInsNumLimit test register insNumLimit
func TestWithInsNumLimit(t *testing.T) {
	insNumLimit := 10
	opt := WithInsNumLimit(insNumLimit)

	gs := &GlobalSchedulerManager{}
	err := opt(gs)

	assert.NoError(t, err)
	assert.Equal(t, insNumLimit, gs.config.maxInsNumPerGS)
}

// TestWithRuntimeMode test register aigw runtime mode
func TestWithRuntimeMode(t *testing.T) {
	gs := &GlobalSchedulerManager{}
	assert.Equal(t, base.ServiceMode, gs.runtimeMode)

	opt := WithRuntimeMode(base.SdkMode)
	err := opt(gs)

	assert.NoError(t, err)
	assert.Equal(t, base.SdkMode, gs.runtimeMode)
}

func TestGetStats(t *testing.T) {
	g := &GlobalSchedulerManager{stats: &stats.DataPlaneStats{}}
	res := g.GetStats()
	assert.NotNil(t, res)
	assert.Equal(t, len(res), int(stats.TypeCount))
}

// TestWithInsConnectType test register insNumLimit
func TestWithInsConnectType(t *testing.T) {
	connectType := "sse"
	opt := WithInsConnectType(connectType)
	gs := &GlobalSchedulerManager{}
	err := opt(gs)
	assert.NoError(t, err)
	assert.Equal(t, connectType, gs.config.insConnectType)
}

// TestRecordScheduleStats_Mixed_Success tests mixed deployment with valid prefillUrl
func TestRecordScheduleStats_Mixed_Success(t *testing.T) {
	// Arrange
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{
		config: globalSchedulerManagerConfig{deployPolicy: MixedDeployment},
		stats:  st,
	}
	result := &ScheduleResult{PrefillUrl: "http://prefill", DecodeUrl: ""}
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleFailure])
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_Mixed_Failure tests mixed deployment with empty prefillUrl
func TestRecordScheduleStats_Mixed_Failure(t *testing.T) {
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{
		config: globalSchedulerManagerConfig{deployPolicy: MixedDeployment},
		stats:  st,
	}
	result := &ScheduleResult{PrefillUrl: "", DecodeUrl: "http://decode"}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_Separated_Success tests both URLs present
func TestRecordScheduleStats_Separated_Success(t *testing.T) {
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{
		config: globalSchedulerManagerConfig{deployPolicy: SeparatedDeployment},
		stats:  st,
	}
	result := &ScheduleResult{PrefillUrl: "http://prefill", DecodeUrl: "http://decode"}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_Separated_Failure_PrefillEmpty tests prefillUrl empty
func TestRecordScheduleStats_Separated_Failure_PrefillEmpty(t *testing.T) {
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{config: globalSchedulerManagerConfig{deployPolicy: SeparatedDeployment}, stats: st}
	result := &ScheduleResult{PrefillUrl: "", DecodeUrl: "http://decode"}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_Separated_Failure_DecodeEmpty tests decodeUrl empty
func TestRecordScheduleStats_Separated_Failure_DecodeEmpty(t *testing.T) {
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{config: globalSchedulerManagerConfig{deployPolicy: SeparatedDeployment}, stats: st}
	result := &ScheduleResult{PrefillUrl: "http://prefill", DecodeUrl: ""}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_Separated_Failure_BothEmpty tests both empty
func TestRecordScheduleStats_Separated_Failure_BothEmpty(t *testing.T) {
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{
		config: globalSchedulerManagerConfig{deployPolicy: SeparatedDeployment},
		stats:  st,
	}
	result := &ScheduleResult{PrefillUrl: "", DecodeUrl: ""}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleFailure])
}

// TestRecordScheduleStats_UnknownPolicy_Failure tests unknown policy falls to default
func TestRecordScheduleStats_UnknownPolicy_Failure(t *testing.T) {
	// Arrange
	st := stats.NewDataPlaneStats()
	m := &GlobalSchedulerManager{
		config: globalSchedulerManagerConfig{deployPolicy: 2},
		stats:  st,
	}
	result := &ScheduleResult{PrefillUrl: "http://any", DecodeUrl: "http://any"}
	m.recordScheduleStats(result)
	assert.Equal(t, uint64(1), st.Counts[stats.ScheduleSuccess])
	assert.Equal(t, uint64(0), st.Counts[stats.ScheduleFailure])
}
