/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: definitions for gs manager options.
 * Create: 2025-06-11
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"fmt"
	"time"

	"huawei.com/aigw/internal/agentregistry"
	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
	"huawei.com/aigw/internal/renderclient"
	"huawei.com/aigw/internal/tokenizers"
	"huawei.com/aigw/pkg/crypto"
	"huawei.com/aigw/pkg/lightgbm"
)

// GlobalSchedulerManagerOption is the option for global scheduler manager
type GlobalSchedulerManagerOption func(manager *GlobalSchedulerManager) error

// WithModel supplies model
func WithModel(model string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.model = model
		return nil
	}
}

// WithDeploymentPolicy supplies deployment policy
func WithDeploymentPolicy(deploy string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		switch deploy {
		case "mixed":
			gs.config.deployPolicy = MixedDeployment
		case "separated":
			gs.config.deployPolicy = SeparatedDeployment
		default:
			return fmt.Errorf("invalid deployment policy: %s", deploy)
		}

		gs.config.lbConfig.PdMode = gs.config.deployPolicy
		return nil
	}
}

// WithPredict supplies predict type
func WithPredict(predictType string, gbm *lightgbm.Booster) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		switch predictType {
		case "none":
			gs.config.predictType = PredictTypeNone
		case "ema":
			gs.config.predictType = PredictTypeEma
		case "lightgbm":
			{
				gs.config.predictType = PredictTypeLightgbm
				gs.lgm = gbm
			}
		default:
			return fmt.Errorf("invalid predict type: %s", predictType)
		}

		gs.config.lbConfig.PredictType = gs.config.predictType
		return nil
	}
}

// WithTokenizer supplies tokenizer model path
func WithTokenizer(tk tokenizers.Tokenizer) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.tokenizer = tk
		return nil
	}
}

// WithSLOThreshold supplies slo threshold
func WithSLOThreshold(maxTTFT float64, maxTBT float64) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.TtftThreshold = maxTTFT
		gs.config.lbConfig.TbtThreshold = maxTBT

		return nil
	}
}

// WithAlgorithmThreshold supplies algorithm threshold
func WithAlgorithmThreshold(minBlocks int, batchSize int, powerOfTwo bool, blockSize int) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.MinBlockThreshold = minBlocks
		gs.config.lbConfig.BatchSize = batchSize
		gs.config.lbConfig.PowerOfTwo = powerOfTwo
		gs.config.lbConfig.BlockSize = blockSize
		return nil
	}
}

// WithLBType supplies loadBalancer type
func WithLBType(mixed string, prefill string, decode string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.PdMixedLB = convertLBType(mixed)
		gs.config.lbConfig.PrefillLB = convertLBType(prefill)
		gs.config.lbConfig.DecodeLB = convertLBType(decode)
		return nil
	}
}

func convertLBType(lb string) LoadBalancerType {
	switch lb {
	case "roundRobin":
		return LoadBalancerRoundRobin
	case "leastConn":
		return LoadBalancerLeastConn
	case "capacity":
		return LoadBalancerCapacity
	case "token":
		return LoadBalancerToken
	case "decode":
		return LoadBalancerDecode
	case "prefillTimeAware":
		return LoadBalancerPrefillTimeAware
	case "consistentHash":
		return LoadBalancerConsistentHash
	case "prefixCache":
		return LoadBalancerPrefixCache
	default:
		return LoadBalancerNone
	}
}

// WithSnapFreq supplies insSnapShotFreq
func WithSnapFreq(t int) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.insSnapShotFreq = time.Duration(t) * time.Second
		return nil
	}
}

// WithCrypto supplies hmac and aes
func WithCrypto(hm *crypto.HmacManager, am *crypto.AesManager) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.hmacMgr = hm
		gs.aesMgr = am
		return nil
	}
}

// WithInsConnectType supplies connect type in instance
func WithInsConnectType(t string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		if t == "" {
			t = "sse"
		}
		gs.config.insConnectType = t
		return nil
	}
}

// WithInsNumLimit set insNumPerGS
func WithInsNumLimit(insNum int) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.maxInsNumPerGS = insNum
		return nil
	}
}

// WithReqSurvivalDuration request Survival Duration
func WithReqSurvivalDuration(timeout time.Duration) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.reqSurvivalDuration = timeout
		return nil
	}
}

// WithTokenizationRatio setup tokenization ratio
func WithTokenizationRatio(tokenizationRatio float64) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.tokenizationRatio = tokenizationRatio
		return nil
	}
}

// WithCacheDriverOps register cache driver ops
func WithCacheDriverOps(ops *cachecenter.CacheDriverOps) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.cacheDriverOps = ops
		return nil
	}
}

// WithPretrainTTFTPath set pretrain ttft data path
func WithPretrainTTFTPath(path string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.PretrainTTFTPath = path
		return nil
	}
}

// WithRuntimeMode set runtime mode for gs
func WithRuntimeMode(runtimeMode base.RuntimeMode) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.runtimeMode = runtimeMode
		return nil
	}
}

// WithKvc wires the per-model KvcSessionManager when KVC management is enabled
// (Phase 2). Constructs a VllmKvcClient pointing at kvcCfg.Vllm.Endpoint and a
// KvcSessionManager subscribed to the AgentRegistry. Called from AigwManager.RegisterModel.
func WithKvc(reg agentregistry.Registry, kvcCfg base.KvcConfig, clock agentregistry.Clock) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		if !kvcCfg.Enabled || reg == nil {
			return nil
		}
		vcfg := kvcCfg.Vllm
		sender := NewVllmKvcClient(vcfg.Endpoint, VllmClientConfig{
			Endpoint: vcfg.Endpoint, TimeoutMs: vcfg.TimeoutMs, MaxRetries: vcfg.MaxRetries,
			RetryBaseDelayMs: vcfg.RetryBaseDelayMs, RetryMaxDelayMs: vcfg.RetryMaxDelayMs,
			BatchSize: vcfg.BatchSize, HmacEnabled: vcfg.HmacEnabled,
		})
		sessionCfg := KvcSessionConfig{
			SessionTtlSec:           kvcCfg.Session.SessionTtlSec,
			BlockTtlSec:             kvcCfg.Session.BlockTtlSec,
			PendingBlockMatchTtlSec: kvcCfg.Session.PendingBlockMatchTtlSec,
			MaxRetries:              kvcCfg.Vllm.MaxRetries,
			Offload:                 kvcCfg.Agent.Offload,
			Prefetch:                kvcCfg.Agent.Prefetch,
			Aging:                   kvcCfg.Agent.Aging,
		}
		gs.kvcSessionMgr = NewKvcSessionManager(gs.config.model, reg, sender, sessionCfg, clock)
		return nil
	}
}

// WithRenderClientConfig set render client config for gs
func WithRenderClientConfig(renderCfg renderclient.RenderClientConfig) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.renderClientConfig = renderCfg
		return nil
	}
}
