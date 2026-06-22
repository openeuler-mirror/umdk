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

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/internal/cachecenter"
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
