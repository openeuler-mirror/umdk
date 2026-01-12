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
			gs.config.deployPolicy = mixedDeployment
		case "separated":
			gs.config.deployPolicy = separatedDeployment
		default:
			return fmt.Errorf("invalid deployment policy: %s", deploy)
		}

		return nil
	}
}

// WithPredict supplies predict type
func WithPredict(predictType string, gbm *lightgbm.Booster) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		switch predictType {
		case "none":
			gs.config.predictType = predictTypeNone
		case "ema":
			gs.config.predictType = predictTypeEma
		case "lightgbm":
			{
				gs.config.predictType = predictTypeLightgbm
				gs.lgm = gbm
			}
		default:
			return fmt.Errorf("invalid predict type: %s", predictType)
		}
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
		gs.config.lbConfig.ttftThreshold = maxTTFT
		gs.config.lbConfig.tbtThreshold = maxTBT

		return nil
	}
}

// WithAlgorithmThreshold supplies algorithm threshold
func WithAlgorithmThreshold(minBlocks int, batchSize int, powerOfTwo bool, blockSize int) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.minBlockThreshold = minBlocks
		gs.config.lbConfig.batchSize = batchSize
		gs.config.lbConfig.powerOfTwo = powerOfTwo
		gs.config.lbConfig.blockSize = blockSize
		return nil
	}
}

// WithLBType supplies loadBalancer type
func WithLBType(mixed string, prefill string, decode string) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.config.lbConfig.pdMixedLB = convertLBType(mixed)
		gs.config.lbConfig.prefillLB = convertLBType(prefill)
		gs.config.lbConfig.decodeLB = convertLBType(decode)
		return nil
	}
}

func convertLBType(lb string) loadBalancerType {
	switch lb {
	case "roundRobin":
		return loadBalancerRoundRobin
	case "leastConn":
		return loadBalancerLeastConn
	case "capacity":
		return loadBalancerCapacity
	case "token":
		return loadBalancerToken
	case "decode":
		return loadBalancerDecode
	default:
		return loadBalancerNone
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
		gs.config.hmacMgr = hm
		gs.config.aesMgr = am
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
		gs.maxInsNumPerGS = insNum
		return nil
	}
}

// WithReqSurvivalDuration request Survival Duration, unit is second
func WithReqSurvivalDuration(timeout int64) GlobalSchedulerManagerOption {
	return func(gs *GlobalSchedulerManager) error {
		gs.reqSurvivalDuration = timeout
		return nil
	}
}
