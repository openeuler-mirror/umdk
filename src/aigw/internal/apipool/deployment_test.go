/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

// internal/apipool/deployment_test.go
package apipool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStateKey_FingerprintDeterministic(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	assert.Equal(t, d1.StateKey(), d2.StateKey())
	assert.Equal(t, 16, len(d1.StateKey().KeyFingerprint))
}

func TestStateKey_DifferentKeyDifferentFingerprint(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "openai", APIKey: "sk-xyz"}
	assert.NotEqual(t, d1.StateKey(), d2.StateKey())
}

func TestStateKey_SameKeyDifferentProvider(t *testing.T) {
	d1 := &Deployment{Provider: "openai", APIKey: "sk-abc"}
	d2 := &Deployment{Provider: "deepseek", APIKey: "sk-abc"}
	assert.NotEqual(t, d1.StateKey(), d2.StateKey())
	assert.Equal(t, d1.StateKey().KeyFingerprint, d2.StateKey().KeyFingerprint)
}

func TestStateKey_NoPlaintextKey(t *testing.T) {
	d := &Deployment{Provider: "openai", APIKey: "sk-secret", Timeout: 30 * time.Second}
	assert.NotContains(t, d.StateKey().KeyFingerprint, "sk-secret")
}
