/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Deployment data model and cross-pool StateKey for the provider pool.
 * Create: 2026-06-09
 */

// Package apipool provides IntelliRouter-style provider pool scheduling for AIGW.
package apipool

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// DeploymentStatus is the runtime health status of a deployment endpoint.
type DeploymentStatus int

const (
	// StatusHealthy means the endpoint is selectable.
	StatusHealthy DeploymentStatus = iota
	// StatusCooldown means the endpoint is temporarily skipped.
	StatusCooldown
)

// String renders the status as a human-readable token for logs.
func (s DeploymentStatus) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusCooldown:
		return "cooldown"
	default:
		return "unknown"
	}
}

// Deployment is the immutable configuration of one provider endpoint.
type Deployment struct {
	ID        string
	ModelName string
	APIKey    string
	APIBase   string
	Provider  string

	TPM int // 0 = unlimited
	RPM int // 0 = unlimited

	Tags             []string
	Timeout          time.Duration
	VerifySSL        bool
	AuthHeaderName   string
	AuthHeaderPrefix string
}

// StateKey is the cross-pool addressing key for shared quota/cooldown/latency.
// Same (provider, apiKey) shares one state entry across multiple model pools.
type StateKey struct {
	Provider       string
	KeyFingerprint string // = sha256(apiKey)[:16], avoids retaining plaintext key
}

// StateKey computes the cross-pool key for this deployment.
func (d *Deployment) StateKey() StateKey {
	sum := sha256.Sum256([]byte(d.APIKey))
	return StateKey{
		Provider:       d.Provider,
		KeyFingerprint: hex.EncodeToString(sum[:])[:16],
	}
}
