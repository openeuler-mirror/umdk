/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"context"
	"time"
)

// SessionState is the lifecycle state of a session within KvcSessionManager.
type SessionState int

const (
	SessionActive     SessionState = iota // bound to active agent
	SessionSuspended                      // agent suspected, blocks offloaded
	SessionRecovering                     // agent recovered, blocks prefetching
	SessionTerminated                     // agent gone, awaiting eviction
	SessionEvicted                        // blocks removed
)

// Session is the per-model record of one agent session and its KVC blocks.
type Session struct {
	SessionID           string
	AgentID             string
	Model               string
	State               SessionState
	LastPrefillInstance string
	LastDecodeInstance  string
	BlockHashes         []int64
	LastRequestAt       time.Time
	AccessCount         int
	AccessFrequency     float64
	SuspendedAt         *time.Time
	RecoveringAt        *time.Time
	TerminatedAt        *time.Time
	PendingHints        []PendingHint
	HintFailed          bool
	HintRejectedReason  string
}

// BlockInfo is the per-model record of one KVC block (content-hash keyed).
type BlockInfo struct {
	BlockHash  int64
	Model      string
	Instance   string
	Sessions   map[string]bool // session_ids sharing this block
	LastSeenAt time.Time
	StoredAt   time.Time
	Tier       string // "hbm" | "ddr" | "ssd" | "remote" (advisory, from vLLM ack)
}

// PendingHint is a hint awaiting ack (for retry/observability/restart recovery).
type PendingHint struct {
	Hint        *KvcHint
	NextRetryAt time.Time
	Retries     int
}

// HintType selects the vLLM endpoint: offload|prefetch|evict -> /v1/kvc/{type}.
type HintType string

const (
	HintOffload  HintType = "offload"
	HintPrefetch HintType = "prefetch"
	HintEvict    HintType = "evict"
)

// KvcHint is the AIGW-side hint; VllmKvcClient maps it to vLLM's /v1/kvc/* body.
type KvcHint struct {
	HintID       string   // UUID, idempotency & ack key (maps to vLLM hint_id)
	Type         HintType // selects /v1/kvc/{offload|prefetch|evict} endpoint
	Model        string
	AgentID      string
	Sessions     []SessionHint
	IssuedAt     time.Time
	IssuedReason string // "agent_suspected" | "agent_recovered" | "agent_gone" | "session_close" | "aging"
	Priority     int
}

// SessionHint is one session within a KvcHint.
type SessionHint struct {
	SessionID    string
	LastInstance string
	BlockHashes  []int64 // the universal handle — vLLM resolves hash->live block
	SourceTier   string  // advisory
	TargetTier   string  // advisory; maps to vLLM target_tier
}

// HintAck is the ack from the hint sender (vLLM or mock).
type HintAck struct {
	HintID          string
	Status          HintAckStatus
	AcceptedHashes  []int64
	InFlightHashes  []int64          // vLLM: decode mid-write; NOT an error, do not retry
	MissingHashes   []int64          // vLLM: not resident in any tier; NOT an error, do not retry
	FailedHashes    []int64          // vLLM: store/load failed; GPU copy preserved for offload
	PurgedHashes    []int64          // evict
	NotFoundHashes  []int64          // evict: weren't anywhere
	BlockPlacements map[int64]string // hash -> actual tier (advisory, learned)
	JobID           string           // present for prefetch (202) and offload partial
	Error           string
}

type HintAckStatus string

const (
	AckAccepted HintAckStatus = "accepted"
	AckRejected HintAckStatus = "rejected"
	AckPartial  HintAckStatus = "partial"
)

// KvcHintSender dispatches hints to the KVC executor (vLLM in production, mock in tests).
// Implementations: VllmKvcClient (production, HTTP->vLLM /v1/kvc/*), MockKvcHintSender (test).
type KvcHintSender interface {
	// Send dispatches a hint. For offload/evict: synchronous ack.
	// For prefetch: submits + polls GET /v1/kvc/jobs/{job_id} until done (see Task C2),
	// returning a final ack with BlockPlacements filled.
	Send(ctx context.Context, hint *KvcHint) (*HintAck, error)
}
