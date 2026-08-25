/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"huawei.com/aigw/pkg/log"
)

// VllmClientConfig configures the HTTP client to vLLM's /v1/kvc/* control plane.
type VllmClientConfig struct {
	Endpoint         string
	TimeoutMs        int
	MaxRetries       int
	RetryBaseDelayMs int
	RetryMaxDelayMs  int
	BatchSize        int
	HmacEnabled      bool
}

// VllmKvcClient is the production KvcHintSender: maps KvcHint -> vLLM /v1/kvc/* HTTP calls.
// Design doc named this "PyMotorClient"; pyMotor is unavailable, so it targets vLLM directly.
type VllmKvcClient struct {
	endpoint     string
	http         *http.Client
	cfg          VllmClientConfig
	pollInterval time.Duration // prefetch poll interval (default 200ms; tests override)
}

func NewVllmKvcClient(endpoint string, cfg VllmClientConfig) *VllmKvcClient {
	if cfg.TimeoutMs == 0 {
		cfg.TimeoutMs = 3000
	}
	return &VllmKvcClient{
		endpoint: endpoint,
		http:     &http.Client{Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond},
		cfg:      cfg,
	}
}

// vllmHintBody is the JSON vLLM expects (matches vllm-kvc-offload-prefetch-design §6).
type vllmHintBody struct {
	HintID      string  `json:"hint_id"`
	Op          string  `json:"op"` // informational; endpoint already encodes op
	BlockHashes []int64 `json:"block_hashes"`
	TargetTier  string  `json:"target_tier,omitempty"`
}

// Send implements KvcHintSender. offload/evict: sync ack. prefetch: submit+poll (C2).
func (c *VllmKvcClient) Send(ctx context.Context, hint *KvcHint) (*HintAck, error) {
	if hint.Type == HintPrefetch {
		return c.sendPrefetch(ctx, hint)
	}
	return c.sendSync(ctx, hint)
}

func (c *VllmKvcClient) sendSync(ctx context.Context, hint *KvcHint) (*HintAck, error) {
	path := "/v1/kvc/" + string(hint.Type) // "offload" | "evict"
	// Aggregate all session block_hashes into one vLLM call (block_hashes is the handle).
	body, _ := json.Marshal(c.toBody(hint))
	ack, err := c.doWithRetry(ctx, path, body)
	if err != nil {
		return nil, err
	}
	ack.HintID = hint.HintID
	return ack, nil
}

// sendPrefetch implements async prefetch: POST /v1/kvc/prefetch (202 + job_id),
// then poll GET /v1/kvc/jobs/{job_id} until done/failed. See Task C2.
func (c *VllmKvcClient) sendPrefetch(ctx context.Context, hint *KvcHint) (*HintAck, error) {
	body, _ := json.Marshal(c.toBody(hint))
	path := "/v1/kvc/prefetch"
	submit, err := c.doWithRetry(ctx, path, body)
	if err != nil {
		return nil, err
	}
	if submit.JobID == "" {
		// vLLM returned synchronously (no job_id) — treat as final
		submit.HintID = hint.HintID
		return submit, nil
	}
	// poll GET /v1/kvc/jobs/{job_id}
	interval := c.pollInterval
	if interval == 0 {
		interval = 200 * time.Millisecond
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		select {
		case <-deadline.Done():
			return nil, fmt.Errorf("prefetch job %s poll timeout", submit.JobID)
		case <-time.After(interval):
		}
		status, err := c.pollJob(deadline, submit.JobID)
		if err != nil {
			return nil, err
		}
		if status.Status == "done" || status.Status == "failed" {
			return c.finalizePrefetchAck(hint, submit, status), nil
		}
	}
}

type vllmJobStatus struct {
	JobID        string  `json:"job_id"`
	Status       string  `json:"status"`
	DoneHashes   []int64 `json:"done_hashes"`
	FailedHashes []int64 `json:"failed_hashes"`
	BlocksPinned bool    `json:"blocks_pinned"`
}

func (c *VllmKvcClient) pollJob(ctx context.Context, jobID string) (*vllmJobStatus, error) {
	url := c.endpoint + "/v1/kvc/jobs/" + jobID
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job %s not found (expired)", jobID)
	}
	raw, _ := io.ReadAll(resp.Body)
	var s vllmJobStatus
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse job status: %w", err)
	}
	return &s, nil
}

func (c *VllmKvcClient) finalizePrefetchAck(hint *KvcHint, submit *HintAck, status *vllmJobStatus) *HintAck {
	ack := &HintAck{
		HintID: hint.HintID, Status: AckAccepted, AcceptedHashes: status.DoneHashes,
		FailedHashes: status.FailedHashes, JobID: submit.JobID,
		MissingHashes: submit.MissingHashes,
	}
	if status.Status == "failed" {
		ack.Status = AckPartial
	}
	if status.BlocksPinned {
		ack.BlockPlacements = make(map[int64]string, len(status.DoneHashes))
		for _, h := range status.DoneHashes {
			ack.BlockPlacements[h] = "hbm"
		}
	}
	return ack
}

func (c *VllmKvcClient) toBody(hint *KvcHint) vllmHintBody {
	var hashes []int64
	var target string
	for _, s := range hint.Sessions {
		hashes = append(hashes, s.BlockHashes...)
		if target == "" {
			target = s.TargetTier
		}
	}
	return vllmHintBody{HintID: hint.HintID, Op: string(hint.Type),
		BlockHashes: hashes, TargetTier: target}
}

// doWithRetry retries on 5xx/network/timeout; does NOT retry on 4xx (incl. 409).
// 409 is treated as a cached ack success.
func (c *VllmKvcClient) doWithRetry(ctx context.Context, path string, body []byte) (*HintAck, error) {
	url := c.endpoint + path
	max := c.cfg.MaxRetries
	if max == 0 {
		max = 5
	}
	base := time.Duration(c.cfg.RetryBaseDelayMs) * time.Millisecond
	if base == 0 {
		base = time.Second
	}
	maxDelay := time.Duration(c.cfg.RetryMaxDelayMs) * time.Millisecond
	if maxDelay == 0 {
		maxDelay = 30 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt <= max; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode == http.StatusConflict {
			// 409: cached ack — parse body as success
			raw, derr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if derr != nil {
				return nil, derr
			}
			return parseAck(raw)
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// 4xx (non-409): client error, do not retry
			_ = resp.Body.Close()
			return nil, fmt.Errorf("vllm kvc %s returned %d (no retry)", path, resp.StatusCode)
		} else if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("vllm kvc %s returned %d", path, resp.StatusCode)
			_ = resp.Body.Close()
		} else {
			// 2xx
			raw, derr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if derr != nil {
				return nil, derr
			}
			return parseAck(raw)
		}
		// backoff
		if attempt < max {
			delay := base << uint(attempt)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Warn().Msgf("[kvc] %s retry after %v (attempt %d)", path, delay, attempt+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return nil, fmt.Errorf("vllm kvc %s failed after %d retries: %v", path, max, lastErr)
}

func parseAck(raw []byte) (*HintAck, error) {
	var v struct {
		HintID          string            `json:"hint_id"`
		Status          string            `json:"status"`
		Accepted        []int64           `json:"accepted_hashes"`
		InFlight        []int64           `json:"in_flight_hashes"`
		Missing         []int64           `json:"missing_hashes"`
		Failed          []int64           `json:"failed_hashes"`
		Purged          []int64           `json:"purged_hashes"`
		NotFound        []int64           `json:"not_found_hashes"`
		BlockPlacements map[string]string `json:"block_placements"` // vLLM sends {hash(int64 as string)->tier-name}
		JobID           string            `json:"job_id"`
		Error           string            `json:"error"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse ack: %w", err)
	}
	ack := &HintAck{
		HintID: v.HintID, Status: HintAckStatus(v.Status), AcceptedHashes: v.Accepted,
		InFlightHashes: v.InFlight, MissingHashes: v.Missing, FailedHashes: v.Failed,
		PurgedHashes: v.Purged, NotFoundHashes: v.NotFound, JobID: v.JobID, Error: v.Error,
	}
	// vLLM sends block_placements as map[string]string {hash -> tier name}.
	// We store as map[int64]string. Convert keys.
	if v.BlockPlacements != nil {
		ack.BlockPlacements = make(map[int64]string, len(v.BlockPlacements))
		for h, tier := range v.BlockPlacements {
			if hash, e := strconv.ParseInt(h, 10, 64); e == nil {
				ack.BlockPlacements[hash] = tier
			}
		}
	}
	return ack, nil
}
