/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Proxy manager for HTTP request forwarding in AIGW.
 * Create: 2026-04-29
 */

// Package proxy provides HTTP request proxying for AIGW.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/pkg/log"
)

// ProxyManager manages HTTP request forwarding to backend workers.
type ProxyManager struct {
	ctx                context.Context
	cancel             context.CancelFunc
	rwLock             sync.RWMutex
	client             *http.Client
	timeout            time.Duration
	maxRetry           int
	retryBaseInterval  time.Duration  // Base interval for exponential backoff
	retryMaxInterval   time.Duration  // Maximum interval cap for backoff
	circuitBreaker     *CircuitBreaker // Circuit breaker for fault tolerance
}

// ProxyConfig is the configuration for ProxyManager.
type ProxyConfig struct {
	Timeout            time.Duration      // Request timeout (default: 30s)
	MaxRetry           int                // Maximum retry attempts (default: 3)
	RetryBaseInterval  time.Duration      // Base interval for exponential backoff (default: 100ms)
	RetryMaxInterval   time.Duration      // Maximum interval cap for backoff (default: 5s)
	CircuitBreaker     *CircuitBreakerConfig // Circuit breaker configuration (optional)
}

// NewProxyManager creates a new ProxyManager with configuration.
func NewProxyManager(parentCtx context.Context, config *ProxyConfig) *ProxyManager {
	if config == nil {
		config = &ProxyConfig{
			Timeout:            30 * time.Second,
			MaxRetry:           3,
			RetryBaseInterval:  100 * time.Millisecond,
			RetryMaxInterval:   5 * time.Second,
		}
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetry == 0 {
		config.MaxRetry = 3
	}
	if config.RetryBaseInterval == 0 {
		config.RetryBaseInterval = 100 * time.Millisecond
	}
	if config.RetryMaxInterval == 0 {
		config.RetryMaxInterval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize circuit breaker if configured
	var cb *CircuitBreaker
	if config.CircuitBreaker != nil && config.CircuitBreaker.Enabled {
		cb = NewCircuitBreaker(config.CircuitBreaker)
	}

	return &ProxyManager{
		ctx:                ctx,
		cancel:             cancel,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		timeout:            config.Timeout,
		maxRetry:           config.MaxRetry,
		retryBaseInterval:  config.RetryBaseInterval,
		retryMaxInterval:   config.RetryMaxInterval,
		circuitBreaker:     cb,
	}
}

// ForwardRequest represents parameters for forwarding an HTTP request.
type ForwardRequest struct {
	Method    string            // HTTP method (GET, POST, etc.)
	TargetURL string            // Target URL without @rank (e.g., "http://worker:8000")
	Route     string            // API route (e.g., "/v1/chat/completions")
	FullURL   string            // When non-empty, used verbatim instead of TargetURL+Route
	Headers   http.Header       // Original request headers
	Body      []byte            // Request body
	DpRank    *int              // DP rank for header injection (optional)
	Stream    bool              // Whether to stream the response
}

// ForwardResult represents the result of a forwarded request.
type ForwardResult struct {
	StatusCode  int
	Headers     http.Header
	Body        []byte         // Non-streaming response
	StreamReader *StreamReader // Streaming response
	Error       error
}

// ForwardRequest forwards an HTTP request to the target worker.
func (pm *ProxyManager) ForwardRequest(ctx context.Context, req *ForwardRequest) (*ForwardResult, error) {
	// 0. Check circuit breaker before attempting request
	if pm.circuitBreaker != nil && !pm.circuitBreaker.CanExecute() {
		log.Warn().Msg("[Proxy] circuit breaker is open, rejecting request")
		return nil, fmt.Errorf("circuit breaker is open")
	}

	// 1. Build complete URL (FullURL wins when set)
	targetURL := req.FullURL
	if targetURL == "" {
		targetURL = req.TargetURL + req.Route
	}

	// 2. Create HTTP request with context
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = strings.NewReader(string(req.Body))
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// 3. Forward original headers
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// 4. Inject DP Rank header if present
	if req.DpRank != nil {
		httpReq.Header.Set("X-data-parallel-rank", strconv.Itoa(*req.DpRank))
	}

	// 5. Set Content-Type if not present
	if httpReq.Header.Get("Content-Type") == "" && len(req.Body) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// 6. Send request with exponential backoff retry
	var resp *http.Response
	var lastErr error
	var lastStatusCode int

	// Idempotent methods can be safely retried; non-idempotent methods should not retry
	// unless response indicates retryable error (5xx) and request body can be replayed
	isIdempotent := isIdempotentMethod(req.Method)
	maxRetryCount := pm.maxRetry
	if !isIdempotent && req.Stream {
		// For streaming POST requests, disable retry by default to avoid duplicate processing
		maxRetryCount = 0
		log.Debug().Msgf("[Proxy] streaming %s request, retry disabled for safety", req.Method)
	}

	for retry := 0; retry <= maxRetryCount; retry++ {
		if retry > 0 {
			// Calculate exponential backoff with jitter: baseInterval * 2^retry * (0.5 + random/2)
			backoff := pm.retryBaseInterval * time.Duration(1<<uint(retry-1))
			// Cap at maxInterval
			if backoff > pm.retryMaxInterval {
				backoff = pm.retryMaxInterval
			}
			// Add jitter (10% randomization) to prevent thundering herd
			jitter := time.Duration(int64(backoff) / 10)
			backoff = backoff - jitter/2 + time.Duration(time.Now().UnixNano()%int64(jitter))

			log.Debug().Msgf("[Proxy] retry %d, backoff %v", retry, backoff)

			// Use select to allow context cancellation during backoff
			select {
			case <-time.After(backoff):
				// Continue with retry
			case <-ctx.Done():
				return nil, fmt.Errorf("retry interrupted: %w", ctx.Err())
			}
		}

		resp, lastErr = pm.client.Do(httpReq)
		if resp != nil {
			lastStatusCode = resp.StatusCode
		}

		// Check if request succeeded (no network error AND 2xx status)
		requestSucceeded := lastErr == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300

		if requestSucceeded {
			break
		}

		// Determine if we should retry
		shouldRetry := false
		if lastErr != nil {
			// Network error - always retry
			shouldRetry = true
		} else if resp != nil {
			if resp.StatusCode >= 500 {
				// Server error - retry
				shouldRetry = true
			} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				// Client error - do not retry for idempotent methods either
				shouldRetry = false
			}
		}

		// For non-idempotent methods, do not retry on client errors
		if !isIdempotent && resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			log.Warn().Msgf("[Proxy] non-idempotent %s request failed with client error %d, not retrying",
				req.Method, resp.StatusCode)
			shouldRetry = false
		}

		if !shouldRetry || retry >= maxRetryCount {
			break
		}

		log.Warn().Msgf("[Proxy] request attempt %d failed: network=%v status=%d",
			retry+1, lastErr, lastStatusCode)
	}

	// Record in circuit breaker based on final outcome
	// Failure: network error (lastErr != nil) or HTTP server error (5xx)
	if lastErr != nil || lastStatusCode >= 500 {
		if pm.circuitBreaker != nil {
			pm.circuitBreaker.RecordFailure()
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("server error: %d", lastStatusCode)
	}

	// Record success in circuit breaker
	if pm.circuitBreaker != nil {
		pm.circuitBreaker.RecordSuccess()
	}

	// 7. Build result
	result := &ForwardResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	// 8. Handle streaming vs non-streaming
	if req.Stream {
		result.StreamReader = NewStreamReader(resp.Body)
		return result, nil
	}

	// Non-streaming: read entire body
	defer resp.Body.Close()
	result.Body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetCircuitBreakerStats returns the circuit breaker statistics.
func (pm *ProxyManager) GetCircuitBreakerStats() CircuitBreakerStats {
	if pm.circuitBreaker == nil {
		return CircuitBreakerStats{}
	}
	return pm.circuitBreaker.GetStats()
}

// Stop stops the ProxyManager and its circuit breaker.
func (pm *ProxyManager) Stop() {
	pm.cancel()
	if pm.circuitBreaker != nil {
		pm.circuitBreaker.Reset()
	}
}

// isIdempotentMethod returns true if the HTTP method is considered idempotent.
// Idempotent methods can be safely retried without causing duplicate processing.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "DELETE", "PUT", "TRACE":
		return true
	default:
		return false
	}
}
