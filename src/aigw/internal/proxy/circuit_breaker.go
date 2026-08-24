/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Circuit breaker for proxy request forwarding in AIGW.
 * Create: 2026-05-06
 */

// Package proxy provides HTTP request proxying for AIGW.
package proxy

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota // Normal operation, requests pass through
	CircuitBreakerOpen                               // Failing, requests are rejected
	CircuitBreakerHalfOpen                           // Testing if service recovered
)

// CircuitBreakerConfig is the configuration for a circuit breaker.
type CircuitBreakerConfig struct {
	Enabled           bool          // Whether to enable circuit breaker
	FailureThreshold  int           // Number of failures to trip breaker (default: 5)
	SuccessThreshold  int           // Number of successes to close breaker in half-open (default: 2)
	Timeout           time.Duration // Time to wait before transitioning to half-open (default: 30s)
}

// CircuitBreaker implements the circuit breaker pattern for fault tolerance.
// States:
//   - Closed: Normal operation, requests pass through
//   - Open: Failing, requests are rejected immediately
//   - HalfOpen: Testing if service has recovered
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CircuitBreakerState
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
	timeout          time.Duration
	lastFailureTime  time.Time
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = &CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 5,
			SuccessThreshold: 2,
			Timeout:         30 * time.Second,
		}
	}

	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	return &CircuitBreaker{
		state:            CircuitBreakerClosed,
		failureThreshold: config.FailureThreshold,
		successThreshold: config.SuccessThreshold,
		timeout:          config.Timeout,
	}
}

// CanExecute checks if a request can be executed based on the circuit breaker state.
// Returns true if the request should proceed, false if it should be rejected.
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		// Check if timeout has elapsed to transition to half-open
		if time.Since(cb.lastFailureTime) >= cb.timeout {
			cb.state = CircuitBreakerHalfOpen
			cb.successCount = 0
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	}
	return false
}

// RecordSuccess records a successful request.
// In half-open state, successes count toward closing the breaker.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitBreakerClosed:
		// Reset failure count on success in closed state
		cb.failureCount = 0
	case CircuitBreakerHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			// Enough successes, close the breaker
			cb.state = CircuitBreakerClosed
			cb.failureCount = 0
			cb.successCount = 0
		}
	}
}

// RecordFailure records a failed request.
// In closed state, failures count toward opening the breaker.
// In half-open state, any failure reopens the breaker.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			// Too many failures, open the breaker
			cb.state = CircuitBreakerOpen
		}
	case CircuitBreakerHalfOpen:
		// Failure in half-open, reopen the breaker
		cb.state = CircuitBreakerOpen
		cb.successCount = 0
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitBreakerClosed
	cb.failureCount = 0
	cb.successCount = 0
}

// Stats returns current statistics of the circuit breaker.
type CircuitBreakerStats struct {
	State           CircuitBreakerState
	FailureCount    int
	SuccessCount    int
	FailureThreshold int
	SuccessThreshold int
}

// GetStats returns current statistics of the circuit breaker.
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return CircuitBreakerStats{
		State:            cb.state,
		FailureCount:     cb.failureCount,
		SuccessCount:     cb.successCount,
		FailureThreshold: cb.failureThreshold,
		SuccessThreshold: cb.successThreshold,
	}
}
