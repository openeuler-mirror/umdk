/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Unit tests for ZMQ receive error classification and reconnect trigger.
 * Create: 2026-08-05
 */

package kvevents

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	zmq "github.com/pebbe/zmq4"
)

// TestIsFatalRecvError_TableDriven pins the classification logic that decides
// whether a ZMQ receive() error should trigger an automatic reconnect.
//
// Context: client.go declares `reconnectCh` and selects on it in receiveLoop,
// but nothing in the codebase ever sends to it. As a result, a broken ZMQ
// connection (vLLM restarted, network blip, ETERM) never triggered
// `reconnect()` and aigw silently stopped receiving KV events for that
// instance forever — the prefix-cache index went stale for that worker.
//
// The fix classifies receive() errors: fatal errors (context terminated,
// socket/context closed) trigger reconnect; transient errors (timeout, EAGAIN)
// just log and retry. This test pins the classification against the REAL
// pebbe/zmq4 sentinel values — not fabricated strings — so it will fail if
// the classifier ever diverges from what the library actually returns (which
// is exactly how the original string-matching version shipped broken: its
// lowercase substrings like "context was terminated" never matched the real
// "Context was terminated" / "Socket is closed" / "Context is closed").
func TestIsFatalRecvError_TableDriven(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic error", errors.New("something broke"), false},
		{"transient timeout", errors.New("resource temporarily unavailable"), false},
		{"EAGAIN-like", errors.New("poll timeout"), false},
		{"EINTR (interrupted)", fmt.Errorf("recv error: %w", zmq.Errno(4 /* EINTR */)), false},

		// Real zmq4 sentinels — exactly what the library returns in production.
		{"ETERM raw", zmq.ETERM, true},
		{"ETERM wrapped", fmt.Errorf("recv error: %w", zmq.ETERM), true},
		{"ErrorSocketClosed raw", zmq.ErrorSocketClosed, true},
		{"ErrorSocketClosed wrapped", fmt.Errorf("recv error: %w", zmq.ErrorSocketClosed), true},
		{"ErrorContextClosed raw", zmq.ErrorContextClosed, true},
		{"ErrorContextClosed wrapped", fmt.Errorf("poll error: %w", zmq.ErrorContextClosed), true},

		// Non-fatal zmq4 errnos.
		{"ENOTSOCK raw", zmq.ENOTSOCK, false},
		{"ENOTSOCK wrapped", fmt.Errorf("recv error: %w", zmq.ENOTSOCK), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isFatalRecvError(tc.err)
			if got != tc.want {
				t.Errorf("isFatalRecvError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsFatalRecvError_RealErrorStrings guards against the original bug: the
// string-matching version matched lowercase substrings that never appeared in
// the real zmq4 error strings. Assert that the real .Error() output is in fact
// classified as fatal — if the library ever changes the wording, this test
// fails loudly instead of silently breaking reconnect in production.
func TestIsFatalRecvError_RealErrorStrings(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{zmq.ETERM, true},                   // "Context was terminated"
		{zmq.ErrorSocketClosed, true},       // "Socket is closed"
		{zmq.ErrorContextClosed, true},      // "Context is closed"
		{fmt.Errorf("x: %w", zmq.ETERM), true},
	}
	for _, tc := range cases {
		if got := isFatalRecvError(tc.err); got != tc.want {
			t.Errorf("isFatalRecvError(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestReconnectAttempts_InitiallyZero pins the new observable counter.
// receiveLoop increments it on every triggered reconnect. Before the fix this
// counter did not exist; the only reconnect trigger (`reconnectCh`) was dead
// code with no sender, so a broken socket would never be observed/recovered.
func TestReconnectAttempts_InitiallyZero(t *testing.T) {
	c := &ZMQClient{}
	if got := c.ReconnectAttempts(); got != 0 {
		t.Errorf("new client ReconnectAttempts() = %d, want 0", got)
	}
}

// TestReconnectAttempts_Increment pins that the counter is readable and
// incrementable from the package (used by receiveLoop after a fatal error).
func TestReconnectAttempts_Increment(t *testing.T) {
	c := &ZMQClient{}
	atomic.AddInt64(&c.reconnectAttempts, 1)
	if got := c.ReconnectAttempts(); got != 1 {
		t.Errorf("after 1 increment ReconnectAttempts() = %d, want 1", got)
	}
	atomic.AddInt64(&c.reconnectAttempts, 4)
	if got := c.ReconnectAttempts(); got != 5 {
		t.Errorf("after 5 total increments ReconnectAttempts() = %d, want 5", got)
	}
}
