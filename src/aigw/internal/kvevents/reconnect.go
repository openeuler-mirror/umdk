/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ZMQ reconnect trigger logic.
 * Create: 2026-08-05
 */

package kvevents

import (
	"errors"
	"sync/atomic"

	zmq "github.com/pebbe/zmq4"
)

// isFatalRecvError classifies a ZMQ receive() error as fatal (the socket is
// unusable and must be reconnected) or transient (just retry on the next
// poll). Without this classification, `receiveLoop` logged the error and
// continued retrying on the same broken socket forever — an earlier design
// relied on a `reconnectCh` channel that was never sent to, so a broken ZMQ
// connection silently dropped every KV event for that instance, leaving the
// prefix-cache index stale. (The channel has since been removed; this fatal-
// error path is now the sole reconnect trigger.)
//
// Fatal errors are detected by typed comparison against the pebbe/zmq4
// sentinel errors and the ETERM errno, not by string matching. The receive
// path wraps errors with `fmt.Errorf("...: %w", err)`, so errors.Is/errors.As
// traverse the wrap chain. This covers the three fatal cases that occur when
// a vLLM container restarts or the libzmq context is terminated:
//   - zmq.ETERM ("Context was terminated") — the context was terminated.
//   - zmq.ErrorSocketClosed ("Socket is closed") — the socket was closed.
//   - zmq.ErrorContextClosed ("Context is closed") — the context was closed.
//
// Transient errors (poll timeout, EAGAIN, EINTR) return false and are retried
// on the next poll without reconnecting.
func isFatalRecvError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, zmq.ErrorSocketClosed) || errors.Is(err, zmq.ErrorContextClosed) {
		return true
	}
	// zmq4 surfaces context-termination as an zmq.Errno (ETERM), which does
	// not implement errors.Is/Unwrap, so extract it by type instead.
	var errno zmq.Errno
	if errors.As(err, &errno) && errno == zmq.ETERM {
		return true
	}
	return false
}

// ReconnectAttempts returns the number of times this client has triggered an
// automatic reconnect since startup. Exposed primarily for observability and
// tests; receiveLoop increments it on every fatal-error-triggered reconnect.
// Before the reconnect fix existed this counter was always 0 because nothing
// ever triggered `reconnect()` — a non-zero value proves the new path is
// firing in production.
func (c *ZMQClient) ReconnectAttempts() int64 {
	return atomic.LoadInt64(&c.reconnectAttempts)
}
