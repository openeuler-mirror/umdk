/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: SSE stream reader for AIGW proxy.
 * Create: 2026-04-29
 */

// Package proxy provides HTTP request proxying for AIGW.
package proxy

import (
	"bufio"
	"io"
	"strings"
	"sync"
)

// StreamReader reads Server-Sent Events (SSE) from an HTTP response body.
type StreamReader struct {
	reader  *bufio.Reader
	body    io.ReadCloser
	closed  bool
	mu      sync.Mutex
	closeCh chan struct{}
}

// SSEEvent represents a single Server-Sent Event.
type SSEEvent struct {
	Event string // Event name
	Data  string // Event data
	ID    string // Event ID
	Retry int    // Retry interval (ms)
}

// NewStreamReader creates a new SSE stream reader.
func NewStreamReader(body io.ReadCloser) *StreamReader {
	return &StreamReader{
		reader:  bufio.NewReader(body),
		body:    body,
		closeCh: make(chan struct{}),
	}
}

// ReadEvent reads the next SSE event from the stream.
// Returns io.EOF when the stream is closed.
func (sr *StreamReader) ReadEvent() (*SSEEvent, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.closed {
		return nil, io.EOF
	}

	event := &SSEEvent{}

	for {
		line, err := sr.reader.ReadString('\n')

		// If EOF with no content read, return EOF (unless we have accumulated event data)
		if err == io.EOF && line == "" {
			if event.Data != "" || event.Event != "" || event.ID != "" || event.Retry != 0 {
				return event, nil
			}
			return nil, io.EOF
		}

		// Remove trailing newline and whitespace
		line = strings.TrimSpace(line)

		// Empty line signals end of event
		if line == "" {
			// Return event if we have any data (including multi-line data)
			if event.Data != "" || event.Event != "" || event.ID != "" || event.Retry != 0 {
				return event, nil
			}
			// No data accumulated yet - continue reading (or EOF will be handled in next iteration)
			continue
		}

		// Parse SSE field
		var fieldName, fieldValue string

		// SSE spec: field name is case-insensitive, value comes after ": " (preferred) or ":"
		// Only split on first colon, value part keeps all content including any colons
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			fieldName = strings.TrimSpace(line[:idx])
			fieldValue = line[idx+1:]
			// If value starts with space, trim it (standard format is ": ")
			if len(fieldValue) > 0 && fieldValue[0] == ' ' {
				fieldValue = fieldValue[1:]
			}
		} else {
			// No colon found, could be a comment (starts with :) or invalid line
			if strings.HasPrefix(line, ":") {
				continue // comment line, ignore
			}
			continue // invalid line
		}

		switch fieldName {
		case "event":
			event.Event = fieldValue
		case "data":
			if event.Data != "" {
				event.Data += "\n"
			}
			event.Data += fieldValue
		case "id":
			event.ID = fieldValue
		case "retry":
			// Parse retry interval - trim first, then extract numeric portion
			fieldValue = strings.TrimSpace(fieldValue)
			for _, c := range fieldValue {
				if c >= '0' && c <= '9' {
					event.Retry = event.Retry*10 + int(c-'0')
				} else {
					break
				}
			}
		}

		// After processing a field, check if we're at EOF
		if err == io.EOF {
			return event, nil
		}
	}
}

// ReadAllEvents reads all events from the stream until EOF.
// Returns a slice of all events read.
func (sr *StreamReader) ReadAllEvents() ([]*SSEEvent, error) {
	var events []*SSEEvent
	for {
		event, err := sr.ReadEvent()
		if err != nil {
			if err == io.EOF {
				return events, nil
			}
			return events, err
		}
		events = append(events, event)
	}
}

// Close closes the stream reader.
func (sr *StreamReader) Close() error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.closed {
		return nil
	}

	sr.closed = true
	close(sr.closeCh)
	if sr.body != nil {
		return sr.body.Close()
	}
	return nil
}

// Closed returns whether the stream is closed.
func (sr *StreamReader) Closed() bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.closed
}
