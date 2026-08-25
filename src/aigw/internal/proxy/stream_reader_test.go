/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Unit tests for SSE stream reader.
 * Create: 2026-05-11
 */

package proxy

import (
	"io"
	"strings"
	"testing"
)

func TestReadEvent_BasicEvent(t *testing.T) {
	input := "data: Hello World\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event != "" {
		t.Errorf("expected empty event, got %q", event.Event)
	}
	if event.Data != "Hello World" {
		t.Errorf("expected data 'Hello World', got %q", event.Data)
	}
	if event.ID != "" {
		t.Errorf("expected empty id, got %q", event.ID)
	}
}

func TestReadEvent_EventType(t *testing.T) {
	input := "event: chat.completion.chunk\ndata: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event != "chat.completion.chunk" {
		t.Errorf("expected event 'chat.completion.chunk', got %q", event.Event)
	}
	expectedData := `{"choices":[{"delta":{"role":"assistant"}}]}`
	if event.Data != expectedData {
		t.Errorf("expected data %q, got %q", expectedData, event.Data)
	}
}

func TestReadEvent_MultiLineData(t *testing.T) {
	input := "data: line1\ndata: line2\ndata: line3\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "line1\nline2\nline3"
	if event.Data != expected {
		t.Errorf("expected data %q, got %q", expected, event.Data)
	}
}

func TestReadEvent_JsonWithColon(t *testing.T) {
	input := `data: {"content": "hello: world", "url": "http://example.com/path?a=1:b=2"}
`
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{"content": "hello: world", "url": "http://example.com/path?a=1:b=2"}`
	if event.Data != expected {
		t.Errorf("expected data %q, got %q", expected, event.Data)
	}
}

func TestReadEvent_RetryField(t *testing.T) {
	input := "retry: 3000\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Retry != 3000 {
		t.Errorf("expected retry 3000, got %d", event.Retry)
	}
}

func TestReadEvent_RetryWithSpaces(t *testing.T) {
	input := "retry:   5000  \n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Retry != 5000 {
		t.Errorf("expected retry 5000, got %d", event.Retry)
	}
}

func TestReadEvent_RetryWithSuffix(t *testing.T) {
	input := "retry: 4000ms\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Retry != 4000 {
		t.Errorf("expected retry 4000, got %d", event.Retry)
	}
}

func TestReadEvent_IdField(t *testing.T) {
	input := "id: 12345\ndata: test\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.ID != "12345" {
		t.Errorf("expected id '12345', got %q", event.ID)
	}
}

func TestReadEvent_NoSpaceAfterColon(t *testing.T) {
	input := "data:no space\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != "no space" {
		t.Errorf("expected data 'no space', got %q", event.Data)
	}
}

func TestReadEvent_CommentLine(t *testing.T) {
	input := ": This is a comment\ndata: value\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != "value" {
		t.Errorf("expected data 'value', got %q", event.Data)
	}
}

func TestReadEvent_EmptyLinesBetweenEvents(t *testing.T) {
	input := "data: first\n\ndata: second\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event1, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event1.Data != "first" {
		t.Errorf("expected first event data 'first', got %q", event1.Data)
	}

	event2, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event2.Data != "second" {
		t.Errorf("expected second event data 'second', got %q", event2.Data)
	}
}

func TestReadEvent_EOFWithData(t *testing.T) {
	input := "data: last event without final newline"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != "last event without final newline" {
		t.Errorf("expected data 'last event without final newline', got %q", event.Data)
	}
}

func TestReadEvent_ClosedReader(t *testing.T) {
	sr := NewStreamReader(io.NopCloser(strings.NewReader("")))
	sr.Close()

	event, err := sr.ReadEvent()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
	if event != nil {
		t.Errorf("expected nil event, got %v", event)
	}
}

func TestReadAllEvents(t *testing.T) {
	input := "data: event1\n\nevent: test\nevent: chat.completion.chunk\ndata: {\"delta\":\"a\"}\n\nevent: test\ndata: {\"delta\":\"b\"}\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	events, err := sr.ReadAllEvents()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}

	if events[0].Data != "event1" {
		t.Errorf("expected first event data 'event1', got %q", events[0].Data)
	}
	if events[1].Event != "chat.completion.chunk" {
		t.Errorf("expected second event type 'chat.completion.chunk', got %q", events[1].Event)
	}
	if events[2].Event != "test" || events[2].Data != "{\"delta\":\"b\"}" {
		t.Errorf("expected third event (test, b), got (%q, %q)", events[2].Event, events[2].Data)
	}
}

func TestReadEvent_ComplexJsonData(t *testing.T) {
	json := `{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677856582,"model":"gpt-3.5-turbo","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`
	input := "data: " + json + "\n\n"
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	event, err := sr.ReadEvent()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != json {
		t.Errorf("expected data to match input JSON, got %q", event.Data)
	}
}

func TestReadEvent_StreamingChatCompletion(t *testing.T) {
	input := `event: chat.completion.chunk
data: {"id":"chatcmpl-001","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

event: content
data: {"id":"chatcmpl-001","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}

event: content
data: {"id":"chatcmpl-001","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"!"},"finish_reason":null}]}

event: chat.completion.chunk
data: [DONE]

`
	sr := NewStreamReader(io.NopCloser(strings.NewReader(input)))

	count := 0
	for {
		_, err := sr.ReadEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		count++
	}

	if count != 4 {
		t.Errorf("expected 4 events, got %d", count)
	}
}

func TestClosed(t *testing.T) {
	sr := NewStreamReader(io.NopCloser(strings.NewReader("")))

	if sr.Closed() {
		t.Error("expected Closed() to return false before Close()")
	}

	sr.Close()

	if !sr.Closed() {
		t.Error("expected Closed() to return true after Close()")
	}

	// Double close should not panic
	sr.Close()
}

func TestReadEvent_VariousFieldFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		field    string
	}{
		{"colon_space", "data: value\n\n", "value", "Data"},
		{"colon_only", "data:value\n\n", "value", "Data"},
		{"colon_space_comment", ": comment\ndata: value\n\n", "value", "Data"},
		{"event_colon_space", "event: myevent\n\n", "myevent", "Event"},
		{"id_colon_space", "id: abc123\ndata: x\n\n", "abc123", "ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := NewStreamReader(io.NopCloser(strings.NewReader(tt.input)))
			event, err := sr.ReadEvent()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			switch tt.field {
			case "Data":
				if event.Data != tt.expected {
					t.Errorf("expected Data %q, got %q", tt.expected, event.Data)
				}
			case "Event":
				if event.Event != tt.expected {
					t.Errorf("expected Event %q, got %q", tt.expected, event.Event)
				}
			case "ID":
				if event.ID != tt.expected {
					t.Errorf("expected ID %q, got %q", tt.expected, event.ID)
				}
			}
		})
	}
}
