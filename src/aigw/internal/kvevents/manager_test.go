/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: KV events manager construction tests (#900).
 */

package kvevents

import (
	"testing"
	"time"
)

func TestNewKVEventsManager_ConstructedActive(t *testing.T) {
	cfg := KVEventsManagerConfig{
		EndpointTemplate: "tcp://{ip}:5557",
		PollTimeout:      100 * time.Millisecond,
		ReconnectDelay:   time.Second,
		HWM:              1000,
	}
	m := NewKVEventsManager(countingHandlerAsEventHandler{}, cfg)
	if !m.IsEnabled() {
		t.Fatalf("constructed manager must be active")
	}
}

func TestBuildEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		template string
		ip       string
		want     string
	}{
		{"default template", "tcp://{ip}:5557", "10.0.0.1", "tcp://10.0.0.1:5557"},
		{"custom port", "tcp://{ip}:6666", "10.0.0.1", "tcp://10.0.0.1:6666"},
		{"ipc transport", "ipc:///tmp/kv-events.sock", "10.0.0.1", "ipc:///tmp/kv-events.sock"},
		{"empty ip keeps placeholder", "tcp://{ip}:5557", "", "tcp://:5557"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewKVEventsManager(countingHandlerAsEventHandler{},
				KVEventsManagerConfig{EndpointTemplate: tc.template})
			if got := m.buildEndpoint(tc.ip); got != tc.want {
				t.Fatalf("buildEndpoint(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

type countingHandlerAsEventHandler struct{}

func (countingHandlerAsEventHandler) OnBlockStored(_ BlockStored) error           { return nil }
func (countingHandlerAsEventHandler) OnBlockRemoved(_ BlockRemoved) error         { return nil }
func (countingHandlerAsEventHandler) OnAllBlocksCleared(_ AllBlocksCleared) error { return nil }
