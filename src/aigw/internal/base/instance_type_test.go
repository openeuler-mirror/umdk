/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: instance type test
 * Create: 2026-03-27
 */

package base

import (
	"testing"
)

func TestInstanceRoleString(t *testing.T) {
	tests := []struct {
		role InstanceRole
		want string
	}{
		{MixedRoleInstance, "mixed"},
		{PrefillRoleInstance, "prefill"},
		{DecodeRoleInstance, "decode"},
		{InvalidRoleInstance, "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("InstanceRole.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToInstanceRole(t *testing.T) {
	tests := []struct {
		input    string
		wantRole InstanceRole
		wantErr  bool
	}{
		{"mixed", MixedRoleInstance, false},
		{"prefill", PrefillRoleInstance, false},
		{"decode", DecodeRoleInstance, false},
		{"invalid_role", InvalidRoleInstance, true},
		{"", InvalidRoleInstance, true},
		{"MIXED", InvalidRoleInstance, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			role, err := ToInstanceRole(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToInstanceRole() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if role != tt.wantRole {
				t.Errorf("ToInstanceRole() = %v, want %v", role, tt.wantRole)
			}
		})
	}
}

func TestBuildInstanceAddress(t *testing.T) {
	tests := []struct {
		ip     string
		port   string
		expect string
	}{
		{"192.168.1.1", "8080", "192.168.1.1:8080"},
		{"::1", "8080", "[::1]:8080"},
		{"localhost", "8080", "localhost:8080"},
		{"0.0.0.0", "8000", "0.0.0.0:8000"},
		{"127.0.0.1", "9000", "127.0.0.1:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			got := BuildInstanceAddress(tt.ip, tt.port)
			if got != tt.expect {
				t.Errorf("BuildInstanceAddress(%v, %v) = %v, want %v", tt.ip, tt.port, got, tt.expect)
			}
		})
	}
}

// TestBuildInstanceAddress_DpRank pins the @<rank> suffix behavior.
// A non-DP worker registers with dpRank=0 (the default int). Appending "@0"
// produces a malformed URL like "http://172.17.0.2:8081@0/v1/chat/completions"
// which net/url parses as userinfo="172.17.0.2:8081", host="0" →
// "dial tcp: lookup 0: no such host". The @<rank> suffix must only be appended
// for actual DP ranks > 0; rank 0 (non-DP) yields a clean host:port.
// DP rank-0 still gets @0 in the snapshot path (instance_manager.go
// fmt.Sprintf("%s@%d", snap.insUrl, rank)), so this does not break DP.
func TestBuildInstanceAddress_DpRank(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		port   string
		dpRank []int
		expect string
	}{
		{"non-DP rank 0 no suffix", "172.17.0.2", "8081", []int{0}, "172.17.0.2:8081"},
		{"DP rank 1 gets suffix", "172.17.0.2", "8081", []int{1}, "172.17.0.2:8081@1"},
		{"DP rank 3 gets suffix", "172.17.0.2", "8081", []int{3}, "172.17.0.2:8081@3"},
		{"no dpRank arg no suffix", "172.17.0.2", "8081", nil, "172.17.0.2:8081"},
		{"negative rank no suffix", "172.17.0.2", "8081", []int{-1}, "172.17.0.2:8081"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildInstanceAddress(tt.ip, tt.port, tt.dpRank...)
			if got != tt.expect {
				t.Errorf("BuildInstanceAddress(%v, %v, %v) = %v, want %v",
					tt.ip, tt.port, tt.dpRank, got, tt.expect)
			}
		})
	}
}
