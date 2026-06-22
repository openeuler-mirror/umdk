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
		role    InstanceRole
		want    string
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