/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: definitions of types for AIGW core.
 * Create: 2026-03-10
 */

// Package base contains the global definitions for AIGW.
package base

import (
	"fmt"
	"net"
)

// InstanceRole is the role of instance
type InstanceRole int

// definition for InstanceRole
const (
	MixedRoleInstance InstanceRole = iota
	PrefillRoleInstance
	DecodeRoleInstance
	InvalidRoleInstance
)

var roleToString = map[InstanceRole]string{
	MixedRoleInstance:   "mixed",
	PrefillRoleInstance: "prefill",
	DecodeRoleInstance:  "decode",
}

var stringToRole = map[string]InstanceRole{
	"mixed":   MixedRoleInstance,
	"prefill": PrefillRoleInstance,
	"decode":  DecodeRoleInstance,
}

// String returns the description of instance role
func (r InstanceRole) String() string {
	if s, ok := roleToString[r]; ok {
		return s
	}
	return "invalid"
}

// ToInstanceRole converts string to instance role
func ToInstanceRole(s string) (InstanceRole, error) {
	if role, ok := stringToRole[s]; ok {
		return role, nil
	}
	return InvalidRoleInstance, fmt.Errorf("%s is not a valid instance role", s)
}

// BuildInstanceAddress builds the instance address with ip and port.
// If dpRank is provided (>= 0), appends @rank suffix for DP-aware routing.
func BuildInstanceAddress(ip, port string, dpRank ...int) string {
	ipaddr := ip
	if i := net.ParseIP(ip); i != nil {
		ipaddr = i.String()
	}
	addr := net.JoinHostPort(ipaddr, port)
	// If dpRank is provided and valid, append @rank suffix
	if len(dpRank) > 0 && dpRank[0] >= 0 {
		addr = fmt.Sprintf("%s@%d", addr, dpRank[0])
	}
	return addr
}
