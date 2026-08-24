/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package gs

import "strings"

// containsInt64 reports whether v is present in s.
func containsInt64(s []int64, v int64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removeInt64 returns a new slice with all occurrences of v removed.
func removeInt64(s []int64, v int64) []int64 {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// headerVal returns the value for key in a headers map, case-insensitively.
// Returns "" if absent. Used to extract x-session-id / x-agent-id from ScheduleRequestMsg.Headers.
func headerVal(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	lk := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lk {
			return v
		}
	}
	return ""
}
