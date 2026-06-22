/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Hash key extraction for consistent hashing in AIGW.
 * Create: 2026-04-29
 */

// Package gs is the global scheduler for AIGW.
package gs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Session header names in priority order (highest priority first).
// These headers are checked for session affinity.
var sessionHeaderNames = []string{
	"x-session-id",      // Priority 1: Explicit session ID
	"x-user-id",         // Priority 2: User-based affinity
	"x-tenant-id",       // Priority 3: Tenant-based affinity
	"x-correlation-id",  // Priority 4: Correlation ID
	"x-request-id",      // Priority 5: Request ID
	"x-trace-id",        // Priority 6: Trace ID
}

// HashKey represents an extracted hash key with source information.
type HashKey struct {
	Source   string // Source of the key (header/body/request)
	Key      string // Key name
	Value    string // Key value
	Priority int    // Priority (lower is higher priority)
}

// String returns a formatted string representation of the hash key.
func (hk *HashKey) String() string {
	return fmt.Sprintf("%s:%s:%s", hk.Source, hk.Key, hk.Value)
}

// ExtractHashKey extracts a hash key from HTTP headers and request body.
// Priority order:
// 1. HTTP headers (x-session-id > x-user-id > ...)
// 2. Request body fields (session_params.session_id > user > session_id > user_id)
// 3. Fallback: request content hash
func ExtractHashKey(headers http.Header, body map[string]interface{}) string {
	// 1. Check HTTP headers in priority order
	for i, headerName := range sessionHeaderNames {
		// Check both lowercase and canonical forms
		value := headers.Get(headerName)
		if value == "" {
			// Try canonical form (e.g., "X-Session-Id")
			value = headers.Get(http.CanonicalHeaderKey(headerName))
		}
		if value != "" {
			hk := &HashKey{
				Source:   "header",
				Key:      headerName,
				Value:    value,
				Priority: i,
			}
			return hk.String()
		}
	}

	// 2. Check request body fields
	if body != nil {
		// session_params.session_id (nested field)
		if sessionParams, ok := body["session_params"].(map[string]interface{}); ok {
			if sessionID, ok := sessionParams["session_id"].(string); ok && sessionID != "" {
				return fmt.Sprintf("body:session_params.session_id:%s", sessionID)
			}
		}

		// user (OpenAI chat completion format)
		if user, ok := body["user"].(string); ok && user != "" {
			return fmt.Sprintf("body:user:%s", user)
		}

		// session_id (legacy format)
		if sessionID, ok := body["session_id"].(string); ok && sessionID != "" {
			return fmt.Sprintf("body:session_id:%s", sessionID)
		}

		// user_id (legacy format)
		if userID, ok := body["user_id"].(string); ok && userID != "" {
			return fmt.Sprintf("body:user_id:%s", userID)
		}

		// conversation_id (for conversation affinity)
		if convID, ok := body["conversation_id"].(string); ok && convID != "" {
			return fmt.Sprintf("body:conversation_id:%s", convID)
		}
	}

	// 3. Fallback: request content hash
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err == nil && len(bodyBytes) > 0 {
			hashValue := fnvHash64(string(bodyBytes))
			return fmt.Sprintf("request_hash:%016x", hashValue)
		}
	}

	// Final fallback: empty string (will be hashed to a value)
	return "fallback:empty"
}

// ExtractHashKeyFromBytes extracts hash key from raw JSON body bytes.
// This is a convenience function for when the body is already serialized.
func ExtractHashKeyFromBytes(headers http.Header, bodyBytes []byte) string {
	if len(bodyBytes) == 0 {
		return ExtractHashKey(headers, nil)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		// If parsing fails, use content hash
		hashValue := fnvHash64(string(bodyBytes))
		return fmt.Sprintf("content_hash:%016x", hashValue)
	}

	return ExtractHashKey(headers, body)
}

// extractHeaderValue extracts a header value case-insensitively.
func extractHeaderValue(headers http.Header, name string) string {
	// Try direct lookup
	value := headers.Get(name)
	if value != "" {
		return value
	}

	// Try lowercase
	value = headers.Get(strings.ToLower(name))
	if value != "" {
		return value
	}

	// Try canonical
	value = headers.Get(http.CanonicalHeaderKey(name))
	return value
}
