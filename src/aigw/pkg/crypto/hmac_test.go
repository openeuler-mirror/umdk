/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Manager provides management functions for globalScheduler.
 * Create: 2025-5-13
 */

// Package crypto is the crypto middleware for httpServer.
package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const oneMin = 60 * 1000

func TestEnableHmac(t *testing.T) {
	tests := []struct {
		name   string
		key    []byte
		expect bool
	}{
		{"Empty Key", nil, false},
		{"Valid Key", []byte("secret"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm := NewHmacManager(tt.key)
			if got := hm.EnableHmac(); got != tt.expect {
				t.Errorf("EnableHmac() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestValidateTimestamp(t *testing.T) {
	hm := NewHmacManager([]byte("secret"))
	now := time.Now().UTC().UnixMilli()

	tests := []struct {
		name    string
		ts      string
		wantErr bool
	}{
		{"Valid Timestamp", strconv.FormatInt(now, NumberSystem), false},
		{"Future Timestamp", strconv.FormatInt(now+128*oneMin, NumberSystem), true},
		{"Past Timestamp", strconv.FormatInt(now-128*oneMin, NumberSystem), true},
		{"Invalid Format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hm.validateTimestamp(tt.ts)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDefaultSign(t *testing.T) {
	key := []byte("secret")
	hm := NewHmacManager(key)
	now := time.Now().UTC().UnixMilli()
	validTimestamp := strconv.FormatInt(now, NumberSystem)
	payload := "test payload"

	// Calculate valid signature
	validSig := calculateHMAC(key, []byte(validTimestamp+payload))

	tests := []struct {
		name       string
		headers    map[string]string
		body       string
		wantValid  bool
		wantErrMsg string
	}{
		{"Valid Request",
			map[string]string{"X-Timestamp": validTimestamp, "X-Signature": hex.EncodeToString(validSig)},
			payload, true, ""},
		{"Missing Timestamp",
			map[string]string{"X-Signature": "dummy"}, "", false,
			"Missing auth headers"},
		{"Missing Signature",
			map[string]string{"X-Timestamp": validTimestamp}, "", false,
			"Missing auth headers"},
		{"Invalid Timestamp",
			map[string]string{"X-Timestamp": "123", "X-Signature": "dummy"}, "", false,
			"[HMAC]Verify timestamp failed"},
		{"Invalid Signature",
			map[string]string{"X-Timestamp": validTimestamp, "X-Signature": "dummy"}, payload,
			false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(tt.body))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			valid, msg := hm.validateDefaultSign(req)
			if valid != tt.wantValid {
				t.Errorf("validateDefaultSign() valid = %v, want %v", valid, tt.wantValid)
			}
			if tt.wantErrMsg != "" && !bytes.Contains([]byte(msg), []byte(tt.wantErrMsg)) {
				t.Errorf("validateDefaultSign() msg = %s, want contains %s", msg, tt.wantErrMsg)
			}
		})
	}
}

func TestValidateMepSign(t *testing.T) {
	key := []byte("secret")
	hm := NewHmacManager(key)
	hm.schema = "mep"
	now := time.Now().UTC().UnixMilli()
	validTimestamp := strconv.FormatInt(now, NumberSystem)
	payload := "test payload"
	method := "POST"
	path := "/api/test"
	params := "param=value"
	appID := "testApp"

	// Calculate valid signature
	originStr := method + "&" + path + "&" + params + "&" + payload + "&appid=" +
		appID + "&timestamp=" + validTimestamp
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write([]byte(originStr))
	if err != nil {
		t.Errorf("write error")
	}
	validSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name       string
		authHeader string
		body       string
		wantValid  bool
		wantErrMsg string
	}{
		{"Valid Request",
			`CLOUDSOA-HMAC-SHA256 appid="testApp",timestamp="` +
				validTimestamp + `",signature="` + validSig + `"`,
			payload, true, ""},
		{"Missing Authorization", "", "", false, "[HMAC]missing auth in head"},
		{"Invalid Format", "Invalid Header", "",
			false, "[HMAC]auth missing parts"},
		{"Missing Timestamp",
			`CLOUDSOA-HMAC-SHA256 appid="testApp",signature="dummy"`, "",
			false, "[HMAC]auth missing parts"},
		{"Invalid Timestamp",
			`CLOUDSOA-HMAC-SHA256 appid="testApp",timestamp="123",signature="dummy"`,
			"", false, "[HMAC]Verify timestamp failed"},
		{"Invalid Signature",
			`CLOUDSOA-HMAC-SHA256 appid="testApp",timestamp="` + validTimestamp + `",signature="dummy"`,
			payload, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(method, path+"?"+params, bytes.NewBufferString(tt.body))
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			valid, msg := hm.validateMepSign(req)
			if valid != tt.wantValid {
				t.Errorf("validateMepSign() valid = %v, want %v", valid, tt.wantValid)
			}
			if tt.wantErrMsg != "" && !bytes.Contains([]byte(msg), []byte(tt.wantErrMsg)) {
				t.Errorf("validateMepSign() msg = %s, want contains %s", msg, tt.wantErrMsg)
			}
		})
	}
}

func TestAddHmacSign(t *testing.T) {
	key := []byte("secret")
	payload := "test payload"

	tests := []struct {
		name    string
		schema  string
		method  string
		path    string
		params  string
		wantErr bool
	}{
		{"Default Schema", "default", "POST", "/", "", false},
		{"Mep Schema", "mep", "GET", "/api", "param=value", false},
		{"Invalid Schema", "invalid", "POST", "/", "", true},
		{"Disabled HMAC", "", "POST", "/", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm := NewHmacManager(key, WithHmacSchema(tt.schema))
			req := httptest.NewRequest(tt.method, tt.path+"?"+tt.params, nil)

			err := hm.AddHmacSign(req, payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddHmacSign() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			// Verify headers were set correctly
			switch tt.schema {
			case "default":
				if req.Header.Get("X-Timestamp") == "" {
					t.Errorf("X-Timestamp header not set")
				}
				if req.Header.Get("X-Signature") == "" {
					t.Errorf("X-Signature header not set")
				}
			case "mep":
				auth := req.Header.Get("Authorization")
				if auth == "" {
					t.Errorf("Authorization header not set")
				}
				if !bytes.Contains([]byte(auth), []byte("timestamp=")) {
					t.Errorf("Timestamp not found in auth header")
				}
			default:
				t.Error("invalid schema")
			}
		})
	}
}

func TestWithHMAC(t *testing.T) {
	key := []byte("secret")
	now := time.Now().UTC().UnixMilli()
	timestamp := strconv.FormatInt(now, NumberSystem)
	payload := "test payload"

	// Calculate valid signature for default schema
	defaultSig := calculateHMAC(key, []byte(timestamp+payload))

	tests := []struct {
		name       string
		schema     string
		reqHeaders map[string]string
		body       string
		wantStatus int
		wantErrMsg string
	}{
		{"Default Valid", "default",
			map[string]string{
				"X-Timestamp": timestamp,
				"X-Signature": hex.EncodeToString(defaultSig),
			}, payload, http.StatusOK, ""},
		{"Default Invalid Sig", "default",
			map[string]string{
				"X-Timestamp": timestamp,
				"X-Signature": "invalid",
			}, payload, http.StatusUnauthorized, "Invalid signature"},

		{"Mep Invalid Sig", "mep",
			map[string]string{
				"Authorization": `CLOUDSOA-HMAC-SHA256 appid="aigw",timestamp="` + timestamp + `",signature="invalid"`,
			}, payload, http.StatusUnauthorized, "Invalid signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm := NewHmacManager(key, WithHmacSchema(tt.schema))
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(tt.body))
			for k, v := range tt.reqHeaders {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			hm.WithHMAC(handler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("WithHMAC() status = %v, want %v", rr.Code, tt.wantStatus)
			}

			if tt.wantErrMsg != "" && !bytes.Contains(rr.Body.Bytes(), []byte(tt.wantErrMsg)) {
				t.Errorf("WithHMAC() response = %s, want contains %s", rr.Body.String(), tt.wantErrMsg)
			}
		})
	}
}

// Helper function to calculate HMAC
func calculateHMAC(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(data)
	if err != nil {
		return nil
	}
	return mac.Sum(nil)
}
