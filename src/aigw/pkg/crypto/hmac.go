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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"huawei.com/aigw/pkg/log"
)

const (
	// TimeWindow Anti-replay attack time window, unit is ms, total is 5min
	TimeWindow = int64(5 * 60 * 1000)
	// BitSize the length of timestamp
	BitSize = 64
	// NumberSystem Use decimal notation
	NumberSystem   = 10
	aigwAppId      = "backend"
	partsOfMepAuth = 3
)

// HmacManager Hmac
type HmacManager struct {
	hmacKey []byte
	schema  string
}

// NewHmacManager New Hmac Manager
func NewHmacManager(key []byte, opts ...HmacOption) *HmacManager {
	m := &HmacManager{
		hmacKey: make([]byte, len(key)),
		schema:  "default",
	}

	// The hmacKey cannot be reset to zero because it is required for auth
	copy(m.hmacKey, key)

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func (hm *HmacManager) validateTimestamp(timestamp string) error {
	ts, err := strconv.ParseInt(timestamp, NumberSystem, BitSize)
	if err != nil {
		return errors.New("invalid timestamp format")
	}

	current := time.Now().UTC().UnixMilli()
	if ts > current || ts < current-TimeWindow {
		return errors.New("timestamp out of window")
	}
	return nil
}

func (hm *HmacManager) validateSignature(req *http.Request) (bool, string) {
	switch hm.schema {
	case "default":
		log.Debug().Msgf("validate default Signature")
		return hm.validateDefaultSign(req)
	case "mep":
		log.Debug().Msgf("validate mep Signature")
		return hm.validateMepSign(req)
	default:
		return false, "invalid security schema"

	}
}

func (hm *HmacManager) validateDefaultSign(req *http.Request) (bool, string) {
	// get headers
	timestamp := req.Header.Get("X-Timestamp")
	signature := req.Header.Get("X-Signature")
	if timestamp == "" || signature == "" {
		log.Error().Msgf("[HMAC]Missing auth headers")
		return false, "[HMAC]Missing auth headers"
	}

	// Verify timestamp
	if err := hm.validateTimestamp(timestamp); err != nil {
		log.Error().Msgf("[HMAC]Verify timestamp failed")
		return false, "[HMAC]Verify timestamp failed"
	}

	// Read and retain the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Error().Msgf("[HMAC]Error reading body")
		return false, "[HMAC]Error reading body"
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	mac := hmac.New(sha256.New, hm.hmacKey)
	_, err = mac.Write([]byte(timestamp))
	if err != nil {
		return false, ""
	}
	_, err = mac.Write(body)
	if err != nil {
		return false, ""
	}
	expected := mac.Sum(nil)

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false, ""
	}

	return hmac.Equal(sig, expected), ""
}

func (hm *HmacManager) validateMepSign(req *http.Request) (bool, string) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		log.Error().Msgf("[HMAC]missing auth in head")
		return false, "[HMAC]missing auth in head"
	}
	parts := strings.Split(auth, ",")
	if len(parts) != partsOfMepAuth {
		log.Error().Msgf("[HMAC]auth missing parts")
		return false, "[HMAC]auth missing parts"
	}
	authDict := make(map[string]string)
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", numOfPartsInHex)
		if len(kv) != numOfPartsInHex {
			log.Error().Msgf("[HMAC]the auth header is invalid")
			return false, "[HMAC]the auth header is invalid"
		}
		authDict[kv[0]] = strings.Trim(kv[1], `"`)
	}

	// Verify timestamp
	timestamp, exists := authDict["timestamp"]
	if !exists {
		log.Error().Msgf("[HMAC]the auth header missing field")
		return false, "[HMAC]the auth header missing field"
	}
	if err := hm.validateTimestamp(timestamp); err != nil {
		log.Error().Msgf("[HMAC]Verify timestamp failed")
		return false, "[HMAC]Verify timestamp failed"
	}
	appId, exists := authDict["CLOUDSOA-HMAC-SHA256 appid"]
	if !exists {
		log.Error().Msgf("[HMAC]the auth header is valid")
		return false, "[HMAC]the auth header is valid"
	}
	sign, exists := authDict["signature"]
	if !exists {
		log.Error().Msgf("[HMAC]missing auth header")
		return false, "[HMAC]missing auth header"
	}

	// Read and retain the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Error().Msgf("[HMAC]Error reading body")
		return false, "[HMAC]Error reading body"
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	var mepInfo = map[string]string{
		"timestamp": timestamp,
		"payload":   string(body),
		"method":    req.Method,
		"path":      req.URL.Path,
		"params":    req.URL.RawQuery,
		"appId":     appId,
	}
	expected, err := hm.createMepSign(mepInfo)
	if err != nil {
		return false, err.Error()
	}

	return expected == sign, ""
}

// WithHMAC HMAC middleware
func (hm *HmacManager) WithHMAC(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hm.EnableHmac() {
			log.Debug().Msgf("[HMAC]no hmac")
			next.ServeHTTP(w, r)
			return
		}
		// Verify signature
		ok, msg := hm.validateSignature(r)
		if !ok {
			log.Error().Msgf("[HMAC]Verify signature failed.%v", msg)
			http.Error(w, "[HMAC]Invalid signature."+msg, http.StatusUnauthorized)
			return
		}
		log.Debug().Msgf("[HMAC]Certification approved")

		next.ServeHTTP(w, r)
	})
}

// AddHmacSign Create Hmac Sign
func (hm *HmacManager) AddHmacSign(req *http.Request, payload string) error {
	if !hm.EnableHmac() {
		return fmt.Errorf("hmacKey is not enable")
	}
	timestamp := strconv.FormatInt(time.Now().UTC().UnixMilli(), NumberSystem)
	switch hm.schema {
	case "default":
		{
			sign, err := hm.createDefaultSign(timestamp, payload)
			if err != nil {
				return err
			}
			req.Header.Set("X-Timestamp", timestamp)
			req.Header.Set("X-Signature", sign)
			return nil
		}
	case "mep":
		{
			var mepInfo = map[string]string{
				"timestamp": timestamp,
				"payload":   payload,
				"method":    req.Method,
				"path":      req.URL.Path,
				"params":    req.URL.RawQuery,
				"appId":     aigwAppId,
			}
			sign, err := hm.createMepSign(mepInfo)
			if err != nil {
				return err
			}
			authorization := "CLOUDSOA-HMAC-SHA256 appid=" + aigwAppId + ",timestamp=" + timestamp +
				",signature=\"" + sign + "\""
			req.Header.Set("Authorization", authorization)
			return nil
		}
	default:
		return fmt.Errorf("invalid security schema")
	}
}

func (hm *HmacManager) createDefaultSign(timestamp string, payload string) (string, error) {
	mac := hmac.New(sha256.New, hm.hmacKey)
	_, err := mac.Write([]byte(timestamp))
	if err != nil {
		return "", err
	}
	_, err = mac.Write([]byte(payload))
	if err != nil {
		return "", err
	}
	signature := hex.EncodeToString(mac.Sum(nil))

	return signature, nil
}

func (hm *HmacManager) createMepSign(mepInfo map[string]string) (string, error) {
	originStr := mepInfo["method"] + "&" +
		mepInfo["path"] + "&" +
		mepInfo["params"] + "&" +
		mepInfo["payload"] + "&appid=" +
		mepInfo["appId"] + "&timestamp=" +
		mepInfo["timestamp"]

	log.Debug().Msgf("[HMAC] mep original str: %v", originStr)
	mac := hmac.New(sha256.New, hm.hmacKey)
	_, err := mac.Write([]byte(originStr))
	if err != nil {
		return "", err
	}
	signStr := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signStr, nil
}

// EnableHmac use hmac or not
func (hm *HmacManager) EnableHmac() bool {
	return len(hm.hmacKey) != 0
}

// HmacOption is the option for hmac
type HmacOption func(hm *HmacManager)

// WithHmacSchema add schema
func WithHmacSchema(schema string) HmacOption {
	return func(hm *HmacManager) {
		hm.schema = schema
	}
}
