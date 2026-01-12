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
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"huawei.com/aigw/pkg/log"
)

const (
	numOfPartsInHex = 2
	aesNonceLength  = 12
)

// AesManager aes
type AesManager struct {
	aesKey []byte
	schema string
}

// NewAesManager New Aes Manager
func NewAesManager(key []byte, opts ...AesOption) *AesManager {
	// The integrity of the message is ensured by HMAC.
	m := &AesManager{
		aesKey: make([]byte, len(key)),
		schema: "default",
	}

	// The aesKey cannot be reset to zero because it is required for encrypt and decrypt
	copy(m.aesKey, key)

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// DecryptByteData AES-128-GCM Decrypt
func (am *AesManager) DecryptByteData(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= aesNonceLength {
		return nil, fmt.Errorf("[AES]ciphertext is too short")
	}

	nonce := ciphertext[:aesNonceLength]
	ciphertext = ciphertext[aesNonceLength:]

	block, err := aes.NewCipher(am.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptMepData Usage ":" connect salt value and ciphertext
func (am *AesManager) DecryptMepData(hexData []byte) ([]byte, error) {
	parts := strings.SplitN(string(hexData), ":", numOfPartsInHex)
	if len(parts) != numOfPartsInHex {
		return nil, fmt.Errorf("[AES]invalid format: missing ':'")
	}
	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("[AES]invalid nonce hex: %w", err)
	}
	cipherText, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("[AES]invalid cipher hex: %w", err)
	}
	if len(nonce) != aesNonceLength { // 12
		return nil, fmt.Errorf("[AES]nonce length must be 12 bytes")
	}

	block, err := aes.NewCipher(am.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, cipherText, nil)

}

// Decrypt  Unified entry for decryption
func (am *AesManager) Decrypt(ciphertext []byte) ([]byte, error) {
	var err error
	var plaintext []byte
	if am.schema == "mep" {
		log.Debug().Msgf("[AES]decrypt mep data")
		plaintext, err = am.DecryptMepData(ciphertext)
	} else if am.schema == "default" {
		log.Debug().Msgf("[AES]decrypt default data")
		plaintext, err = am.DecryptByteData(ciphertext)
	} else {
		err = fmt.Errorf("[AES] invalid security schema")
	}
	return plaintext, err
}

// WithAesDecrypt Decryption Middleware
func (am *AesManager) WithAesDecrypt(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.EnableAes() {
			log.Debug().Msgf("[AES]no aes")
			next.ServeHTTP(w, r)
			return
		}
		// Read encrypted data
		ciphertext, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "[AES]Error reading body", http.StatusBadRequest)
			return
		}
		var plaintext []byte

		plaintext, err = am.Decrypt(ciphertext)
		if err != nil {
			log.Error().Msgf("[AES]Decryption failed")
			http.Error(w, "[AES]Decryption failed", http.StatusBadRequest)
			return
		}

		// Replace the request body with plaintext.
		// The decrypted plaintext obtained here needs to be passed on for use in subsequent processes.
		r.Body = io.NopCloser(bytes.NewBuffer(plaintext))
		r.ContentLength = int64(len(plaintext))
		log.Debug().Msgf("[AES]Decryption successful")
		next.ServeHTTP(w, r)
	})
}

// EnableAes use aes or not
func (am *AesManager) EnableAes() bool {
	return len(am.aesKey) != 0
}

// AesOption is the option for aes
type AesOption func(am *AesManager)

// WithAesSchema add schema
func WithAesSchema(schema string) AesOption {
	return func(am *AesManager) {
		am.schema = schema
	}
}
