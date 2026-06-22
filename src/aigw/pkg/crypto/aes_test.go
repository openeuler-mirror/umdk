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
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var testKey = []byte("0123456789abcdef") // 16-byte AES key

// TestNewAesManager 测试AesManager的构造函数
func TestNewAesManager(t *testing.T) {
	key := make([]byte, 16) // AES-128密钥长度
	manager := NewAesManager(key, WithAesSchema("mep"))
	assert.Equal(t, "mep", manager.schema)
	assert.Equal(t, len(key), len(manager.aesKey))
}

// TestDecryptByteData 测试DecryptByteData函数
func TestDecryptByteData(t *testing.T) {
	key := make([]byte, 16)
	manager := NewAesManager(key, WithAesSchema("default"))

	// 准备测试数据
	plaintext := []byte("test plaintext")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encryptedData := append(nonce, ciphertext...)

	// 测试正确解密
	decrypted, err := manager.DecryptByteData(encryptedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 测试密文过短
	_, err = manager.DecryptByteData([]byte{})
	assert.Error(t, err)
}

// TestDecryptMepData 测试DecryptMepData函数
func TestDecryptMepData(t *testing.T) {
	key := make([]byte, 16)
	manager := NewAesManager(key, WithAesSchema("mep"))

	// 准备测试数据
	plaintext := []byte("test plaintext")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	nonceHex := hex.EncodeToString(nonce)
	ciphertextHex := hex.EncodeToString(ciphertext)
	encryptedData := []byte(fmt.Sprintf("%s:%s", nonceHex, ciphertextHex))

	// 测试正确解密
	decrypted, err := manager.DecryptMepData(encryptedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 测试格式错误
	_, err = manager.DecryptMepData([]byte("invalid"))
	assert.Error(t, err)

	// 测试Hex解码错误
	_, err = manager.DecryptMepData([]byte("invalid:hex"))
	assert.Error(t, err)
}

// TestDecrypt 测试Decrypt函数
func TestDecrypt(t *testing.T) {
	key := make([]byte, 16)
	managerDefault := NewAesManager(key, WithAesSchema("default"))
	managerMep := NewAesManager(key, WithAesSchema("mep"))

	// 测试默认schema
	plaintext := []byte("test plaintext")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encryptedData := append(nonce, ciphertext...)

	decrypted, err := managerDefault.Decrypt(encryptedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 测试mep schema
	nonceHex := hex.EncodeToString(nonce)
	ciphertextHex := hex.EncodeToString(ciphertext)
	encryptedMepData := []byte(fmt.Sprintf("%s:%s", nonceHex, ciphertextHex))

	decryptedMep, err := managerMep.Decrypt(encryptedMepData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedMep)

	// 测试无效schema
	managerInvalid := NewAesManager(key, WithAesSchema("invalid"))
	_, err = managerInvalid.Decrypt([]byte{})
	assert.Error(t, err)
}

// TestWithAesDecrypt 测试WithAesDecrypt中间件
func TestWithAesDecrypt(t *testing.T) {
	key := make([]byte, 16)
	manager := NewAesManager(key, WithAesSchema("default"))

	// 准备测试数据
	plaintext := []byte("test plaintext")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encryptedData := append(nonce, ciphertext...)

	// 创建测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "[AES]Error reading body", http.StatusBadRequest)
			return
		}
		assert.Equal(t, plaintext, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// 创建请求
	req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer(encryptedData))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()

	// 调用中间件
	manager.WithAesDecrypt(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "[AES]Error reading body", http.StatusBadRequest)
			return
		}
		assert.Equal(t, plaintext, body)
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)

}

// TestEnableAes 测试EnableAes函数
func TestEnableAes(t *testing.T) {
	managerEnabled := NewAesManager([]byte("key"), WithAesSchema("default"))
	assert.True(t, managerEnabled.EnableAes())

	managerDisabled := NewAesManager([]byte{}, WithAesSchema("default"))
	assert.False(t, managerDisabled.EnableAes())
}
