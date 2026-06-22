/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Manager provides management functions for globalScheduler.
 * Create: 2025-5-13
 */

// Package crypto is the crypto middleware for httpServer.
package crypto

import (
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"
)

// TestGenerateTlsCfgFromFile Test Generate TlsCfg From File
func TestGenerateTlsCfgFromFile(t *testing.T) {
	// Prepare the test certificate file path
	caFile := "../../test/tls_file/ca-cert.pem"
	crtFile := "../../test/tls_file/client-cert.pem"
	keyFile := "../../test/tls_file/client-key.pem"
	serverName := "localhost"
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Error("read file err")
	}
	// Test under normal conditions
	t.Run("normal", func(t *testing.T) {

		cfg, err := GenerateTlsCfgFromFile(caFile, crtFile, key, serverName)
		if err != nil {
			t.Fatalf("TLS configuration generation failed: %v", err)
		}

		// Check if the configuration is correct.
		if len(cfg.Certificates) != 1 {
			t.Error("The number of certificates is incorrect.")
		}
		if cfg.RootCAs == nil {
			t.Error("The root certificate pool was not loaded correctly.")
		}
		if cfg.ServerName != serverName {
			t.Errorf("The server name is incorrect, expected: %s，in fact: %s", serverName, cfg.ServerName)
		}
	})

	// Test certificate file does not exist.
	t.Run("certificate file does not exist", func(t *testing.T) {
		_, err := GenerateTlsCfgFromFile("nonexistent_ca.pem", crtFile, key, serverName)
		if err == nil {
			t.Error("Expected an error to be returned, but none was returned.")
		}
	})

	// Testing for incorrect key file format scenarios
	t.Run("The key file format is incorrect", func(t *testing.T) {
		_, err := GenerateTlsCfgFromFile(caFile, crtFile, nil, serverName)
		if err == nil {
			t.Error("Expected an error to be returned, but none was returned.")
		}
	})
}

// TestGenerateZKTlsDialer Test Generate ZKTls Dialer
func TestGenerateZKTlsDialer(t *testing.T) {
	// Prepare TLS config
	caFile := "../../test/tls_file/ca-cert.pem"
	crtFile := "../../test/tls_file/client-cert.pem"
	keyFile := "../../test/tls_file/client-key.pem"
	serverName := "localhost"
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Error("read file err")
	}
	cfg, err := GenerateTlsCfgFromFile(caFile, crtFile, key, serverName)
	if err != nil {
		t.Fatalf("TLS configuration generation failed: %v", err)
	}

	// Creating a ZooKeeper Dialer
	dialer := GenerateZKTlsDialer(cfg)

	// Test whether the dialer is correctly using the TLS configuration.
	t.Run("Normal dialing", func(t *testing.T) {
		// Simulate a TCP connection
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("Failed to create the listener: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Simulate the TLS handshake.
			tlsConn := tls.Server(conn, cfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			defer tlsConn.Close()
		}()

		// Connect using a dialer
		conn, err := dialer("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("connect fail: %v", err)
		}
		defer conn.Close()

		// Check if it is a TLS connection
		if _, ok := conn.(*tls.Conn); !ok {
			t.Error("Expected a TLS connection, but it was not actually established.")
		}
	})

	// Error Handling for Test Dialer in Case of Connection Failure
	t.Run("connect fail", func(t *testing.T) {
		_, err := dialer("tcp", "invalid_address:1234", time.Second)
		if err == nil {
			t.Error("Expected an error to be returned, but none was returned.")
		}
	})
}
