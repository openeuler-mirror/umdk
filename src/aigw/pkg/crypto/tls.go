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
	"crypto/x509"
	"net"
	"os"
	"time"

	"github.com/go-zookeeper/zk"
)

var defTLSCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// GenerateTlsCfgFromFile Generate TlsCfg From File
func GenerateTlsCfgFromFile(caFile string, crtFile string, keyDER []byte, serverName string) (*tls.Config, error) {
	// load CA
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	// load crtFile and keyFile
	certDER, err := os.ReadFile(crtFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certDER, keyDER)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		ServerName:         serverName,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       defTLSCipherSuites,
	}, nil
}

// GenerateZKTlsDialer Generate ZK TlsDialer
func GenerateZKTlsDialer(tlsCfg *tls.Config) zk.Dialer {
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		tcpConn, err := net.DialTimeout(network, addr, timeout)
		if err != nil {
			return nil, err
		}
		return tls.Client(tcpConn, tlsCfg), nil
	}
}
