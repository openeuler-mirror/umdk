/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: implementation of unix domain socket
 * Create: 2025-8-12
 */

// Package sock
package sock

import (
	"fmt"
	"net"
	"time"

	"huawei.com/aigw/pkg/log"
)

const (
	defaultConnectTimeout = 5 * time.Second
	defaultReadTimeout    = 5 * time.Second

	maxReadLen = 4096
)

// UnixSock is wrapper for unix domain socket
type UnixSock struct {
	conn     net.Conn
	sockPath string

	connectTimeout time.Duration
	readTimeout    time.Duration
}

// NewUnixSock create unix sock and connect this sock
func NewUnixSock(socketPath string, opts ...UnixSockOption) (*UnixSock, error) {
	s := &UnixSock{
		sockPath: socketPath,

		connectTimeout: defaultConnectTimeout,
		readTimeout:    defaultReadTimeout,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Connect to the Unix Domain Socket
	conn, err := net.DialTimeout("unix", socketPath, s.connectTimeout)
	if err != nil {
		log.Error().Msgf("failed to execute net dial, sock %v, err: %v", s.sockPath, err)
		return nil, err
	}

	// Set read deadline to prevent hanging
	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		log.Error().Msgf("failed to SetReadDeadline, sock %v, err: %v", s.sockPath, err)
		if e := conn.Close(); e != nil {
			log.Warn().Msgf("failed to close conn: %v, err: %v", s.sockPath, e)
		}
		return nil, err
	}

	s.conn = conn
	log.Info().Msgf("connect sock %v successfully", s.sockPath)
	return s, nil
}

// ReadData reads data from unix socket
func (s *UnixSock) ReadData() ([]byte, error) {
	if s.conn == nil {
		return nil, fmt.Errorf("conn is unavailable")
	}

	// Read the data
	buf := make([]byte, maxReadLen)
	n, err := s.conn.Read(buf)
	if err != nil {
		log.Error().Msgf("failed to read from sock: %v, err: %v", s.sockPath, err)
		return nil, fmt.Errorf("failed to read from sock: %v, err: %v", s.sockPath, err)
	}
	if n <= 0 {
		log.Error().Msgf("read nothing from sock: %v", s.sockPath)
		return nil, fmt.Errorf("read nothing from sock: %v", s.sockPath)
	}
	if n >= maxReadLen {
		n = maxReadLen
	}

	return buf[:n], err
}

// Close closes the unix socket
func (s *UnixSock) Close() {
	if s.conn == nil {
		return
	}
	if err := s.conn.Close(); err != nil {
		log.Warn().Msgf("failed to close unix sock, sockPath %v", s.sockPath)
		return
	}

	s.conn = nil
	log.Info().Msgf("close sock %v successfully", s.sockPath)
}
