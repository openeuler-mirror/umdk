/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: test for unix domain socket
 * Create: 2025-8-12
 */

// Package sock
package sock

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockNetConn struct {
	mock.Mock
}

func newMockNetConn() *mockNetConn {
	m := new(mockNetConn)
	return m
}

func (c *mockNetConn) Read(b []byte) (int, error) {
	args := c.Called(b)
	return args.Int(0), args.Error(1)
}

func (c *mockNetConn) Write(b []byte) (int, error) {
	args := c.Called(b)
	return args.Int(0), args.Error(1)
}

func (c *mockNetConn) Close() error {
	args := c.Called()
	return args.Error(0)
}

func (c *mockNetConn) LocalAddr() net.Addr {
	args := c.Called()
	return args.Get(0).(net.Addr)
}

func (c *mockNetConn) RemoteAddr() net.Addr {
	args := c.Called()
	return args.Get(0).(net.Addr)
}

func (c *mockNetConn) SetDeadline(t time.Time) error {
	args := c.Called(t)
	return args.Error(0)
}

func (c *mockNetConn) SetReadDeadline(t time.Time) error {
	args := c.Called(t)
	return args.Error(0)
}

func (c *mockNetConn) SetWriteDeadline(t time.Time) error {
	args := c.Called(t)
	return args.Error(0)
}

// GenerateRandomFileName generates a random file name with a specified prefix and length
func GenerateRandomFileName() (string, error) {
	const length = 32
	const prefix = "socktemp"

	// Generate random bytes
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Convert random bytes to a base64 string
	randomString := fmt.Sprintf("%x", randomBytes)

	// Ensure the length of the random string
	if len(randomString) > length {
		randomString = randomString[:length]
	}

	return fmt.Sprintf("%s_%s", prefix, randomString), nil
}

// TestNewUnixSock tests the NewUnixSock function
func TestNewUnixSock(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	// Create a Unix domain socket server for testing
	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer l.Close()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()
		wg.Done()
	}()

	// Test default options
	sock, err := NewUnixSock(socketPath)
	require.NoError(t, err)
	defer sock.Close()
	assert.Equal(t, socketPath, sock.sockPath)
	assert.Equal(t, defaultConnectTimeout, sock.connectTimeout)
	assert.Equal(t, defaultReadTimeout, sock.readTimeout)
	assert.NotNil(t, sock.conn)

	// Test custom options
	const customConnectTimeout = 10 * time.Second
	const customReadTimeout = 10 * time.Second
	sock, err = NewUnixSock(socketPath, WithConnectTimeout(customConnectTimeout), WithReadTimeout(customReadTimeout))
	require.NoError(t, err)
	defer sock.Close()
	assert.Equal(t, socketPath, sock.sockPath)
	assert.Equal(t, customConnectTimeout, sock.connectTimeout)
	assert.Equal(t, customReadTimeout, sock.readTimeout)
	assert.NotNil(t, sock.conn)

	wg.Wait()
}

// TestNewUnixSockSetReadDeadlineErr tests the NewUnixSock function with setReadDeadline err
func TestNewUnixSockSetReadDeadlineErr(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	m := newMockNetConn()
	dialTimeoutMock1 := gomonkey.ApplyFunc(net.DialTimeout,
		func(network, address string, timeout time.Duration) (net.Conn, error) {
			return m, nil
		})
	defer dialTimeoutMock1.Reset()

	// Test SetReadDeadline failed
	m.On("SetReadDeadline", mock.Anything).Return(fmt.Errorf("failed to set deadline")).Once()
	m.On("Close").Return(nil).Once()
	sock, err := NewUnixSock(socketPath)
	assert.Error(t, err)
	assert.Equal(t, "failed to set deadline", err.Error())
	assert.Nil(t, sock)
}

// TestReadData tests the ReadData method
func TestReadData(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	// Create a Unix domain socket server for testing
	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer l.Close()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		// Send some data to the client
		_, err = conn.Write([]byte("Hello, World!"))
		require.NoError(t, err)

		wg.Done()
	}()

	// Create a UnixSock instance
	sock, err := NewUnixSock(socketPath)
	require.NoError(t, err)
	defer sock.Close()

	// Read data from the socket
	data, err := sock.ReadData()
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello, World!"), data)

	wg.Wait()
}

// TestReadDataWithErr tests the ReadData method with error
func TestReadDataWithErr(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	m := newMockNetConn()
	dialTimeoutMock2 := gomonkey.ApplyFunc(net.DialTimeout,
		func(network, address string, timeout time.Duration) (net.Conn, error) {
			return m, nil
		})
	defer dialTimeoutMock2.Reset()

	// Create a UnixSock instance
	m.On("SetReadDeadline", mock.Anything).Return(nil).Once()
	sock, err := NewUnixSock(socketPath)
	require.NoError(t, err)
	defer sock.Close()

	// Read data error
	m.On("Read", mock.Anything).Return(0, fmt.Errorf("failed to read")).Once()
	data, err := sock.ReadData()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
	assert.Nil(t, data)

	// Read nothing
	m.On("Read", mock.Anything).Return(0, nil).Once()
	data, err = sock.ReadData()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read nothing from sock")
	assert.Nil(t, data)

	// Read data with length exceeds the max
	m.On("Read", mock.Anything).Return(maxReadLen+int(1), nil).Once()
	data, err = sock.ReadData()
	assert.NoError(t, err)
	assert.Equal(t, maxReadLen, len(data))

	m.On("Close").Return(nil).Once()
}

// TestClose tests the Close method
func TestClose(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	// Create a Unix domain socket server for testing
	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer l.Close()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()
		wg.Done()
	}()

	// Create a UnixSock instance
	sock, err := NewUnixSock(socketPath)
	require.NoError(t, err)

	// Close the socket success
	sock.Close()

	// Ensure the connection is closed
	assert.Nil(t, sock.conn)

	// conn is nil
	sock.Close()

	wg.Wait()
}

// TestReadDataWithClosedSocket tests the ReadData method with a closed socket
func TestReadDataWithClosedSocket(t *testing.T) {
	socketPath, e := GenerateRandomFileName()
	assert.NoError(t, e)

	// Create a Unix domain socket server for testing
	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer l.Close()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()
		wg.Done()
	}()

	// Create a UnixSock instance
	sock, err := NewUnixSock(socketPath)
	require.NoError(t, err)

	// Close the socket
	sock.Close()

	// Read data from the closed socket
	data, err := sock.ReadData()
	require.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, "conn is unavailable", err.Error())

	wg.Wait()
}
