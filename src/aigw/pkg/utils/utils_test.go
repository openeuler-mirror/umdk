/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in non linux platform
 * Create: 2025-6-17
 */

// Package utils
package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	zkServerDivide = 12
	ten            = 10
	oneHundred     = 100
)

// TestCheckFile test check file
func TestCheckFile(t *testing.T) {
	// 1.test file exist
	fileName := "/noTestFile"
	isFileExist := FileExist(fileName)
	if isFileExist {
		t.Errorf("expected false")
	}

	// 2.test create a file
	fileName = "/tmp/file_test.log"
	os.Remove(fileName)
	isFileExist = FileExist(fileName)
	if isFileExist {
		t.Errorf("expected false")
	}
	file, err := os.Create(fileName)
	if err != nil {
		t.Errorf("%v", err)
	}
	file.Close()
	isFileExist = FileExist(fileName)
	if !isFileExist {
		t.Errorf("expected true")
	}
	os.Remove(fileName)
}

func TestValidateIPPort(t *testing.T) {
	testCases := []struct {
		name     string
		ipPort   string
		expected error
	}{
		{
			name:     "valid ip and port",
			ipPort:   "192.168.1.1:8080",
			expected: nil,
		},
		{
			name:     "invalid ip",
			ipPort:   "256.255.255.255:8080",
			expected: errors.New("the ip 256.255.255.255 is invalid"),
		},
		{
			name:     "invalid port",
			ipPort:   "192.168.1.1:65536",
			expected: errors.New("the port 65536 is bigger than 65535"),
		},
		{
			name:     "invalid port range",
			ipPort:   "192.168.1.1:0",
			expected: errors.New("the port 0 is less than 1024"),
		},
		{
			name:     "invalid ipPort format",
			ipPort:   "192.168.1.1",
			expected: errors.New("address 192.168.1.1: missing port in address"),
		},
		{
			name:     "invalid unspecified ip",
			ipPort:   "0.0.0.0:8080",
			expected: errors.New("the ip 0.0.0.0 is Unspecified"),
		},
		{
			name:     "valid ipv6 ip and port",
			ipPort:   "[::1]:2181",
			expected: nil,
		},
		{
			name:     "invalid ipv6 ip and port",
			ipPort:   "::1:2181",
			expected: errors.New("address ::1:2181: too many colons in address"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIPPort(tc.ipPort)
			if err != nil && tc.expected == nil {
				t.Errorf("expected nil, got %v", err)
				return
			}
			if err == nil && tc.expected != nil {
				t.Errorf("expected %v, got nil", tc.expected)
				return
			}
			if err != nil && tc.expected != nil && err.Error() != tc.expected.Error() {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}
}

// TestValidateFilePath tests the validateFilePath function
func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Valid existing file",
			input:    "/usr/bin/ls",
			expected: "/usr/bin/ls",
			wantErr:  false,
		},
		{
			name:     "Non-existent file",
			input:    "nonexistent_file.txt",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Directory instead of file",
			input:    "/home",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "file path exceeds the limit",
			input:    strings.Repeat("s", maxPathLen+1),
			expected: "",
			wantErr:  true,
		},
		{
			name:     "abs failed",
			input:    "no root dir",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateFilePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("validateFilePath() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestIsValidPathChar tests the isValidPathChar function.
func TestIsValidPathChar(t *testing.T) {
	testCases := []struct {
		char  rune
		valid bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'-', true},
		{'_', true},
		{'.', true},
		{'/', false},
		{' ', false},
		{'!', false},
	}

	for _, tc := range testCases {
		result := isValidPathChar(tc.char)
		if result != tc.valid {
			t.Errorf("isValidPathChar(%q) = %v, want %v", tc.char, result, tc.valid)
		}
	}
}

// TestValidateZooKeeperPath tests the ValidateZooKeeperPath function.
func TestValidateZooKeeperPath(t *testing.T) {
	testCases := []struct {
		path  string
		valid bool
	}{
		{"/", true},
		{"/valid/path", true},
		{"/valid-path", true},
		{"/valid_path", true},
		{"/valid.path", true},
		{"", false},
		{"invalid", false},
		{"//", false},
		{"/invalid//path", false},
		{"/invalid/./path", false},
		{"/invalid/../path", false},
		{"/invalid*path", false},
		{"/invalid path", false},
	}

	for _, tc := range testCases {
		err := ValidateZooKeeperPath(tc.path)
		if tc.valid && err != nil {
			t.Errorf("ValidateZooKeeperPath(%q) = %v, want nil", tc.path, err)
		} else if !tc.valid && err == nil {
			t.Errorf("ValidateZooKeeperPath(%q) = nil, want error", tc.path)
		} else if !tc.valid && err != nil {
			t.Logf("ValidateZooKeeperPath(%q) = %v, as expected", tc.path, err)
		}
	}
}

func TestValidateZooKeeperServers(t *testing.T) {
	tests := []struct {
		input    string
		expected error
	}{
		{
			input:    "",
			expected: fmt.Errorf("zookeeper servers should not be empty"),
		},
		{
			input:    "127.0.0.1:2181,1.2.3.4:2181",
			expected: nil,
		},
		{
			input: "127.0.0.1:2181,1.2.3.4:2181,127.0.0.1:2181",
			expected: fmt.Errorf("each server must have a different name, " +
				"servers: '127.0.0.1:2181,1.2.3.4:2181,127.0.0.1:2181'"),
		},
		{
			input:    ",,",
			expected: fmt.Errorf("no server is specified in zookeeper servers ',,'"),
		},
		{
			input: "127.0.0.1:2181,1.2.3.4:2181,5.6.7.8:1",
			expected: fmt.Errorf("parsing zookeeper servers '127.0.0.1:2181,1.2.3.4:2181,5.6.7.8:1' " +
				"failed with error: the port 1 is less than 1024"),
		},
		{
			input:    "127.0.0.1:2181,1.2.3.4:2181,5.6.7.8:2181",
			expected: nil,
		},
		// Test case: Server string exceeds max length
		{
			input:    strings.Repeat("127.0.0.1:2181,", zkServerMaxLen/zkServerDivide) + "127.0.0.1:2181",
			expected: fmt.Errorf("server length exceed %v", zkServerMaxLen),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test case %d", i+1), func(t *testing.T) {
			err := ValidateZooKeeperServers(test.input)
			if !reflect.DeepEqual(err, test.expected) {
				t.Errorf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

// TestIndexOfMaxFloat tests the IndexOfMaxFloat function
func TestIndexOfMaxFloat(t *testing.T) {
	const negative1, negative2, negative3 = -1.0, -2.0, -3.0
	testCases := []struct {
		name     string
		data     []float64
		expected int
	}{
		{
			name:     "empty slice",
			data:     []float64{},
			expected: -1,
		},
		{
			name:     "single element",
			data:     []float64{1.0},
			expected: 0,
		},
		{
			name:     "multiple elements with max at the end",
			data:     []float64{1.0, 2.0, 3.0},
			expected: 2,
		},
		{
			name:     "multiple elements with max at the beginning",
			data:     []float64{3.0, 2.0, 1.0},
			expected: 0,
		},
		{
			name:     "multiple elements with max in the middle",
			data:     []float64{1.0, 3.0, 2.0},
			expected: 1,
		},
		{
			name:     "all elements are the same",
			data:     []float64{1.0, 1.0, 1.0},
			expected: 0,
		},
		{
			name:     "negative numbers",
			data:     []float64{negative1, negative2, negative3},
			expected: 0,
		},
		{
			name:     "mixed positive and negative numbers",
			data:     []float64{negative1, 2.0, negative3},
			expected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IndexOfMaxFloat(tc.data)
			if result != tc.expected {
				t.Errorf("IndexOfMaxFloat(%v) = %d, want %d", tc.data, result, tc.expected)
			}
		})
	}
}

// TestCheckStringLength tests the CheckStringLength function
func TestCheckStringLength(t *testing.T) {
	testCases := []struct {
		input    string
		expected error
	}{
		{"", errors.New("the length of string is 0")},
		{"a", nil},
		{"a" + "b", nil},
		{fmt.Sprintf("%256s", "a"), nil},
		{fmt.Sprintf("%257s", "a"), errors.New("string is too long")},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			err := CheckStringLength(tc.input)
			if !reflect.DeepEqual(err, tc.expected) {
				t.Errorf("CheckStringLength(%q) = %v, want %v", tc.input, err, tc.expected)
			}
		})
	}
}

// TestCheckIP tests the CheckIP function
func TestCheckIP(t *testing.T) {
	testCases := []struct {
		input    string
		expected error
	}{
		{"", errors.New("the ip  is invalid")},
		{"192.168.1.1", nil},
		{"256.256.256.256", errors.New("the ip 256.256.256.256 is invalid")},
		{"::1", nil},
		{"0.0.0.0", errors.New("the ip 0.0.0.0 is Unspecified")},
		{"::", errors.New("the ip :: is Unspecified")},
		{"123.45.67.89", nil},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", nil},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:733g",
			errors.New("the ip 2001:0db8:85a3:0000:0000:8a2e:0370:733g is invalid")},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			err := CheckIP(tc.input)
			if !reflect.DeepEqual(err, tc.expected) {
				t.Errorf("CheckIP(%q) = %v, want %v", tc.input, err, tc.expected)
			}
		})
	}
}

// TestCheckPort tests the CheckPort function
func TestCheckPort(t *testing.T) {
	testCases := []struct {
		input    string
		expected error
	}{
		{"", errors.New("the port  is invalid")},
		{"1023", fmt.Errorf("the port %v is less than %v", "1023", portMin)},
		{"1024", nil},
		{"65535", nil},
		{"65536", fmt.Errorf("the port %v is bigger than %v", "65536", portMax)},
		{"abc", errors.New("the port abc is invalid")},
		{"-1", fmt.Errorf("the port %v is less than %v", "-1", portMin)},
		{"12345", nil},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			err := CheckPort(tc.input)
			if !reflect.DeepEqual(err, tc.expected) {
				t.Errorf("CheckPort(%q) = %v, want %v", tc.input, err, tc.expected)
			}
		})
	}
}

func TestGetExpBackoffDelay(t *testing.T) {
	tests := []struct {
		name     string
		i        uint32
		maxDelay int
		want     time.Duration
	}{
		{
			name:     "i=0, maxDelay=5",
			i:        0,
			maxDelay: 5,
			want:     1 * time.Second,
		},
		{
			name:     "i=10, maxDelay=2000",
			i:        10,
			maxDelay: 2000,
			want:     1024 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetExpBackoffDelay(tt.i, tt.maxDelay)
			if got != tt.want {
				t.Errorf("GetExpBackoffDelay(%d, %d) = %v, want %v", tt.i, tt.maxDelay, got, tt.want)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{"normal case", []byte{1, 2, 3}, []byte{0, 0, 0}},
		{"empty slice", []byte{}, []byte{}},
		{"single element", []byte{5}, []byte{0}},
		{"multiple elements", []byte{0x10, 0x20, 0x30}, []byte{0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := make([]byte, len(tt.input))
			copy(b, tt.input)
			ZeroBytes(b)
			if !bytes.Equal(b, tt.want) {
				t.Errorf("ZeroBytes(%v) = %v, want %v", tt.input, b, tt.want)
			}
		})
	}
}

func TestSleepWithContext(t *testing.T) {
	t.Run("Normal completion", func(t *testing.T) {
		ctx := context.Background()
		duration := ten * time.Millisecond

		done := make(chan struct{})
		go func() {
			SleepWithContext(ctx, duration)
			close(done)
		}()

		select {
		case <-done:

		case <-time.After(duration + oneHundred*time.Millisecond):
			t.Fatal("SleepWithContext did not return after duration")
		}
	})

	t.Run("Cancellation during sleep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		duration := time.Second

		done := make(chan struct{})
		go func() {
			SleepWithContext(ctx, duration)
			close(done)
		}()

		time.Sleep(ten * time.Millisecond)
		cancel()

		select {
		case <-done:

		case <-time.After(oneHundred * time.Millisecond):
			t.Fatal("SleepWithContext did not return after cancellation")
		}
	})

	t.Run("Already cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan struct{})
		go func() {
			SleepWithContext(ctx, time.Second)
			close(done)
		}()

		select {
		case <-done:

		case <-time.After(oneHundred * time.Millisecond):
			t.Fatal("SleepWithContext did not return immediately for already cancelled context")
		}
	})
}

func TestValidateMonitorAlarmPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{
			name:     "empty path",
			input:    "",
			expected: fmt.Errorf("empty monitor alarmPath"),
		},
		{
			name:     "path too long",
			input:    strings.Repeat("a", maxPathLen+1),
			expected: fmt.Errorf("alarmPath length exceed %v", maxPathLen),
		},
		{
			name:     "path does not start with /",
			input:    "invalid/path",
			expected: fmt.Errorf("path must start with '/'"),
		},
		{
			name:     "valid path",
			input:    "/valid/path",
			expected: nil,
		},
		{
			name:     "path with exactly max length",
			input:    fmt.Sprintf("/%s", strings.Repeat("a", maxPathLen-1)),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMonitorAlarmPath(tt.input)
			if err == nil && tt.expected != nil {
				t.Errorf("expected error %v, got nil", tt.expected)
			} else if err != nil && tt.expected == nil {
				t.Errorf("expected no error, got %v", err)
			} else if err != nil && tt.expected != nil && err.Error() != tt.expected.Error() {
				t.Errorf("expected error %v, got %v", tt.expected, err)
			}
		})
	}
}

func TestValidateMonitorEnvFields(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{
			name:     "envFields too long",
			input:    strings.Repeat("a", monitorEnvFieldsMaxLen+1),
			expected: fmt.Errorf("envFields length exceed %v", monitorEnvFieldsMaxLen),
		},
		{
			name:     "envFields valid",
			input:    "valid_env_fields",
			expected: nil,
		},
		{
			name:     "envFields with exactly max length",
			input:    strings.Repeat("a", monitorEnvFieldsMaxLen),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMonitorEnvFields(tt.input)
			if err == nil && tt.expected != nil {
				t.Errorf("expected error %v, got nil", tt.expected)
			} else if err != nil && tt.expected == nil {
				t.Errorf("expected no error, got %v", err)
			} else if err != nil && tt.expected != nil && err.Error() != tt.expected.Error() {
				t.Errorf("expected error %v, got %v", tt.expected, err)
			}
		})
	}
}

// TestCheckUnixDomainSocket tests the CheckUnixDomainSocket function
func TestCheckUnixDomainSocket(t *testing.T) {
	// Test case: file does not exist
	nonExistentPath := "/path/to/nonexistent"
	err := CheckUnixDomainSocket(nonExistentPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")

	// Test case: file is not a socket
	const fileMode = 0600
	regularFilePath := "testfile"
	file, err := os.Create(regularFilePath)
	assert.NoError(t, err)
	err = file.Chmod(fileMode)
	assert.NoError(t, err)
	defer os.Remove(regularFilePath)
	err = file.Close()
	assert.NoError(t, err)

	err = CheckUnixDomainSocket(regularFilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is not a socket file")

	// Test case: file is a socket (this requires creating a socket file, which is platform-dependent)
	socketFilePath := "testsocket"
	listener, err := net.Listen("unix", socketFilePath)
	assert.NoError(t, err)
	defer os.Remove(socketFilePath)
	defer listener.Close()

	err = CheckUnixDomainSocket(socketFilePath)
	assert.NoError(t, err)
}
