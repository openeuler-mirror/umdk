/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in non linux platform
 * Create: 2025-6-17
 */

// Package utils
package utils

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	numberOfSplitIp        = 2
	portMax                = 65535
	portMin                = 1024
	maxInputStringLen      = 256
	zkServerMaxLen         = 1024
	maxPathLen             = 4096
	defaultBaseDelay       = 2.0
	monitorEnvFieldsMaxLen = 256
	// MaxMessageLength Max Message Length
	MaxMessageLength  = 128 * 1024
	maxDelayThreshold = 32

	maxOpenFd = 65535
)

// FileExist check file exist
func FileExist(fileName string) bool {
	info, err := os.Stat(fileName)
	if err != nil {
		if os.IsExist(err) {
			return !info.IsDir()
		}
		return false
	}
	return !info.IsDir()
}

// ValidateIPPort checks if the input string is a valid IP:port combination
// Returns false for 0.0.0.0 IP and port outside 1024-65535 range
// Notice: ipv6 and port should be this style, e.g. "[::1]:80"
func ValidateIPPort(ipPort string) error {
	host, port, err := net.SplitHostPort(ipPort)
	if err != nil {
		return err
	}

	// ip should not be 0.0.0.0
	if err = CheckIP(host); err != nil {
		return err
	}

	if err = CheckPort(port); err != nil {
		return err
	}

	return nil
}

// ValidateZooKeeperServers validates the zookeeper server with format like "127.0.0.1:2181,192.168.1.10:2181"
func ValidateZooKeeperServers(zkServer string) error {
	if len(zkServer) == 0 {
		return fmt.Errorf("zookeeper servers should not be empty")
	}

	if len(zkServer) > zkServerMaxLen {
		return fmt.Errorf("server length exceed %v", zkServerMaxLen)
	}

	servers := strings.TrimSpace(zkServer)
	tmp := strings.Split(servers, ",")
	srvMap := make(map[string]int, len(tmp))
	for _, s := range tmp {
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		if _, existed := srvMap[s]; !existed {
			srvMap[s] = 0
		} else {
			return fmt.Errorf("each server must have a different name, servers: '%v'", servers)
		}
	}

	// should contain at least one non-empty string
	if len(srvMap) == 0 {
		return fmt.Errorf("no server is specified in zookeeper servers '%v'", servers)
	}

	for s := range srvMap {
		if err := ValidateIPPort(s); err != nil {
			return fmt.Errorf("parsing zookeeper servers '%v' failed with error: %v", servers, err)
		}
	}

	return nil
}

// ValidateFilePath checks and normalizes file path
func ValidateFilePath(inputPath string) (string, error) {
	if len(inputPath) > maxPathLen {
		return "", fmt.Errorf("path length exceed %v", maxPathLen)
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		return "", fmt.Errorf("path conversion failed: %v", err)
	}

	// Check file existence
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %s", absPath)
		}
		return "", fmt.Errorf("file stat error: %v", err)
	}

	// Check if it's a regular file
	if fileInfo.IsDir() {
		return "", fmt.Errorf("not a file: %s", absPath)
	}

	return absPath, nil
}

// isValidPathChar checks if character is allowed in ZooKeeper path
func isValidPathChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.'
}

// ValidateZooKeeperPath checks if a path conforms to ZooKeeper naming rules
// Rules:
// 1. Must start with forward slash '/'
// 2. Cannot contain empty node names (consecutive slashes)
// 3. Cannot contain relative path indicators (. or ..)
// 4. Only allows alphanumeric, hyphen, underscore and dot in node names
func ValidateZooKeeperPath(inputPath string) error {
	path := strings.TrimSpace(inputPath)
	if len(path) == 0 {
		return errors.New("empty zookeeper path")
	}
	if len(path) > maxPathLen {
		return fmt.Errorf("path length exceed %v", maxPathLen)
	}

	// Must start with forward slash
	if path[0] != '/' {
		return errors.New("path must start with '/'")
	}

	// Special case: root path
	if path == "/" {
		return nil
	}

	nodes := strings.Split(path, "/")[1:] // Skip first empty element

	for _, node := range nodes {
		if len(node) == 0 {
			return errors.New("empty node name between slashes")
		}

		if node == "." || node == ".." {
			return errors.New("relative path indicators (. or ..) not allowed")
		}

		for _, c := range node {
			if !isValidPathChar(c) {
				return fmt.Errorf("invalid character '%c' in path", c)
			}
		}
	}

	return nil
}

// ValidateMonitorAlarmPath checks if a path conforms to Monitor alarmPath naming rules
// Rules:
// 1. Must start with forward slash '/'
// 2. Maximum length is 4096, Cannot be empty
func ValidateMonitorAlarmPath(alarmPath string) error {
	if len(alarmPath) == 0 {
		return fmt.Errorf("empty monitor alarmPath")
	}
	if len(alarmPath) > maxPathLen {
		return fmt.Errorf("alarmPath length exceed %v", maxPathLen)
	}
	if !strings.HasPrefix(alarmPath, "/") {
		return fmt.Errorf("path must start with '/'")
	}
	return nil
}

// ValidateMonitorEnvFields checks the length of environment variables on the mep platform
func ValidateMonitorEnvFields(envFields string) error {
	if len(envFields) > monitorEnvFieldsMaxLen {
		return fmt.Errorf("envFields length exceed %v", monitorEnvFieldsMaxLen)
	}
	return nil
}

// IndexOfMaxFloat select the max index
func IndexOfMaxFloat(data []float64) int {
	if len(data) == 0 {
		return -1
	}

	maxIndex := 0
	maxValue := data[0]

	for i := 1; i < len(data); i++ {
		if data[i] > maxValue {
			maxValue = data[i]
			maxIndex = i
		}
	}

	return maxIndex
}

// CheckStringLength check string length should less than 128
func CheckStringLength(s string) error {
	if len(s) > maxInputStringLen {
		return fmt.Errorf("string is too long")
	}
	if len(s) == 0 {
		return fmt.Errorf("the length of string is 0")
	}
	return nil
}

// CheckIP check string is IP or nor,exclude zero
func CheckIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("the ip %v is invalid", ipStr)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("the ip %v is Unspecified", ipStr)
	}

	return nil
}

// CheckPort check port is in 1024-65535
func CheckPort(s string) error {
	port, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("the port %v is invalid", s)
	}
	if port < portMin {
		return fmt.Errorf("the port %v is less than %v", s, portMin)
	}

	if port > portMax {
		return fmt.Errorf("the port %v is bigger than %v", s, portMax)
	}
	return nil
}

// GetExpBackoffDelay Get ExpBackoff Delay
func GetExpBackoffDelay(i uint32, maxDelay int) time.Duration {
	if i > maxDelayThreshold {
		return time.Duration(maxDelay) * time.Second
	}

	t := math.Round(math.Pow(defaultBaseDelay, float64(i)))
	delay := time.Duration(t) * time.Second
	if delay > time.Duration(maxDelay)*time.Second {
		delay = time.Duration(maxDelay) * time.Second
	}
	return delay
}

// ZeroBytes zero bytes
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SleepWithContext sleep with context
func SleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		{
		}
	case <-ctx.Done():
		{
		} // 被取消
	}
}

// CheckUnixDomainSocket checks that the file is a socket file or not
func CheckUnixDomainSocket(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("check unix domain socket with err: %v", err)
	}

	if fileInfo.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%v is not a socket file", path)
	}
	return nil
}

// SetOpenFilesLimit sets the maximum number of files that can be opened by a process
func SetOpenFilesLimit() bool {
	var rlim syscall.Rlimit
	rlim.Cur = maxOpenFd
	rlim.Max = maxOpenFd

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		fmt.Printf("setrlimit failed: %v", err)
		return false
	}

	fmt.Printf("[Init] set max FD %v \n", maxOpenFd)
	return true
}
