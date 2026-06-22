/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: chown implementation in non linux platform
 * Create: 2025-6-4
 */

package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"
)

const (
	defaultLogPath = "/var/log/routec_test"
	defaultLogFile = "/var/log/routec_test/test.log"
)

func checkFileCnt(t *testing.T, cnt int) {
	infos, err := os.ReadDir(defaultLogPath)
	require.NoError(t, err)
	require.Equal(t, cnt, len(infos))
}

func checkPerm(t *testing.T) {
	dirEntries, err := os.ReadDir(defaultLogPath)
	require.NoError(t, err)
	for _, d := range dirEntries {
		info, e := d.Info()
		if e != nil {
			continue
		}
		if strings.HasSuffix(info.Name(), ".gz") {
			require.Equal(t, info.Mode(), os.FileMode(0440))
		} else {
			require.Equal(t, info.Mode(), os.FileMode(0640))
		}
	}
}

func newWriter() *RotateWriter {
	w := &RotateWriter{
		Filename:   filepath.Join(defaultLogPath, "test.log"),
		MaxSize:    int64(1),
		MaxBackups: 2,
	}
	return w
}

// TestNewFile test new a log file
func TestNewFile(t *testing.T) {
	w := newWriter()
	err := w.openExistOrNewFile(megaByte + 1)
	require.NoError(t, err)
	stat, err := os.Stat(filepath.Join(defaultLogPath, "test.log"))
	require.NoError(t, err)
	require.Equal(t, stat.Mode(), os.FileMode(0640))
	checkPerm(t)
	os.RemoveAll(defaultLogPath)
}

// TestOpenExist test open exist log file
func TestOpenExist(t *testing.T) {
	w := newWriter()
	defer os.RemoveAll(defaultLogPath)
	w.Write([]byte("rooster"))
	w.Close()
	w.Write([]byte("rooster"))
	b, err := os.ReadFile(filepath.Join(defaultLogPath, "test.log"))
	require.NoError(t, err)
	require.Equal(t, string(b), "roosterrooster")
	checkPerm(t)
}

// TestWriteLog test write log
func TestWriteLog(t *testing.T) {
	w := newWriter()
	_, err := w.Write([]byte("rooster"))
	require.NoError(t, err)
	checkFileCnt(t, 1)
	b, err := os.ReadFile(filepath.Join(defaultLogPath, "test.log"))
	require.NoError(t, err)
	require.Equal(t, string(b), "rooster")
	checkPerm(t)
	os.RemoveAll(defaultLogPath)
}

// TestWriteTooLong test write too long log
func TestWriteTooLong(t *testing.T) {
	megaByte = 1
	w := newWriter()
	defer os.RemoveAll(defaultLogPath)
	_, err := w.Write([]byte("ro"))
	require.Equal(t, "write length 2 exceeds max size 1", err.Error())
}

// TestNoFile 测试不配置日志路径
func TestNoFile(t *testing.T) {
	defer os.RemoveAll(defaultLogPath)
	w := &RotateWriter{MaxSize: 3}
	_, err := w.Write([]byte("123"))
	require.Equal(t, "log file name is empty", err.Error())
}

// TestRotate 测试日志转储
func TestRotate(t *testing.T) {
	defer os.RemoveAll(defaultLogPath)
	megaByte = 5
	w := &RotateWriter{Filename: defaultLogFile, MaxSize: 1, MaxBackups: 3}
	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = w.Write([]byte("hi"))
	require.NoError(t, err)
	checkFileCnt(t, 2)
	b, err := os.ReadFile(defaultLogFile)
	require.NoError(t, err)
	require.Equal(t, string(b), "hi")
	checkPerm(t)
}

// TestMaxBackups 测试最大备份数
func TestMaxBackups(t *testing.T) {
	defer os.RemoveAll(defaultLogPath)
	megaByte = 5
	w := &RotateWriter{Filename: defaultLogFile, MaxSize: 1, MaxBackups: 5}
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := w.Write([]byte("hello"))
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	checkFileCnt(t, 6)
	_, err := w.Write([]byte("hi"))
	require.NoError(t, err)
	b, err := os.ReadFile(defaultLogFile)
	require.NoError(t, err)
	require.Equal(t, string(b), "hi")
	// 检查压缩文件权限
	checkPerm(t)
}

// TestException 测试异常值
func TestException(t *testing.T) {
	defer os.RemoveAll(defaultLogPath)
	megaByte = 1
	w := &RotateWriter{Filename: defaultLogFile, MaxSize: 0, MaxBackups: 0}
	require.Error(t, w.compress(defaultLogFile, defaultLogFile+".gz"))
	w.Write([]byte("hellohello"))
	time.Sleep(time.Millisecond)
	w.Write([]byte("hellohello"))
	time.Sleep(time.Millisecond)
	w.Write([]byte("hello"))
	checkFileCnt(t, 3)
	require.NoError(t, os.Chmod(defaultLogFile, 0400))
	w.close()
	_, err := w.Write([]byte("123"))
	require.NoError(t, err)
}

// TestCompress 测试压缩
func TestCompress(t *testing.T) {
	defer os.RemoveAll(defaultLogPath)
	megaByte = 1024 * 1024
	w := &RotateWriter{Filename: defaultLogFile, MaxSize: 1, MaxBackups: 5}
	w.Write([]byte(fmt.Sprintf("testtest")))
	p1 := gomonkey.ApplyFunc(os.OpenFile, func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return nil, fmt.Errorf("stub open file failed")
	})
	err := w.compress(defaultLogFile, defaultLogFile+".gz")
	require.Error(t, err)
	require.Equal(t, "failed to open log file: stub open file failed", err.Error())
	p1.Reset()

	_, err = w.Write([]byte(fmt.Sprintf("testtest")))
	require.NoError(t, err)
	p2 := gomonkey.ApplyFunc(os.Stat, func(name string) (os.FileInfo, error) {
		return nil, fmt.Errorf("stub stat failed")
	})
	require.Equal(t, "failed to stat log file: stub stat failed", w.compress(defaultLogFile, defaultLogFile+".gz").Error())
	p2.Reset()
}
