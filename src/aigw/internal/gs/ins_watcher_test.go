/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: inference instance management.
 * Create: 2025-05-13
 */

// Package gs is the global scheduler for gateway.
package gs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"huawei.com/aigw/pkg/crypto"
)

const testInterval = 100

func TestConnectSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	hmacMgr := crypto.NewHmacManager(nil)
	aesMgr := crypto.NewAesManager(nil)
	ins := &instance{
		insUrl:  ts.Listener.Addr().String(),
		msgChan: make(chan string),
		ctx:     context.Background(),
		insMgr: &InstanceManager{
			hmacMgr: hmacMgr,
			aesMgr:  aesMgr,
		},
	}
	watcher := newSseWatcher(ins)

	if err := watcher.connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if watcher.resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, watcher.resp.StatusCode)
	}
}

func TestConnectFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	hmacMgr := crypto.NewHmacManager(nil)
	aesMgr := crypto.NewAesManager(nil)
	ins := &instance{
		insUrl:  ts.Listener.Addr().String(),
		msgChan: make(chan string),
		ctx:     context.Background(),
		insMgr: &InstanceManager{
			hmacMgr: hmacMgr,
			aesMgr:  aesMgr,
		},
	}
	watcher := newSseWatcher(ins)

	if err := watcher.connect(); err == nil {
		t.Error("Expected connect to fail, but it succeeded")
	}
}

func TestConnectWithRetry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	hmacMgr := crypto.NewHmacManager(nil)
	aesMgr := crypto.NewAesManager(nil)

	// 创建一个自定义的RoundTripper来控制连接行为
	retryCount := 0
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if retryCount == 0 {
				retryCount++
				return nil, fmt.Errorf("connection refused")
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}

	// 创建一个自定义的http.Client，使用自定义的Transport
	client := &http.Client{
		Transport: transport,
	}
	ins := &instance{
		insUrl:  ts.Listener.Addr().String(),
		msgChan: make(chan string),
		ctx:     context.Background(),
		insMgr: &InstanceManager{
			hmacMgr: hmacMgr,
			aesMgr:  aesMgr,
		},
	}

	watcher := newSseWatcher(ins)
	watcher.client = client

	if err := watcher.connectWithRetry(); err != nil {
		t.Errorf("ConnectWithRetry failed: %v", err)
	}

	// 验证是否成功连接
	if watcher.resp == nil {
		t.Error("Expected response to be non-nil after successful retry")
	}
	if watcher.resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, watcher.resp.StatusCode)
	}
}

// SSE handler：负责把事件源源不断写给客户端
func sseHandler(w http.ResponseWriter, r *http.Request) {
	// SSE 规范头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 模拟每 100ms 推送一条数据
	ctx := r.Context()
	tick := time.NewTicker(testInterval * time.Millisecond)
	defer tick.Stop()

	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			fmt.Fprintf(w, "data\n")
			flusher.Flush()
		}
	}
}
func TestCheckConnAndRetry(t *testing.T) {
	// 1. 创建 httptest server
	mux := http.NewServeMux()
	mux.HandleFunc("/subscribe-event", sseHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	testWg := new(sync.WaitGroup)
	msgChan := make(chan string, 1)
	// 创建测试用的 sseWatcher 实例
	ctx, cancel := context.WithCancel(context.Background())
	ins := &instance{
		insUrl:  ts.URL,
		msgChan: msgChan,
		ctx:     ctx,
		insMgr: &InstanceManager{
			hmacMgr: crypto.NewHmacManager(nil),
			aesMgr:  crypto.NewAesManager(nil),
		},
	}
	watcher := newSseWatcher(ins)
	watcher.targetUrl = ts.URL + "/subscribe-event"
	// 测试 1: 正常连接
	t.Run("Test normal connection", func(t *testing.T) {
		// 连接服务端
		err := watcher.connect()
		testWg.Add(1)
		go watcher.run(testWg)
		if err != nil {
			t.Errorf("except no error")
		}

		// 检查连接是否健康
		if !watcher.isHealth() {
			t.Errorf("except health")
		}

		// 读取消息
		select {
		case msg := <-msgChan:
			if msg != "data" {
				t.Errorf("except get data, but get %v", msg)
			}
		case <-time.After(time.Second):
			t.Error("Timed out waiting for message")
		}
		cancel()
	})
}

func TestCheckConnAndRetry1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a sseWatcher instance
	tempIns, _ := newInstance("test", 0, "test", make(chan *ControlMessage, chanBufferSize), newInstanceManager())
	w := &sseWatcher{
		ins:        tempIns,
		insCtx:     ctx,
		resp:       &http.Response{Body: io.NopCloser(bytes.NewBufferString(""))},
		retryCount: 0,
		maxDelay:   defaultMaxDelay,
		enable:     true,
		hmacMgr:    crypto.NewHmacManager(nil),
		aesMgr:     crypto.NewAesManager(nil),
	}

	// Test case: Scanner.Scan() returns true
	w.scanner = bufio.NewScanner(bytes.NewBufferString("test message\n"))
	err := w.checkConnAndRetry()
	assert.NoError(t, err)

	// Test case: Scanner.Scan() returns false, connection is enabled
	w.scanner = bufio.NewScanner(bytes.NewBufferString(""))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test message\n"))
	}))
	defer server.Close()
	w.targetUrl = server.URL
	w.client = &http.Client{}
	err = w.checkConnAndRetry()
	assert.NoError(t, err)

	// Test case: Scanner.Scan() returns false, connection is disabled, retry fails
	w.scanner = bufio.NewScanner(bytes.NewBufferString(""))
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	w.targetUrl = server.URL
	w.client = &http.Client{}
	err = w.checkConnAndRetry()
	assert.Error(t, err)

	// Test case: Scanner.Scan() returns false, connection is disabled, retry succeeds
	w.scanner = bufio.NewScanner(bytes.NewBufferString(""))
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test message\n"))
	}))
	defer server.Close()
	w.targetUrl = server.URL
	w.client = &http.Client{}
	err = w.checkConnAndRetry()
	assert.NoError(t, err)

	// Test case: Context is canceled
	cancel()
	err = w.checkConnAndRetry()
	assert.Equal(t, err, nil)
}
