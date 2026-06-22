/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: zk manager test
 * Create: 2025-07-29
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-zookeeper/zk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"huawei.com/aigw/internal/base"
)

const (
	zkTestChSize         = 128
	zkTestDelay          = 50 // ms
	zkTestReconnectDelay = 20 // ms
	zkTest2thArg         = 2
	zkTestTime2          = 2
)

// MockZkConn is a mock struct for *zk.Conn
type MockZkConn struct {
	mock.Mock

	connectEventCh  chan zk.Event
	inferInsEventCh chan zk.Event
}

func newMockZkConn() *MockZkConn {
	m := new(MockZkConn)
	m.connectEventCh = make(chan zk.Event, zkTestChSize)
	m.inferInsEventCh = make(chan zk.Event, zkTestChSize)
	return m
}

func (m *MockZkConn) Connect(servers []string, sessionTimeout time.Duration, dialer zk.Dialer,
	opts ...ConnOption) (<-chan zk.Event, error) {
	args := m.Called(servers, sessionTimeout, dialer, opts)
	return args.Get(0).(chan zk.Event), args.Error(1)
}

// Create is a mock method for *zk.Conn.Create
func (m *MockZkConn) Create(path string, data []byte, flags int32, acl []zk.ACL) (string, error) {
	args := m.Called(path, data, flags, acl)
	return args.String(0), args.Error(1)
}

// Exists is a mock method for *zk.Conn.Exists
func (m *MockZkConn) Exists(path string) (bool, *zk.Stat, error) {
	args := m.Called(path)
	return args.Bool(0), args.Get(1).(*zk.Stat), args.Error(zkTest2thArg)
}

// Delete is a mock method for *zk.Conn.Delete
func (m *MockZkConn) Delete(path string, version int32) error {
	args := m.Called(path, version)
	return args.Error(0)
}

// Children is a mock method for *zk.Conn.Children
func (m *MockZkConn) Children(path string) ([]string, *zk.Stat, error) {
	args := m.Called(path)
	return args.Get(0).([]string), args.Get(1).(*zk.Stat), args.Error(zkTest2thArg)
}

// ChildrenW is a mock method for *zk.Conn.ChildrenW
func (m *MockZkConn) ChildrenW(path string) ([]string, <-chan zk.Event, error) {
	args := m.Called(path)
	return args.Get(0).([]string), args.Get(1).(chan zk.Event), args.Error(zkTest2thArg)
}

// Get is a mock method for *zk.Conn.Get
func (m *MockZkConn) Get(path string) ([]byte, *zk.Stat, error) {
	args := m.Called(path)
	return args.Get(0).([]byte), args.Get(1).(*zk.Stat), args.Error(zkTest2thArg)
}

// Close is a mock method for *zk.Conn.Close
func (m *MockZkConn) Close() {
	m.Called()
}

// AddAuth adds an authentication config to the connection.
func (m *MockZkConn) AddAuth(scheme string, auth []byte) error {
	args := m.Called(scheme, auth)
	return args.Error(0)
}

// TestZkManagerMainFlow tests the main functionalities of ZooKeeperManager
func TestZkManagerMainFlow(t *testing.T) {
	// Mock data
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		AclScheme:             "digest",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}
	ins1 := &inferInstanceInfo{
		Name:  "1",
		Model: "testModel",
		IP:    "127.0.0.1",
		Port:  "8888",
		Role:  "mixed",
	}

	zkMgr, err := NewZookeeperManager(config, eventCbs)
	assert.NoError(t, err)
	zkMgr.maxCreateRetry = 1

	mockConn := newMockZkConn()
	// connectWithTimeout success
	mockConn.On("Connect", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			mockConn.connectEventCh <- zk.Event{State: zk.StateHasSession}
		}).
		Return(mockConn.connectEventCh, nil)
	mockConn.On("AddAuth", mock.Anything, mock.Anything).Return(nil)
	// ensureBasePaths success
	mockConn.On("Exists", mock.Anything).Return(true, &zk.Stat{}, nil)
	mockConn.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)

	// watchInferenceInstances success
	mockConn.On("ChildrenW", mock.Anything).Return([]string{"1", "2"}, mockConn.inferInsEventCh, nil)
	// registerServiceNode success
	mockConn.On("Delete", mock.Anything, mock.Anything).Return(nil)

	// handleInstanceChanges success
	mockConn.On("Children", mock.Anything).Return([]string{"1"}, &zk.Stat{}, nil).Once()
	data, err := json.Marshal(ins1)
	assert.NoError(t, err)
	mockConn.On("Get", mock.Anything).Return(data, &zk.Stat{}, nil)

	// start zkManager successfully, discovery the initial inference instances
	zkMgr.conn = mockConn
	err = zkMgr.Start()
	assert.NoError(t, err)
	time.Sleep(zkTestDelay * time.Millisecond)

	// delete the all inference instances
	mockConn.On("Children", mock.Anything).Return([]string{}, &zk.Stat{}, nil).Once()
	mockConn.inferInsEventCh <- zk.Event{Type: zk.EventNodeChildrenChanged}

	time.Sleep(zkTestDelay * time.Millisecond)
	mockConn.On("Close").Return()
	zkMgr.Stop()
}

// TestZkManagerException tests the exceptions
func TestZkManagerException(t *testing.T) {
	// Mock data
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}

	// Test case 0: test NewZookeeperManager
	_, e := NewZookeeperManager(nil, eventCbs)
	assert.Error(t, e)
	invalidCb := EventCallback{}
	_, e1 := NewZookeeperManager(config, invalidCb)
	assert.Error(t, e1)

	// Mock objects
	zkMgr, err := NewZookeeperManager(config, eventCbs, WithServiceAddress("127.0.0.1:8888"))
	assert.NoError(t, err)
	mockConn := newMockZkConn()
	zkMgr.conn = mockConn
	zkMgr.maxCreateRetry = 1

	// Test case 1: test connectWithTimeout
	var connectEventCh chan zk.Event
	mockConn.On("Connect", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(connectEventCh, fmt.Errorf("connection timeout")).Once()
	err = zkMgr.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection timeout")

	// event chan is nil
	mockConn.On("Connect", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(connectEventCh, nil).Once()
	mockConn.On("Close").Return().Once()
	err = zkMgr.Start()
	assert.Error(t, err)

	// AddAuth failed
	mockConn.On("Connect", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mockConn.connectEventCh, nil).Once()
	mockConn.On("AddAuth", mock.Anything, mock.Anything).Return(nil).Once()
	mockConn.On("Close").Return().Once()
	err = zkMgr.Start()
	assert.Error(t, err)

	// context done
	mockConn.On("Connect", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mockConn.connectEventCh, nil).Once()
	mockConn.On("Close").Return().Once()
	zkMgr.cancelFunc()
	err = zkMgr.Start()
	assert.Error(t, err)

	// Test case 2: test ensureBasePath
	mockConn.On("Exists", mock.Anything).
		Return(false, &zk.Stat{}, fmt.Errorf("err")).Once()
	err = zkMgr.ensureBasePath("/mep")
	assert.Error(t, err)

	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, nil).Once()
	mockConn.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return("", fmt.Errorf("error")).Once()
	err = zkMgr.ensureBasePath("/mep")
	assert.Error(t, err)

	// Test case 3: test ensureServiceNode
	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, fmt.Errorf("err")).Once()
	err = zkMgr.ensureServiceNode(false)
	assert.Error(t, err)

	mockConn.On("Exists", mock.Anything).Return(true, &zk.Stat{}, nil).Once()
	mockConn.On("Delete", mock.Anything, mock.Anything).Return(fmt.Errorf("err"))
	err = zkMgr.ensureServiceNode(true)
	assert.Error(t, err)

	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, nil).Once()
	mockConn.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return("", fmt.Errorf("error"))
	err = zkMgr.ensureServiceNode(true)
	assert.Error(t, err)

	// Test case 4: test ensureInferenceInstancePath
	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, fmt.Errorf("err")).Once()
	err = zkMgr.ensureInferenceInstancePath()
	assert.Error(t, err)

	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, nil).Times(1)
	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, fmt.Errorf("err")).Times(zkTestTime2)
	err = zkMgr.ensureInferenceInstancePath()
	assert.Error(t, err)
}

// TestZkOpts tests opts
func TestZkOpts(t *testing.T) {
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}

	zkMgr, err := NewZookeeperManager(config, eventCbs)
	assert.NoError(t, err)
	zkMgr.maxCreateRetry = 1
	if err != nil {
		t.Error("read file err")
	}
	config.EnableTls = false
	f := WithTlsAndDialer(config, nil)
	err = f(zkMgr)
	assert.NoError(t, err)

	config.EnableTls = true
	f = WithTlsAndDialer(config, nil)
	err = f(zkMgr)
	assert.Error(t, err)

	// invalid for handler
	zkMgr.handleNewInstance(nil, "", nil, nil)
	zkMgr.handleDeletedInstance(nil, "", nil, nil, nil)
}

func TestMonitorConnection(t *testing.T) {
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}

	zkMgr, err := NewZookeeperManager(config, eventCbs)
	assert.NoError(t, err)
	ch := make(chan zk.Event, zkTestChSize)
	zkMgr.eventChan = ch

	zkMgr.wg.Add(1)
	go zkMgr.monitorConnection()

	ch <- zk.Event{State: zk.StateDisconnected}
	ch <- zk.Event{State: zk.StateConnected}
	ch <- zk.Event{State: zk.StateExpired}
	ch <- zk.Event{State: zk.StateConnecting}
	ch <- zk.Event{State: zk.StateHasSession}

	const delayTime = 10 * time.Millisecond
	time.Sleep(delayTime)

	zkMgr.cancelFunc()
	zkMgr.wg.Wait()

	assert.Equal(t, 0, len(ch))
}

func TestMonitorServiceNode(t *testing.T) {
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}

	zkMgr, err := NewZookeeperManager(config, eventCbs)
	assert.NoError(t, err)

	mockConn := newMockZkConn()
	zkMgr.conn = mockConn
	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, nil)
	mockConn.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)

	zkMgr.monitorServicePathDelay = time.Millisecond
	zkMgr.wg.Add(1)
	go zkMgr.monitorServiceNode()

	const delayTime = 10 * time.Millisecond
	time.Sleep(delayTime)

	zkMgr.cancelFunc()
	zkMgr.wg.Wait()
}

func TestGetInferenceInstancePathWatch(t *testing.T) {
	config := &base.ZookeeperConfig{
		Address:               "zk_address",
		SessionTimeout:        1,
		ConnectTimeout:        1,
		InferenceInstancePath: "/inference/instances",
		ScheduleServicePath:   "/schedule/services",
	}
	eventCbs := EventCallback{
		RegInferInsCb:   func(in *base.RegisterInstanceIn) error { return nil },
		UnRegInferInsCb: func(in *base.UnregisterInstanceIn) error { return nil },
	}

	zkMgr, err := NewZookeeperManager(config, eventCbs)
	assert.NoError(t, err)

	mockConn := newMockZkConn()
	zkMgr.conn = mockConn

	// failed to ensureInferenceInstancePath
	mockConn.On("Exists", mock.Anything).Return(false, &zk.Stat{}, fmt.Errorf("err")).Once()
	ch, e := zkMgr.getInferenceInstancePathWatch()
	assert.Error(t, e)
	assert.Nil(t, ch)

	// failed to ChildrenW
	mockConn.On("Exists", mock.Anything).Return(true, &zk.Stat{}, nil).Once()
	mockConn.On("ChildrenW", mock.Anything).Return([]string{"1", "2"},
		mockConn.inferInsEventCh, fmt.Errorf("err")).Once()
	ch, e = zkMgr.getInferenceInstancePathWatch()
	assert.Error(t, e)
	assert.Nil(t, ch)

	// watch is nil
	var nilCh chan zk.Event
	mockConn.On("Exists", mock.Anything).Return(true, &zk.Stat{}, nil).Once()
	mockConn.On("ChildrenW", mock.Anything).Return([]string{"1", "2"}, nilCh, nil).Once()
	ch, e = zkMgr.getInferenceInstancePathWatch()
	assert.Error(t, e)
	assert.Nil(t, ch)
}
