/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: zk manager provides zookeeper management for AIGW.
 * Create: 2025-07-21
 */

// Package zk provides zookeeper management for AIGW.
package zk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-zookeeper/zk"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
	"huawei.com/aigw/pkg/utils"
)

const (
	defaultMaxDelay       = 16 // Maximum delay, unit is second
	defaultMaxCreateRetry = 3  // Maximum retry count for creating znode

	watchInstancePathDelay  = 2 * time.Second
	monitorServicePathDelay = 5 * time.Second
	reconnectDelay          = 5 * time.Second

	defaultServiceAddress = "127.0.0.1:8888"

	defaultZkBufferSize = 10 * 1024 * 1024 // 10MB
)

type aclSchemeType int

const (
	aclSchemeDefault aclSchemeType = iota
	aclSchemeDigest
)

func toAclSchemeType(in string) aclSchemeType {
	switch in {
	case "digest":
		return aclSchemeDigest
	default:
		return aclSchemeDefault
	}
}

type inferInstanceInfo struct {
	Name    string `json:"name"`
	Model   string `json:"model"`
	IP      string `json:"instanceIp"`
	Port    string `json:"port"`
	Role    string `json:"role"`
	GroupID string `json:"groupID"`
}

// EventCallback provides the callbacks for zookeeper manager event
type EventCallback struct {
	RegInferInsCb   func(in *base.RegisterInstanceIn) error   // callback to register new inference instance
	UnRegInferInsCb func(in *base.UnregisterInstanceIn) error // callback to unregister inference instance
}

// ZooKeeperManager providers management of zookeeper connection
type ZooKeeperManager struct {
	config    *base.ZookeeperConfig
	conn      Connection // Active ZooKeeper connection
	eventChan <-chan zk.Event
	eventCbs  EventCallback

	ctx        context.Context    // Context for graceful shutdown
	cancelFunc context.CancelFunc // Function to cancel context
	wg         *sync.WaitGroup

	localInstances map[string]*inferInstanceInfo // local instance nodes

	tlsCfg *tls.Config
	dialer zk.Dialer

	maxDelay       int
	maxCreateRetry int

	watchInstancePathDelay  time.Duration
	monitorServicePathDelay time.Duration
	reconnectDelay          time.Duration

	serviceAddress string // address for other service

	aclScheme aclSchemeType

	user     string
	password []byte // The password cannot be reset to zero because it is required for authentication

	insPathLock sync.Mutex
}

// NewZookeeperManager creates a new manager instance with configuration
func NewZookeeperManager(config *base.ZookeeperConfig, eventCbs EventCallback,
	opts ...ZooKeeperOption) (*ZooKeeperManager, error) {
	if config == nil {
		log.Error().Msgf("config is nil")
		return nil, fmt.Errorf("config is nil")
	}
	if eventCbs.RegInferInsCb == nil || eventCbs.UnRegInferInsCb == nil {
		log.Error().Msgf("regInsCb or unRegInsCb is nil")
		return nil, fmt.Errorf("regInsCb or unRegInsCb is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	mgr := &ZooKeeperManager{
		config:         config,
		conn:           newGoZooKeeperConn(), // using go-zookeeper as the default client
		eventCbs:       eventCbs,
		ctx:            ctx,
		cancelFunc:     cancel,
		wg:             new(sync.WaitGroup),
		localInstances: make(map[string]*inferInstanceInfo),
		dialer:         net.DialTimeout,
		maxDelay:       defaultMaxDelay,
		maxCreateRetry: defaultMaxCreateRetry,
		serviceAddress: defaultServiceAddress,

		watchInstancePathDelay:  watchInstancePathDelay,
		monitorServicePathDelay: monitorServicePathDelay,
		reconnectDelay:          reconnectDelay,

		aclScheme: toAclSchemeType(config.AclScheme),
	}

	for _, opt := range opts {
		err := opt(mgr)
		if err != nil {
			log.Error().Msgf("failed to execute zk option, err: %v", err)
			return nil, err
		}
	}

	return mgr, nil
}

func (m *ZooKeeperManager) ensureBasePath(path string) error {
	var data []byte

	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := ""
	for _, part := range parts {
		current += "/" + part
		exists, _, err := m.conn.Exists(current)
		if err != nil {
			log.Error().Msgf("check path %v with err, err: %v", path, err)
			return err
		}

		if exists {
			continue
		}

		log.Info().Msgf("retry creating base path %v", current)
		if err := m.retryCreateZkNode(current, data, true); err != nil {
			log.ErrorAlarmMsgf(log.ZKPathCreationFailed, log.Report,
				fmt.Sprintf("failed to create base path %v, err: %v", current, err))
			return err
		}
		log.Info().Msgf("base path %v has been created successfully", current)
	}

	return nil
}

func (m *ZooKeeperManager) ensureBasePaths() error {
	log.Debug().Msgf("ensure base path %v", m.config.InferenceInstancePath)
	if err := m.ensureBasePath(m.config.InferenceInstancePath); err != nil {
		return err
	}

	log.Debug().Msgf("ensure base path %v", m.config.ScheduleServicePath)
	if err := m.ensureBasePath(m.config.ScheduleServicePath); err != nil {
		return err
	}
	return nil
}

func (m *ZooKeeperManager) getZkAcl() []zk.ACL {
	switch m.aclScheme {
	case aclSchemeDefault:
		return zk.WorldACL(zk.PermAll)
	case aclSchemeDigest:
		return zk.DigestACL(zk.PermAll, m.user, string(m.password))
	default:
		return []zk.ACL{}
	}
}

func (m *ZooKeeperManager) addAuth() error {
	if m.aclScheme == aclSchemeDefault {
		log.Info().Msgf("using default acl scheme")
		return nil
	}

	log.Info().Msgf("using digest acl scheme")
	totalLen := len(m.user) + len(":") + len(m.password)
	auth := make([]byte, totalLen)
	idx := 0
	idx += copy(auth[idx:], m.user)
	idx += copy(auth[idx:], ":")
	idx += copy(auth[idx:], m.password)
	defer utils.ZeroBytes(auth)
	err := m.conn.AddAuth("digest", auth)
	if err != nil {
		log.Error().Msgf("failed to add digest auth, err: %v", err)
		return err
	}

	log.Info().Msgf("add digest auth successfully")
	return nil
}

func (m *ZooKeeperManager) connectWithTimeout() error {
	log.Info().Msgf("start to connect zookeeper server %v", m.config.Address)
	eventCh, err := m.conn.Connect(
		strings.Split(m.config.Address, ","),
		time.Duration(m.config.SessionTimeout)*time.Second,
		m.dialer,
	)
	if err != nil {
		log.Error().Msgf("failed to execute zk.connect, err: %v", err)
		return err
	}
	if eventCh == nil {
		err = fmt.Errorf("eventCh is nil")
		log.Error().Msgf("%v", err)
		m.conn.Close()
		return err
	}

	ticker := time.NewTicker(time.Duration(m.config.ConnectTimeout) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-eventCh:
			log.Info().Msgf("connecting Zk, received event: %v", event.State)
			if event.State != zk.StateHasSession {
				continue
			}

			// connect ok, add auth
			if err := m.addAuth(); err != nil {
				log.Error().Msgf("failed to add auth, scheme: %v, err: %v", m.aclScheme, err)
				m.conn.Close()
				return err
			}

			// everything is ok
			log.Info().Msgf("connect zookeeper successfully")
			m.eventChan = eventCh
			return nil

		case <-ticker.C:
			err = fmt.Errorf("connect zookeeper server timeout")
			log.ErrorAlarmMsgf(log.ZKConnectionTimeout, log.Report, fmt.Sprintf("%v", err))
			m.conn.Close()
			return err
		case <-m.ctx.Done():
			err = fmt.Errorf("connectWithTimeout exit for context done")
			log.Error().Msgf("%v", err)
			m.conn.Close()
			return err
		}
	}
}

// Start initiates ZooKeeper connection with exponential backoff delay
func (m *ZooKeeperManager) Start() error {
	log.Info().Msgf("starting zookeeper manager")

	m.ctx, m.cancelFunc = context.WithCancel(context.Background())

	if err := m.connectWithTimeout(); err != nil {
		return err
	}

	if err := m.ensureBasePaths(); err != nil {
		m.Stop()
		return err
	}
	log.Info().Msgf("ins path %v", m.config.InferenceInstancePath)

	// Start background monitoring routines
	m.wg.Add(1)
	go m.monitorConnection()
	m.wg.Add(1)
	log.Info().Msgf("ins path %v", m.config.InferenceInstancePath)
	go m.watchInferenceInstances()
	log.Info().Msgf("ins path %v", m.config.InferenceInstancePath)

	// export address of schedule service
	if err := m.registerServiceNode(); err != nil {
		m.Stop()
		return err
	}
	log.Info().Msgf("service path %v", m.config.ScheduleServicePath)

	m.wg.Add(1)
	go m.monitorServiceNode()

	m.wg.Add(1)
	go m.monitorInsNode()

	log.Info().Msgf("zookeeper manager has been started successfully")
	return nil
}

// monitorConnection watches for ZooKeeper connection state changes
func (m *ZooKeeperManager) monitorConnection() {
	log.Info().Msgf("starting monitorConnection loop")
	defer m.wg.Done()

	for {
		select {
		case event := <-m.eventChan:
			switch event.State {
			case zk.StateDisconnected:
				log.ErrorAlarmMsgf(log.ZKDisconnected, log.Report, "ZooKeeper connection lost")
			case zk.StateConnected:
				log.WarnAlarmMsgf(log.ZKDisconnected, log.Clear, "ZooKeeper connection established")
			case zk.StateExpired:
				log.Warn().Msgf("ZooKeeper session expired, reconnecting")
			case zk.StateConnecting:
				log.Debug().Msgf("Zookeeper has been disconnected, connecting...")
			default:
				log.Info().Msgf("ZooKeeper state changed, new state %v", event.State.String())
			}
		case <-m.ctx.Done():
			log.Info().Msgf("monitorConnection loop exited")
			return
		}
	}
}

// ensureServiceNode creates ephemeral node for service registration
func (m *ZooKeeperManager) ensureServiceNode(deleteOld bool) error {
	path := fmt.Sprintf("%s/%s", m.config.ScheduleServicePath, m.serviceAddress)
	data := []byte(m.serviceAddress)

	exists, stat, err := m.conn.Exists(path)
	if err != nil {
		log.Error().Msgf("failed to check path %v, err: %v", path, err)
		return err
	}

	if exists {
		if !deleteOld {
			return nil
		}

		// service node already exists, remove the old one.
		if err := m.conn.Delete(path, stat.Version); err != nil && !errors.Is(err, zk.ErrNoNode) {
			log.Error().Msgf("failed to delete service node, err: %v", err)
			return err
		}

		log.Info().Msgf("service node %v exists, delete it successfully", path)
	}

	// If deleteOld is False, it means that the ensureServiceNode method is not being invoked at aigw startup.
	if !deleteOld {
		// If the service node do not exist, log and report an alarm
		log.WarnAlarmMsgf(log.ZKPathNotExist, log.Report,
			fmt.Sprintf("Service schedule node %s does not exist, create it", path))
	}

	// service node doesn't exist, then create a new one.
	if err := m.retryCreateZkNode(path, data, false); err != nil {
		log.ErrorAlarmMsgf(log.ZKPathCreationFailed, log.Report,
			fmt.Sprintf("failed to create zookeeper node %v, err: %v", path, err))
		return err
	}

	return nil
}

// monitorServiceNode monitors key paths
func (m *ZooKeeperManager) monitorServiceNode() {
	log.Info().Msgf("starting monitorServiceNode loop")
	defer m.wg.Done()

	checkFunc := func() {
		exists, _, err := m.conn.Exists(m.config.ScheduleServicePath)
		if err != nil {
			log.Error().Msgf("failed to check schedule service, path %v, err: %v", m.config.ScheduleServicePath, err)
			return
		}
		if !exists {
			log.WarnAlarmMsgf(log.ZKPathNotExist, log.Report, fmt.Sprintf("zookeeper schedule service path has been deleted"))
			if err := m.ensureBasePath(m.config.ScheduleServicePath); err != nil {
				log.Warn().Msgf("ensure service path failed, err: %v", err)
				return
			}
		}

		if err := m.ensureServiceNode(false); err != nil {
			log.Warn().Msgf("failed to ensure service node, err: %v", err)
			return
		}
	}

	ticker := time.NewTicker(m.monitorServicePathDelay)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			checkFunc()

		case <-m.ctx.Done():
			log.Info().Msgf("monitorServiceNode loop exited")
			return
		}
	}
}

func (m *ZooKeeperManager) monitorInsNode() {
	log.Info().Msgf("starting monitorInsNode loop")
	defer m.wg.Done()

	ticker := time.NewTicker(m.monitorServicePathDelay)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.handleInstanceChanges()

		case <-m.ctx.Done():
			log.Info().Msgf("monitorInsNodde loop exited")
			return
		}
	}
}

// registerServiceNode creates ephemeral node for service registration
func (m *ZooKeeperManager) registerServiceNode() error {
	path := fmt.Sprintf("%s/%s", m.config.ScheduleServicePath, m.serviceAddress)
	log.Info().Msgf("start to register service node %v", path)

	if err := m.ensureServiceNode(true); err != nil {
		return err
	}

	log.Info().Msgf("register new service node %v successfully", path)
	return nil
}

func (m *ZooKeeperManager) ensureInferenceInstancePath() error {
	exists, _, err := m.conn.Exists(m.config.InferenceInstancePath)
	if err != nil {
		log.Error().Msgf("failed to check inference instances, path %v, err: %v", m.config.InferenceInstancePath, err)
		return err
	}

	if !exists {
		log.WarnAlarmMsgf(log.ZKPathNotExist, log.Report,
			fmt.Sprintf("inference instance path %v does not exist, create it", m.config.InferenceInstancePath))
		if err := m.ensureBasePath(m.config.InferenceInstancePath); err != nil {
			log.Error().Msgf("%v", err)
			return err
		}
	}

	return nil
}

func (m *ZooKeeperManager) getInferenceInstancePathWatch() (<-chan zk.Event, error) {
	if err := m.ensureInferenceInstancePath(); err != nil {
		msg := fmt.Sprintf("failed to ensureInferenceInstancePath, path: %v, err: %v",
			m.config.InferenceInstancePath, err)
		log.Warn().Msgf("%v", msg)
		return nil, fmt.Errorf("%v", msg)
	}

	_, watch, err := m.conn.ChildrenW(m.config.InferenceInstancePath)
	if err != nil {
		msg := fmt.Sprintf("failed to execute ChildrenW, path %v, err: %v", m.config.InferenceInstancePath, err)
		log.Warn().Msgf("%v", msg)
		return nil, err
	}

	if watch == nil {
		msg := fmt.Sprintf("failed to get watch for path %v", m.config.InferenceInstancePath)
		log.Warn().Msgf("%v", msg)
		return nil, fmt.Errorf("%v", msg)
	}

	return watch, nil
}

// watchInferenceInstances monitors changes in inference instance nodes
func (m *ZooKeeperManager) watchInferenceInstances() {
	log.Info().Msgf("starting watchInferenceInstances loop")
	defer m.wg.Done()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	discoveryDone := false

	for {
		watch, err := m.getInferenceInstancePathWatch()
		if err != nil || watch == nil {
			timer.Reset(m.watchInstancePathDelay)
			select {
			case <-timer.C:
				log.Warn().Msgf("failed to get watch for path %v, retrying", m.config.InferenceInstancePath)
				continue
			case <-m.ctx.Done():
				log.Info().Msgf("watchInferenceInstances loop exited for context done")
				return
			}
		}

		if !discoveryDone {
			log.Info().Msgf("discovery on path %v", m.config.InferenceInstancePath)
			m.handleInstanceChanges()
			discoveryDone = true
		}

		log.Debug().Msgf("watching inference instance path %v", m.config.InferenceInstancePath)
		select {
		case event := <-watch:
			log.Debug().Msgf("received event %v", event)
			if event.Type == zk.EventNodeChildrenChanged {
				log.Debug().Msgf("received EventNodeChildrenChanged")
				m.handleInstanceChanges()
			}
		case <-m.ctx.Done():
			log.Info().Msgf("watchInferenceInstances loop exited for context done")
			return
		}
	}
}

func (m *ZooKeeperManager) handleNewInstance(wg *sync.WaitGroup, newNode string, result map[string]*inferInstanceInfo,
	lock *sync.Mutex) {
	if result == nil {
		log.Error().Msgf("result map is nil")
		return
	}

	defer wg.Done()

	var insp *inferInstanceInfo
	defer func() {
		lock.Lock()
		if _, exists := result[newNode]; exists {
			lock.Unlock()
			log.Error().Msgf("found duplicated instance %v", newNode)
			return
		}
		result[newNode] = insp
		lock.Unlock()
	}()

	log.Info().Msgf("start to process new instance %v", newNode)

	path := fmt.Sprintf("%s/%s", m.config.InferenceInstancePath, newNode)
	data, _, err := m.conn.Get(path)
	if err != nil {
		log.Error().Msgf("Failed to get node data, path: %v, err: %v", path, err)
		return
	}

	var instance inferInstanceInfo
	if err = json.Unmarshal(data, &instance); err != nil {
		log.Error().Msgf("failed to unmarshal data for path %v", path)
		return
	}
	log.Info().Msgf("new inference instance detected, path: %v, info: %+v", path, instance)

	input := &base.RegisterInstanceIn{
		Name:    instance.Name,
		Model:   instance.Model,
		IP:      instance.IP,
		Port:    instance.Port,
		Role:    instance.Role,
		GroupID: instance.GroupID,
	}

	if err = m.eventCbs.RegInferInsCb(input); err != nil {
		log.Error().Msgf("failed to register instance from zookeeper, err: %v", err)
		return
	}
	insp = &instance
	log.Info().Msgf("finished to process new instance %v", newNode)
}

func (m *ZooKeeperManager) handleDeletedInstance(wg *sync.WaitGroup, node string, deletedNodeInfo *inferInstanceInfo,
	result map[string]error, lock *sync.Mutex) {
	if result == nil {
		log.Error().Msgf("result map is nil")
		return
	}

	defer wg.Done()

	var err error
	defer func() {
		lock.Lock()
		if _, exists := result[node]; exists {
			lock.Unlock()
			log.Error().Msgf("found duplicated instance %v", node)
			return
		}
		result[node] = err
		lock.Unlock()
	}()

	log.Info().Msgf("start to handle deleting zookeeper node %v", node)
	input := &base.UnregisterInstanceIn{
		IP:    deletedNodeInfo.IP,
		Port:  deletedNodeInfo.Port,
		Model: deletedNodeInfo.Model,
	}
	if err = m.eventCbs.UnRegInferInsCb(input); err != nil {
		log.Error().Msgf("failed to unregister instance from zookeeper, err: %v", err)
		return
	}

	log.Info().Msgf("unregister instance %v_%v successfully", input.IP, input.Port)
}

// handleInstanceChanges processes node changes in inference path
func (m *ZooKeeperManager) handleInstanceChanges() {
	m.insPathLock.Lock()
	defer m.insPathLock.Unlock()
	children, _, err := m.conn.Children(m.config.InferenceInstancePath)
	if err != nil {
		log.Error().Msgf("failed to get children, err: %v", err)
		return
	}

	log.Debug().Msgf("received children: %v", children)
	// Convert current nodes to map for comparison
	currentNodes := make(map[string]bool)
	for _, child := range children {
		currentNodes[child] = true
	}

	wg := new(sync.WaitGroup)
	var lock sync.Mutex
	newResultMap := make(map[string]*inferInstanceInfo)
	// Process each child node
	for _, child := range children {
		// skip existing node
		if _, exists := m.localInstances[child]; exists {
			continue
		}

		// skip node with getting data error
		wg.Add(1)
		go m.handleNewInstance(wg, child, newResultMap, &lock)
	}

	deletedNodes := make(map[string]*inferInstanceInfo)
	// Detect removed nodes
	for node, info := range m.localInstances {
		if !currentNodes[node] {
			deletedNodes[node] = info
		}
	}

	deleteResultMap := make(map[string]error)
	for node, info := range deletedNodes {
		wg.Add(1)
		go m.handleDeletedInstance(wg, node, info, deleteResultMap, &lock)
	}

	wg.Wait()
	for node, info := range newResultMap {
		if info == nil {
			continue
		}
		m.localInstances[node] = info
		log.Info().Msgf("zookeeper node %v created", node)
	}
	for node, e := range deleteResultMap {
		if e != nil {
			continue
		}
		delete(m.localInstances, node)
		log.Info().Msgf("zookeeper node %v deleted", node)
	}
}

// executeTaskWithRetry executes the task with maxRetry, maxRetry 0 means infinity loop
func (m *ZooKeeperManager) executeTaskWithRetry(maxRetry uint32, taskName string, task func() error) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for i := uint32(0); ; i++ {
		if maxRetry != 0 && i >= maxRetry {
			return fmt.Errorf("failed to execute task %v after max retries %v", taskName, maxRetry)
		}

		log.Info().Msgf("execute task %v, attempt: %v", taskName, i+1)

		err := task()
		if err == nil {
			log.Info().Msgf("execute task %v successfully, attempt: %v", taskName, i+1)
			return nil
		}

		delay := utils.GetExpBackoffDelay(i, m.maxDelay)
		log.Error().Msgf("failed to execute task %v, retrying, attempt %v, delay %v, err: %v",
			taskName, i+1, delay, err)

		ticker.Reset(delay)
		select {
		case <-ticker.C:
			continue
		case <-m.ctx.Done():
			return fmt.Errorf("execute task %v exited for context done", taskName)
		}
	}
}

// retryCreateZkNode creates zk node with delay
func (m *ZooKeeperManager) retryCreateZkNode(path string, data []byte, persistent bool) error {
	flags := zk.FlagEphemeral
	if persistent {
		flags = zk.FlagPersistent
	}

	task := fmt.Sprintf("retryCreateZkNode %v", path)
	err := m.executeTaskWithRetry(uint32(m.maxCreateRetry), task, func() error {
		_, e := m.conn.Create(path, data, int32(flags), m.getZkAcl())
		return e
	})

	return err
}

// Stop performs graceful shutdown and cleanup
func (m *ZooKeeperManager) Stop() {
	log.Info().Msgf("start to stop zooKeeper manager")

	m.cancelFunc() // Cancel all background routines
	m.wg.Wait()

	// Remove registered service node
	path := fmt.Sprintf("%s/%s", m.config.ScheduleServicePath, m.serviceAddress)
	if err := m.conn.Delete(path, -1); err != nil && !errors.Is(err, zk.ErrNoNode) {
		log.Warn().Msgf("Failed to delete service node, err: %v", err)
	}

	m.conn.Close()

	log.Info().Msgf("zooKeeper manager stopped")
}
