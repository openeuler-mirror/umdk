/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: KV Events manager for subscription management.
 * Create: 2026-05-21
 */

package kvevents

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/pkg/log"
)

const (
	defaultPollTimeout    = 100 * time.Millisecond
	defaultReconnectDelay = 1 * time.Second
	defaultHWM            = 100000
)

func loadEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		return val == "true" || val == "1"
	}
	return defaultVal
}

func loadEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func loadEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

var (
	envKVEventsEnabled          = loadEnvBool("AIGW_KV_EVENTS_ENABLED", false)
	envKVEventsEndpointTemplate = loadEnvString("AIGW_KV_EVENTS_ENDPOINT_TEMPLATE", "tcp://{ip}:5557")
	envKVEventsTopic            = loadEnvString("AIGW_KV_EVENTS_TOPIC", "")
	envKVEventsPollTimeoutMs    = loadEnvInt("AIGW_KV_EVENTS_POLL_TIMEOUT_MS", 100)
	envKVEventsReconnectDelayMs = loadEnvInt("AIGW_KV_EVENTS_RECONNECT_DELAY_MS", 1000)
	envKVEventsHWM              = loadEnvInt("AIGW_KV_EVENTS_HWM", defaultHWM)
	envKVEventsUseMockPorts     = loadEnvBool("AIGW_KV_EVENTS_USE_MOCK_PORTS", false) // only enable in test solution
)

type KVEventsManagerConfig struct {
	EndpointTemplate string
	Topic            string
	PollTimeout      time.Duration
	ReconnectDelay   time.Duration
	HWM              int
}

func DefaultKVEventsManagerConfig() KVEventsManagerConfig {
	return KVEventsManagerConfig{
		EndpointTemplate: envKVEventsEndpointTemplate,
		Topic:            envKVEventsTopic,
		PollTimeout:      time.Duration(envKVEventsPollTimeoutMs) * time.Millisecond,
		ReconnectDelay:   time.Duration(envKVEventsReconnectDelayMs) * time.Millisecond,
		HWM:              envKVEventsHWM,
	}
}

type KVEventsManager struct {
	config  KVEventsManagerConfig
	enabled bool
	handler EventHandler

	mu       sync.RWMutex
	clients  map[string]*ZMQClient
	handlers map[string]*eventHandler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewKVEventsManager(handler EventHandler, config KVEventsManagerConfig) *KVEventsManager {
	ctx, cancel := context.WithCancel(context.Background())

	enabled := envKVEventsEnabled

	if enabled {
		log.Info().Msg("[kvevents] KV Events support is enabled")
	} else {
		log.Info().Msg("[kvevents] KV Events support is disabled")
	}

	return &KVEventsManager{
		config:   config,
		enabled:  enabled,
		handler:  handler,
		clients:  make(map[string]*ZMQClient),
		handlers: make(map[string]*eventHandler),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (m *KVEventsManager) IsEnabled() bool {
	return m.enabled
}

func (m *KVEventsManager) SubscribeInstance(instanceName, instanceIP, modelName string) error {
	if !m.enabled {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[instanceName]; exists {
		return nil
	}

	// Calculate endpoint - use mock ports if env var is set
	var endpoint string
	if envKVEventsUseMockPorts && strings.HasPrefix(instanceName, "worker-") {
		workerPortStr := strings.TrimPrefix(instanceName, "worker-")
		if workerPort, err := strconv.Atoi(workerPortStr); err == nil {
			zmqPort := 55570 + (workerPort - 19000)
			endpoint = fmt.Sprintf("tcp://%s:%d", instanceIP, zmqPort)
			log.Info().Msgf("[kvevents] using mock port %s for instance %s", endpoint, instanceName)
		} else {
			endpoint = m.buildEndpoint(instanceIP)
		}
	} else {
		endpoint = m.buildEndpoint(instanceIP)
	}

	config := ZMQConfig{
		Endpoint:       endpoint,
		Topic:          m.config.Topic,
		PollTimeout:    m.config.PollTimeout,
		ReconnectDelay: m.config.ReconnectDelay,
		HWM:            m.config.HWM,
	}

	client, err := NewZMQClient(config, instanceName, modelName)
	if err != nil {
		return fmt.Errorf("failed to create ZMQ client: %w", err)
	}

	handler := newEventHandler(m, instanceName, modelName)

	m.clients[instanceName] = client
	m.handlers[instanceName] = handler

	m.wg.Add(1)
	go m.eventLoop(instanceName, client, handler)

	if err := client.Start(m.ctx); err != nil {
		delete(m.clients, instanceName)
		delete(m.handlers, instanceName)
		return fmt.Errorf("failed to start client: %w", err)
	}

	log.Info().Msgf("[kvevents] subscribed to %s (model: %s, endpoint: %s)",
		instanceName, modelName, endpoint)
	return nil
}

func (m *KVEventsManager) UnsubscribeInstance(instanceName string) {
	m.mu.Lock()
	client, exists := m.clients[instanceName]
	if exists {
		delete(m.clients, instanceName)
		delete(m.handlers, instanceName)
	}
	m.mu.Unlock()

	if client != nil {
		client.Stop()
		log.Info().Msgf("[kvevents] unsubscribed from %s", instanceName)
	}
}

func (m *KVEventsManager) buildEndpoint(ip string) string {
	template := m.config.EndpointTemplate
	if ip == "" {
		return template
	}
	return fmt.Sprintf("tcp://%s:5557", ip)
}

func (m *KVEventsManager) eventLoop(instanceName string, client *ZMQClient, handler *eventHandler) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case batch := <-client.Events():
			log.Info().Msgf("[kvevents] eventLoop received batch with %d events for %s", len(batch.Events), instanceName)
			for _, event := range batch.Events {
				// Recover from panics to prevent crash
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Error().Msgf("[kvevents] panic in handleEvent: %v", r)
						}
					}()
					if err := handler.handleEvent(event); err != nil {
						log.Error().Msgf("[kvevents] event handling error: %v", err)
					}
				}()
			}
		case err := <-client.Errors():
			log.Error().Msgf("[kvevents] client error for %s: %v", instanceName, err)
		}
	}
}

func (m *KVEventsManager) Stop() {
	log.Info().Msg("[kvevents] stopping manager")

	m.cancel()

	m.mu.Lock()
	for name, client := range m.clients {
		client.Stop()
		delete(m.clients, name)
	}
	m.mu.Unlock()

	m.wg.Wait()
	log.Info().Msg("[kvevents] manager stopped")
}

func (m *KVEventsManager) Close() {
	m.Stop()
}
