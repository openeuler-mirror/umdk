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
	"sync"
	"time"

	"huawei.com/aigw/pkg/log"
)

const (
	defaultEndpointTemplate = "tcp://{ip}:5557"
	defaultTopic            = ""
	defaultPollTimeout      = 100 * time.Millisecond
	defaultReconnectDelay   = 1 * time.Second
	defaultHWM              = 100000
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
		EndpointTemplate: defaultEndpointTemplate,
		Topic:            defaultTopic,
		PollTimeout:      defaultPollTimeout,
		ReconnectDelay:   defaultReconnectDelay,
		HWM:              defaultHWM,
	}
}

type KVEventsManager struct {
	config  KVEventsManagerConfig
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

	log.Info().Msg("[kvevents] KV Events support is enabled")

	return &KVEventsManager{
		config:   config,
		handler:  handler,
		clients:  make(map[string]*ZMQClient),
		handlers: make(map[string]*eventHandler),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (m *KVEventsManager) IsEnabled() bool {
	return m != nil
}

func (m *KVEventsManager) SubscribeInstance(instanceName, instanceIP, modelName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[instanceName]; exists {
		return nil
	}

	config := ZMQConfig{
		Endpoint:       m.buildEndpoint(instanceIP),
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
		instanceName, modelName, config.Endpoint)
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
