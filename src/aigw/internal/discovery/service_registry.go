/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Service registry for AIGW.
 * Create: 2026-04-29
 */

// Package discovery provides service discovery for AIGW.
package discovery

import (
	"context"
	"fmt"
	"sync"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

// ServiceRegistry manages discovered service instances.
type ServiceRegistry struct {
	mu         sync.RWMutex
	instances  map[string]*ServiceInstance // ID -> Instance
	watchers   []chan WatchEvent
	discovery  ServiceDiscovery
	running    bool
	cancelFunc context.CancelFunc
}

// NewServiceRegistry creates a new service registry.
func NewServiceRegistry(discovery ServiceDiscovery) *ServiceRegistry {
	return &ServiceRegistry{
		instances: make(map[string]*ServiceInstance),
		discovery: discovery,
	}
}

// StartDiscovery starts watching for service changes.
func (sr *ServiceRegistry) StartDiscovery(ctx context.Context, opts *DiscoverOptions) error {
	sr.mu.Lock()
	if sr.running {
		sr.mu.Unlock()
		return fmt.Errorf("discovery already running")
	}

	// Create cancelable context
	ctx, cancel := context.WithCancel(ctx)
	sr.cancelFunc = cancel
	sr.running = true
	sr.mu.Unlock()

	// Start watching in background
	go func() {
		log.Info().Msg("[ServiceRegistry] Starting discovery Watch...")
		eventCh, err := sr.discovery.Watch(ctx, opts)
		if err != nil {
			log.Error().Msgf("failed to start discovery watch: %v", err)
			sr.mu.Lock()
			sr.running = false
			sr.mu.Unlock()
			return
		}
		log.Info().Msg("[ServiceRegistry] Discovery Watch returned, starting event loop...")
		log.Info().Msgf("[ServiceRegistry] eventCh is nil: %v", eventCh == nil)

		eventCount := 0
		log.Info().Msg("[ServiceRegistry] Starting event loop...")
		for {
			log.Debug().Msg("[ServiceRegistry] waiting for event...")
			select {
			case <-ctx.Done():
				log.Info().Msgf("[ServiceRegistry] context cancelled after %d events", eventCount)
				sr.mu.Lock()
				sr.running = false
				sr.mu.Unlock()
				return
			case event, ok := <-eventCh:
				log.Info().Msgf("[ServiceRegistry] received from eventCh, ok=%v, eventCount=%d", ok, eventCount)
				if !ok {
					log.Info().Msgf("[ServiceRegistry] event channel closed after %d events", eventCount)
					sr.mu.Lock()
					sr.running = false
					sr.mu.Unlock()
					return
				}
				eventCount++
				if event.Instance != nil {
					log.Info().Msgf("[ServiceRegistry] received event #%d: type=%v, instance=%s",
						eventCount, event.Type, event.Instance.ID)
				} else {
					log.Warn().Msgf("[ServiceRegistry] received event #%d with nil instance, type=%v", eventCount, event.Type)
				}
				sr.handleEvent(event)
			}
		}
	}()

	return nil
}

// StopDiscovery stops the discovery.
func (sr *ServiceRegistry) StopDiscovery() error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if !sr.running {
		return nil
	}

	if sr.cancelFunc != nil {
		sr.cancelFunc()
	}
	sr.running = false

	return sr.discovery.Close()
}

// handleEvent handles a watch event.
func (sr *ServiceRegistry) handleEvent(event WatchEvent) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	switch event.Type {
	case WatchEventAdd:
		if event.Instance == nil {
			return
		}
		sr.instances[event.Instance.ID] = event.Instance
		log.Info().Msgf("discovered instance: %s (%s:%d)", event.Instance.ID, event.Instance.IP, event.Instance.Port)

	case WatchEventModify:
		if event.Instance == nil {
			return
		}
		sr.instances[event.Instance.ID] = event.Instance
		log.Debug().Msgf("modified instance: %s", event.Instance.ID)

	case WatchEventDelete:
		if event.Instance == nil {
			return
		}
		delete(sr.instances, event.Instance.ID)
		log.Info().Msgf("removed instance: %s", event.Instance.ID)
	}

	// Notify all watchers
	for _, ch := range sr.watchers {
		select {
		case ch <- event:
		default:
			log.Warn().Msg("watcher channel full, dropping event")
		}
	}
}

// GetInstances returns all discovered instances.
func (sr *ServiceRegistry) GetInstances(role base.InstanceRole) []*ServiceInstance {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var result []*ServiceInstance
	for _, inst := range sr.instances {
		if role == base.InvalidRoleInstance || inst.Role == role {
			result = append(result, inst)
		}
	}
	return result
}

// GetInstance returns an instance by ID.
func (sr *ServiceRegistry) GetInstance(id string) *ServiceInstance {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.instances[id]
}

// AddWatcher adds a watcher for service changes.
func (sr *ServiceRegistry) AddWatcher() chan WatchEvent {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	ch := make(chan WatchEvent, 100)
	sr.watchers = append(sr.watchers, ch)
	return ch
}

// RemoveWatcher removes a watcher.
func (sr *ServiceRegistry) RemoveWatcher(ch chan WatchEvent) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	for i, watcher := range sr.watchers {
		if watcher == ch {
			sr.watchers = append(sr.watchers[:i], sr.watchers[i+1:]...)
			close(ch)
			return
		}
	}
}

// InstanceCount returns the number of discovered instances.
func (sr *ServiceRegistry) InstanceCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(sr.instances)
}

// IsRunning returns whether discovery is running.
func (sr *ServiceRegistry) IsRunning() bool {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.running
}

// Clear clears all discovered instances.
func (sr *ServiceRegistry) Clear() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.instances = make(map[string]*ServiceInstance)
}

// DiscoverOnce performs a one-time discovery.
func (sr *ServiceRegistry) DiscoverOnce(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error) {
	instances, err := sr.discovery.Discover(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Update registry
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Clear existing instances if not specified
	if opts.Role == base.InvalidRoleInstance {
		sr.instances = make(map[string]*ServiceInstance)
	}

	// Add discovered instances
	for _, inst := range instances {
		sr.instances[inst.ID] = inst
	}

	return instances, nil
}
