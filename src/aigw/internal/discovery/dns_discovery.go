/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: DNS service discovery for AIGW.
 * Create: 2026-04-29
 */

// Package discovery provides service discovery for AIGW.
package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

// DNSDiscovery implements ServiceDiscovery using DNS SRV records.
// This is useful for Headless Services in Kubernetes.
type DNSDiscovery struct {
	resolver *net.Resolver
	config   *DiscoveryConfig
	mu       sync.RWMutex
	running  bool
	cancelFunc context.CancelFunc
}

// NewDNSDiscovery creates a new DNS service discovery.
func NewDNSDiscovery(config *DiscoveryConfig) (*DNSDiscovery, error) {
	if config == nil {
		config = &DiscoveryConfig{}
	}

	resolver := net.DefaultResolver
	if config.DNSHost != "" {
		// Custom DNS server
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: config.LookupTimeout,
				}
				return d.DialContext(ctx, network, net.JoinHostPort(config.DNSHost, "53"))
			},
		}
	}

	return &DNSDiscovery{
		resolver: resolver,
		config:   config,
	}, nil
}

// Discover discovers service instances using DNS SRV records.
func (dd *DNSDiscovery) Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error) {
	opts = DiscoverOptionsWithDefaults(opts)

	if opts.ServiceName == "" {
		return nil, fmt.Errorf("service name required for DNS discovery")
	}

	// Build SRV record name
	// Format: _service._proto.namespace.svc.cluster.local
	srvName := dd.buildSRVName(opts.ServiceName, opts.Namespace)

	// Lookup SRV records
	_, addrs, err := dd.resolver.LookupSRV(ctx, opts.ServiceName, "tcp", srvName)
	if err != nil {
		// Try without namespace suffix for simpler names
		srvName = dd.buildSRVNameSimple(opts.ServiceName)
		_, addrs, err = dd.resolver.LookupSRV(ctx, opts.ServiceName, "tcp", srvName)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup SRV records: %w", err)
		}
	}

	// Convert to ServiceInstance
	var instances []*ServiceInstance
	for _, addr := range addrs {
		// Remove trailing dot from target
		target := strings.TrimSuffix(addr.Target, ".")

		instance := &ServiceInstance{
			ID:     fmt.Sprintf("%s:%d", target, addr.Port),
			Name:   opts.ServiceName,
			IP:     target,
			Port:   int(addr.Port),
			Labels: make(map[string]string),
			Healthy: true,
		}

		// Filter by role if specified
		if opts.Role != base.InvalidRoleInstance {
			// DNS discovery doesn't have role labels
			// Set default role
			instance.Role = opts.Role
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// Watch watches for service changes using DNS polling.
// DNS doesn't support watch, so we poll periodically.
func (dd *DNSDiscovery) Watch(ctx context.Context, opts *DiscoverOptions) (<-chan WatchEvent, error) {
	opts = DiscoverOptionsWithDefaults(opts)

	pollInterval := dd.config.ResyncPeriod
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}

	// Create watch channel
	eventCh := make(chan WatchEvent, 100)

	// Create cancelable context
	ctx, cancel := context.WithCancel(ctx)
	dd.mu.Lock()
	dd.cancelFunc = cancel
	dd.running = true
	dd.mu.Unlock()

	// Start polling in background
	go func() {
		defer close(eventCh)

		// Initial discovery
		instances, err := dd.Discover(ctx, opts)
		if err != nil {
			log.Warn().Msgf("initial DNS discovery failed: %v", err)
		} else {
			// Send ADD events
			for _, ins := range instances {
				select {
				case <-ctx.Done():
					return
				case eventCh <- WatchEvent{Type: WatchEventAdd, Instance: ins}:
				default:
					log.Warn().Msg("DNS discovery event channel full")
				}
			}
		}

		// Poll periodically
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		// Track known instances
		known := make(map[string]bool)
		for _, ins := range instances {
			known[ins.ID] = true
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Re-discover
				newInstances, err := dd.Discover(ctx, opts)
				if err != nil {
					log.Warn().Msgf("DNS discovery poll failed: %v", err)
					continue
				}

				// Build new set
				newSet := make(map[string]bool)
				for _, ins := range newInstances {
					newSet[ins.ID] = true
				}

				// Send DELETE events for removed instances
				for id := range known {
					if !newSet[id] {
						select {
						case eventCh <- WatchEvent{Type: WatchEventDelete, Instance: &ServiceInstance{ID: id}}:
							delete(known, id)
						default:
						}
					}
				}

				// Send ADD events for new instances
				for _, ins := range newInstances {
					if !known[ins.ID] {
						select {
						case eventCh <- WatchEvent{Type: WatchEventAdd, Instance: ins}:
							known[ins.ID] = true
						default:
						}
					}
				}
			}
		}
	}()

	return eventCh, nil
}

// Close closes the discovery.
func (dd *DNSDiscovery) Close() error {
	dd.mu.Lock()
	defer dd.mu.Unlock()

	if dd.cancelFunc != nil {
		dd.cancelFunc()
	}
	dd.running = false
	return nil
}

// IsRunning returns whether discovery is running.
func (dd *DNSDiscovery) IsRunning() bool {
	dd.mu.RLock()
	defer dd.mu.RUnlock()
	return dd.running
}

// buildSRVName builds the SRV record name for Kubernetes.
func (dd *DNSDiscovery) buildSRVName(serviceName, namespace string) string {
	// _service._proto.namespace.svc.cluster.local
	return fmt.Sprintf("_%s._tcp.%s.svc.cluster.local", serviceName, namespace)
}

// buildSRVNameSimple builds a simpler SRV name.
func (dd *DNSDiscovery) buildSRVNameSimple(serviceName string) string {
	return fmt.Sprintf("_%s._tcp", serviceName)
}
