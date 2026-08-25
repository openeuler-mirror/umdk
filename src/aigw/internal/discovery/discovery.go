/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Service discovery interface for AIGW.
 * Create: 2026-04-29
 */

// Package discovery provides service discovery for AIGW.
package discovery

import (
	"context"
	"time"

	"huawei.com/aigw/internal/base"
)

// ServiceDiscovery is the interface for service discovery.
type ServiceDiscovery interface {
	// Discover discovers service instances.
	Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error)

	// Watch watches for service changes.
	Watch(ctx context.Context, opts *DiscoverOptions) (<-chan WatchEvent, error)

	// Close closes the discovery.
	Close() error
}

// ServiceInstance represents a discovered service instance.
type ServiceInstance struct {
	ID         string            // Instance ID
	Name       string            // Service name
	Namespace  string            // Kubernetes namespace
	IP         string            // IP address
	Port       int               // Port number
	Role       base.InstanceRole // Instance role (prefill/decode)
	Labels     map[string]string // Labels
	Annotations map[string]string // Annotations
	Healthy    bool              // Health status
	DpRank     int               // DP rank for data parallel routing
}

// DiscoverOptions defines options for discovery.
type DiscoverOptions struct {
	Namespace     string            // Namespace to discover
	ServiceName   string            // Service name to discover
	LabelSelector map[string]string // Label selector for filtering
	Role          base.InstanceRole // Role filter
}

// WatchEvent represents a service change event.
type WatchEvent struct {
	Type     WatchEventType // Event type (ADD/MODIFY/DELETE)
	Instance *ServiceInstance
}

// WatchEventType is the type of watch event.
type WatchEventType int

const (
	WatchEventAdd WatchEventType = iota
	WatchEventModify
	WatchEventDelete
)

// DiscoveryConfig is the configuration for service discovery.
type DiscoveryConfig struct {
	Type         string // "k8s", "dns", "zk"
	KubeconfigPath string // Path to kubeconfig (empty for in-cluster)
	Namespace    string // Namespace to discover
	ResyncPeriod time.Duration // Resync period for informers
	DNSHost      string // DNS server for DNS discovery
	LookupTimeout time.Duration // DNS lookup timeout
}

// DiscoverOptionsWithDefaults returns DiscoverOptions with default values.
func DiscoverOptionsWithDefaults(opts *DiscoverOptions) *DiscoverOptions {
	if opts == nil {
		opts = &DiscoverOptions{}
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.Role == 0 {
		opts.Role = base.InvalidRoleInstance
	}
	return opts
}
