/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Kubernetes service discovery for AIGW.
 * Create: 2026-04-29
 */

// Package discovery provides service discovery for AIGW.
package discovery

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"huawei.com/aigw/internal/base"
	"huawei.com/aigw/pkg/log"
)

// K8sDiscovery implements ServiceDiscovery using Kubernetes API.
type K8sDiscovery struct {
	clientset  K8sClientset
	informer   K8sInformer
	config     *DiscoveryConfig
	mu         sync.RWMutex
	running    bool
	cancelFunc context.CancelFunc
}

// K8sClientset is the interface for Kubernetes client operations.
// This is a simplified interface to avoid direct k8s.io/client-go dependency.
type K8sClientset interface {
	// ListEndpoints lists endpoints in the namespace.
	ListEndpoints(ctx context.Context, namespace string, labelSelector map[string]string) ([]K8sEndpoints, error)
	// WatchEndpoints watches for endpoint changes.
	WatchEndpoints(ctx context.Context, namespace string, labelSelector map[string]string) (<-chan K8sEndpointsEvent, error)
	// Close closes the client.
	Close() error
}

// K8sInformer is the interface for Kubernetes informers.
type K8sInformer interface {
	// Start starts the informer.
	Start(ctx context.Context)
	// Stop stops the informer.
	Stop()
}

// K8sEndpoints represents Kubernetes Endpoints.
type K8sEndpoints struct {
	Name      string
	Namespace string
	Labels    map[string]string
	Addresses []K8sEndpointAddress
	Ports     []K8sEndpointPort
}

// K8sEndpointAddress represents an address in Kubernetes Endpoints.
type K8sEndpointAddress struct {
	IP        string
	Port      int
	TargetRef map[string]string
}

// K8sEndpointPort represents a port in Kubernetes Endpoints.
type K8sEndpointPort struct {
	Port int
	Name string
}

// K8sEndpointsEvent represents an event for endpoints changes.
type K8sEndpointsEvent struct {
	Type      WatchEventType
	Endpoints K8sEndpoints
}

// NewK8sDiscovery creates a new Kubernetes service discovery.
// Automatically initializes the Kubernetes client if kubeconfig is provided or in-cluster.
func NewK8sDiscovery(config *DiscoveryConfig) (*K8sDiscovery, error) {
	if config == nil {
		config = &DiscoveryConfig{}
	}

	kd := &K8sDiscovery{
		config: config,
	}

	// Auto-initialize Kubernetes client
	// If KubeconfigPath is provided, use that kubeconfig
	// If KubeconfigPath is empty, try in-cluster config
	if config.KubeconfigPath != "" {
		// Out-of-cluster: use provided kubeconfig
		client, err := NewK8sClient(&K8sClientConfig{
			KubeconfigPath: config.KubeconfigPath,
			Namespace:      config.Namespace,
		})
		if err != nil {
			log.Warn().Msgf("[K8sDiscovery] failed to create k8s client with kubeconfig %s: %v", config.KubeconfigPath, err)
		} else {
			kd.clientset = client
			log.Info().Msgf("[K8sDiscovery] initialized k8s client with kubeconfig: %s", config.KubeconfigPath)
		}
	} else {
		// In-cluster: try to use service account token
		// This is automatically detected by empty KubeconfigPath
		client, err := NewK8sClient(&K8sClientConfig{
			Namespace: config.Namespace,
		})
		if err != nil {
			log.Warn().Msgf("[K8sDiscovery] failed to create in-cluster k8s client: %v", err)
		} else {
			kd.clientset = client
			log.Info().Msg("[K8sDiscovery] initialized in-cluster k8s client")
		}
	}

	return kd, nil
}

// SetClientset sets the Kubernetes clientset.
// This is used for dependency injection.
func (kd *K8sDiscovery) SetClientset(clientset K8sClientset) {
	kd.mu.Lock()
	defer kd.mu.Unlock()
	kd.clientset = clientset
}

// Discover discovers service instances from Kubernetes Endpoints.
func (kd *K8sDiscovery) Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error) {
	kd.mu.RLock()
	clientset := kd.clientset
	kd.mu.RUnlock()

	if clientset == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	opts = DiscoverOptionsWithDefaults(opts)
	namespace := opts.Namespace
	if kd.config.Namespace != "" {
		namespace = kd.config.Namespace
	}

	// List endpoints from Kubernetes
	endpoints, err := clientset.ListEndpoints(ctx, namespace, opts.LabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to list endpoints: %w", err)
	}

	// Convert to ServiceInstance
	var instances []*ServiceInstance
	for _, ep := range endpoints {
		// Filter by role if specified
		if opts.Role != base.InvalidRoleInstance {
			if role, ok := ep.Labels["role"]; ok {
				instanceRole, _ := base.ToInstanceRole(role)
				if instanceRole != opts.Role {
					continue
				}
			}
		}

		// Create instance for each (address, port) pair
		for _, addr := range ep.Addresses {
			for _, port := range ep.Ports {
				instance := &ServiceInstance{
					ID:        fmt.Sprintf("%s-%s-%d", ep.Name, addr.IP, port.Port),
					Name:      ep.Name,
					Namespace: ep.Namespace,
					IP:        addr.IP,
					Port:      port.Port,
					Labels:    ep.Labels,
					Healthy:   true,
				}

				// Parse role from labels
				if role, ok := ep.Labels["role"]; ok {
					instance.Role, _ = base.ToInstanceRole(role)
				}

				// Parse DP rank from labels
				if dpRankStr, ok := ep.Labels["dp-rank"]; ok {
					if dpRank, err := strconv.Atoi(dpRankStr); err == nil {
						instance.DpRank = dpRank
					}
				}

				instances = append(instances, instance)
			}
		}
	}

	return instances, nil
}

// Watch watches for service changes using Kubernetes informers.
func (kd *K8sDiscovery) Watch(ctx context.Context, opts *DiscoverOptions) (<-chan WatchEvent, error) {
	kd.mu.RLock()
	clientset := kd.clientset
	kd.mu.RUnlock()

	if clientset == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	opts = DiscoverOptionsWithDefaults(opts)
	namespace := opts.Namespace
	if kd.config.Namespace != "" {
		namespace = kd.config.Namespace
	}

	// Create watch channel
	eventCh := make(chan WatchEvent, 100)

	// Start watching endpoints
	ctx, cancel := context.WithCancel(ctx)
	kd.mu.Lock()
	kd.cancelFunc = cancel
	kd.running = true
	kd.mu.Unlock()

	// Watch endpoints in background
	go func() {
		defer close(eventCh)

		log.Info().Msg("[K8sDiscovery] Starting to watch endpoints...")
		watchCh, err := clientset.WatchEndpoints(ctx, namespace, opts.LabelSelector)
		if err != nil {
			log.Error().Msgf("failed to watch endpoints: %v", err)
			return
		}
		log.Info().Msg("[K8sDiscovery] WatchEndpoints returned, starting event loop...")

		eventCount := 0
		for {
			select {
			case <-ctx.Done():
				log.Info().Msgf("[K8sDiscovery] context cancelled after %d events", eventCount)
				return
			case k8sEvent, ok := <-watchCh:
				if !ok {
					log.Info().Msgf("[K8sDiscovery] watch channel closed after %d events", eventCount)
					return
				}
			eventCount++
			log.Debug().Msgf("[K8sDiscovery] received k8s event #%d: %v, endpoints=%s, addresses=%d, ports=%d",
				eventCount, k8sEvent.Type, k8sEvent.Endpoints.Name,
				len(k8sEvent.Endpoints.Addresses), len(k8sEvent.Endpoints.Ports))

				// Convert K8s event to ServiceInstance events
				for _, addr := range k8sEvent.Endpoints.Addresses {
					for _, port := range k8sEvent.Endpoints.Ports {
						instance := &ServiceInstance{
							ID:        fmt.Sprintf("%s-%s-%d", k8sEvent.Endpoints.Name, addr.IP, port.Port),
							Name:      k8sEvent.Endpoints.Name,
							Namespace: k8sEvent.Endpoints.Namespace,
							IP:        addr.IP,
							Port:      port.Port,
							Labels:    k8sEvent.Endpoints.Labels,
							Healthy:   true,
						}

						// Parse role from labels
						if role, ok := k8sEvent.Endpoints.Labels["role"]; ok {
							instance.Role, _ = base.ToInstanceRole(role)
						}

						// Parse DP rank from labels
						if dpRankStr, ok := k8sEvent.Endpoints.Labels["dp-rank"]; ok {
							if dpRank, err := strconv.Atoi(dpRankStr); err == nil {
								instance.DpRank = dpRank
							}
						}

						// Filter by role if specified
						if opts.Role != base.InvalidRoleInstance && instance.Role != opts.Role {
							log.Info().Msgf("[K8sDiscovery] filtered out instance by role: instanceRole=%s, opts.Role=%s, instance=%s",
								instance.Role, opts.Role, instance.ID)
							continue
						}

						// Send event (blocking)
						log.Info().Msgf("[K8sDiscovery] sending ServiceInstance event: %s", instance.ID)
						eventCh <- WatchEvent{Type: k8sEvent.Type, Instance: instance}
					}
				}
			}
		}
	}()

	return eventCh, nil
}

// Close closes the discovery.
func (kd *K8sDiscovery) Close() error {
	kd.mu.Lock()
	defer kd.mu.Unlock()

	if kd.cancelFunc != nil {
		kd.cancelFunc()
	}
	kd.running = false

	if kd.clientset != nil {
		return kd.clientset.Close()
	}
	return nil
}

// IsRunning returns whether discovery is running.
func (kd *K8sDiscovery) IsRunning() bool {
	kd.mu.RLock()
	defer kd.mu.RUnlock()
	return kd.running
}

// ResyncPeriod returns the resync period.
func (kd *K8sDiscovery) ResyncPeriod() time.Duration {
	if kd.config.ResyncPeriod > 0 {
		return kd.config.ResyncPeriod
	}
	return 30 * time.Second
}
