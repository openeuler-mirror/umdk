/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Kubernetes client implementation for AIGW.
 * Create: 2026-05-06
 */

package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"huawei.com/aigw/pkg/log"
)

type K8sClient struct {
	mu            sync.RWMutex
	kubeconfigPath string
	namespace     string
	timeout       time.Duration
	initialized   bool
	httpClient    *http.Client
	baseURL       string
}

type K8sClientConfig struct {
	KubeconfigPath string
	Namespace      string
	Timeout        time.Duration
}

func NewK8sClient(config *K8sClientConfig) (*K8sClient, error) {
	if config == nil {
		config = &K8sClientConfig{}
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	baseURL := ""
	if config.KubeconfigPath != "" {
		baseURL = extractServerFromKubeconfig(config.KubeconfigPath)
	}

	client := &K8sClient{
		kubeconfigPath: config.KubeconfigPath,
		namespace:      config.Namespace,
		timeout:        config.Timeout,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		baseURL: baseURL,
	}

	if err := client.init(); err != nil {
		log.Warn().Msgf("[K8sClient] initialization failed: %v, will retry on first use", err)
		return client, nil
	}

	return client, nil
}

func extractServerFromKubeconfig(kubeconfigPath string) string {
	if kubeconfigPath == "" {
		return ""
	}

	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		log.Warn().Msgf("[K8sClient] failed to read kubeconfig: %v", err)
		return ""
	}

	log.Debug().Msgf("[K8sClient] kubeconfig content: %s", string(data[:min(200, len(data))]))

	var kubeconfig struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}

	if err := json.Unmarshal(data, &kubeconfig); err != nil {
		log.Warn().Msgf("[K8sClient] failed to parse kubeconfig: %v", err)
		return ""
	}

	if len(kubeconfig.Clusters) > 0 && kubeconfig.Clusters[0].Cluster.Server != "" {
		server := strings.TrimSuffix(kubeconfig.Clusters[0].Cluster.Server, "/")
		log.Info().Msgf("[K8sClient] extracted server from kubeconfig: %s", server)
		return server
	}

	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (kc *K8sClient) init() error {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	if kc.initialized {
		return nil
	}

	log.Info().Msgf("[K8sClient] initializing with kubeconfig: %s, namespace: %s, baseURL: %s",
		kc.kubeconfigPath, kc.namespace, kc.baseURL)

	kc.initialized = true
	return nil
}

func (kc *K8sClient) doRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := kc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (kc *K8sClient) getEndpointsURL(namespace string) string {
	if kc.baseURL != "" {
		return fmt.Sprintf("%s/api/v1/namespaces/%s/endpoints", kc.baseURL, namespace)
	}
	return fmt.Sprintf("http://127.0.0.1:18080/api/v1/namespaces/%s/endpoints", namespace)
}

func (kc *K8sClient) getWatchURL(namespace string) string {
	if kc.baseURL != "" {
		return fmt.Sprintf("%s/api/v1/namespaces/%s/endpoints?watch=true", kc.baseURL, namespace)
	}
	return fmt.Sprintf("http://127.0.0.1:18080/api/v1/namespaces/%s/endpoints?watch=true", namespace)
}

func buildLabelSelector(selector map[string]string) string {
	if len(selector) == 0 {
		return ""
	}
	var parts []string
	for k, v := range selector {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}

func appendLabelSelector(baseURL string, selector map[string]string) string {
	labelSel := buildLabelSelector(selector)
	if labelSel == "" {
		return baseURL
	}
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return baseURL + sep + "labelSelector=" + url.QueryEscape(labelSel)
}

func (kc *K8sClient) parseEndpointsResponse(body []byte) ([]K8sEndpoints, error) {
	var response struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Subsets []struct {
				Addresses []struct {
					IP        string            `json:"ip"`
					TargetRef map[string]string `json:"targetRef"`
				} `json:"addresses"`
				Ports []struct {
					Port int    `json:"port"`
					Name string `json:"name"`
				} `json:"ports"`
			} `json:"subsets"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var endpoints []K8sEndpoints
	log.Info().Msgf("[K8sClient] parseEndpointsResponse: found %d items", len(response.Items))
	for _, item := range response.Items {
		log.Info().Msgf("[K8sClient]   item=%s, subsets=%d", item.Metadata.Name, len(item.Subsets))
		for _, subset := range item.Subsets {
			var addrs []K8sEndpointAddress
			for _, addr := range subset.Addresses {
				addrs = append(addrs, K8sEndpointAddress{
					IP:        addr.IP,
					Port:      0, // Port will come from Ports array
					TargetRef: addr.TargetRef,
				})
			}
			var ports []K8sEndpointPort
			for _, port := range subset.Ports {
				ports = append(ports, K8sEndpointPort{
					Port: port.Port,
					Name: port.Name,
				})
			}
			ep := K8sEndpoints{
				Name:      item.Metadata.Name,
				Namespace: item.Metadata.Namespace,
				Labels:    item.Metadata.Labels,
				Addresses: addrs,
				Ports:     ports,
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

func (kc *K8sClient) ListEndpoints(ctx context.Context, namespace string, labelSelector map[string]string) ([]K8sEndpoints, error) {
	kc.mu.RLock()
	initialized := kc.initialized
	kc.mu.RUnlock()

	if !initialized {
		if err := kc.init(); err != nil {
			return nil, fmt.Errorf("k8s client not initialized: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, kc.timeout)
	defer cancel()

	if namespace == "" {
		namespace = kc.namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	log.Debug().Msgf("[K8sClient] ListEndpoints: namespace=%s, selector=%v", namespace, labelSelector)

	url := appendLabelSelector(kc.getEndpointsURL(namespace), labelSelector)
	log.Info().Msgf("[K8sClient] ListEndpoints: requesting URL=%s", url)
	body, err := kc.doRequest(ctx, url)
	if err != nil {
		log.Warn().Msgf("[K8sClient] ListEndpoints failed: %v", err)
		return nil, err
	}
	log.Info().Msgf("[K8sClient] ListEndpoints: received %d bytes", len(body))

	endpoints, err := kc.parseEndpointsResponse(body)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("[K8sClient] ListEndpoints: found %d endpoints", len(endpoints))
	return endpoints, nil
}

func (kc *K8sClient) WatchEndpoints(ctx context.Context, namespace string, labelSelector map[string]string) (<-chan K8sEndpointsEvent, error) {
	kc.mu.RLock()
	initialized := kc.initialized
	kc.mu.RUnlock()

	if !initialized {
		if err := kc.init(); err != nil {
			return nil, fmt.Errorf("k8s client not initialized: %w", err)
		}
	}

	if namespace == "" {
		namespace = kc.namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	log.Debug().Msgf("[K8sClient] WatchEndpoints: namespace=%s, selector=%v", namespace, labelSelector)

	eventCh := make(chan K8sEndpointsEvent, 100)

	go func() {
		defer close(eventCh)

		url := appendLabelSelector(kc.getWatchURL(namespace), labelSelector)
		log.Info().Msgf("[K8sClient] WatchEndpoints: streaming URL=%s", url)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Error().Msgf("[K8sClient] WatchEndpoints: failed to create request: %v", err)
			return
		}

		resp, err := kc.httpClient.Do(req)
		if err != nil {
			log.Warn().Msgf("[K8sClient] WatchEndpoints: failed to connect: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			log.Error().Msgf("[K8sClient] WatchEndpoints: unexpected status %d: %s", resp.StatusCode, string(body))
			return
		}

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
			if len(line) == 0 {
				if err == io.EOF {
					break
				}
				continue
			}

			if err != nil {
				if err == io.EOF {
					break
				}
				log.Warn().Msgf("[K8sClient] WatchEndpoints: read error: %v", err)
				break
			}

			var watchEvent struct {
				Type   string `json:"type"`
				Object struct {
					Metadata struct {
						Name            string            `json:"name"`
						Namespace       string            `json:"namespace"`
						ResourceVersion string            `json:"resourceVersion"`
						Labels          map[string]string `json:"labels"`
					} `json:"metadata"`
					Subsets []struct {
						Addresses []struct {
							IP        string            `json:"ip"`
							TargetRef map[string]string `json:"targetRef"`
						} `json:"addresses"`
						Ports []struct {
							Port int    `json:"port"`
							Name string `json:"name"`
						} `json:"ports"`
					} `json:"subsets"`
				} `json:"object"`
			}

			if err := json.Unmarshal(line, &watchEvent); err != nil {
				log.Warn().Msgf("[K8sClient] WatchEndpoints: parse event failed: %v, line: %s", err, string(line))
				continue
			}

			var eventType WatchEventType
			switch watchEvent.Type {
			case "ADDED":
				eventType = WatchEventAdd
			case "MODIFIED":
				eventType = WatchEventModify
			case "DELETED":
				eventType = WatchEventDelete
			default:
				log.Debug().Msgf("[K8sClient] WatchEndpoints: unknown event type: %s", watchEvent.Type)
				continue
			}

			for _, subset := range watchEvent.Object.Subsets {
				var addrs []K8sEndpointAddress
				for _, addr := range subset.Addresses {
					addrs = append(addrs, K8sEndpointAddress{
						IP:        addr.IP,
						Port:      0,
						TargetRef: addr.TargetRef,
					})
				}
				var ports []K8sEndpointPort
				for _, port := range subset.Ports {
					ports = append(ports, K8sEndpointPort{
						Port: port.Port,
						Name: port.Name,
					})
				}

				ep := K8sEndpoints{
					Name:      watchEvent.Object.Metadata.Name,
					Namespace: watchEvent.Object.Metadata.Namespace,
					Labels:    watchEvent.Object.Metadata.Labels,
					Addresses: addrs,
					Ports:     ports,
				}

				select {
				case eventCh <- K8sEndpointsEvent{Type: eventType, Endpoints: ep}:
					log.Debug().Msgf("[K8sClient] WatchEndpoints: sent event type=%s, endpoint=%s", watchEvent.Type, ep.Name)
				case <-ctx.Done():
					log.Debug().Msg("[K8sClient] WatchEndpoints: context cancelled")
					return
				case <-time.After(5 * time.Second):
					log.Warn().Msgf("[K8sClient] WatchEndpoints: channel send timeout for endpoint=%s", ep.Name)
				}
			}
		}
		log.Info().Msg("[K8sClient] WatchEndpoints: stream ended")
	}()

	return eventCh, nil
}

func (kc *K8sClient) Close() error {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	if !kc.initialized {
		return nil
	}

	log.Info().Msg("[K8sClient] closing client")
	kc.initialized = false
	return nil
}

func (kc *K8sClient) IsInitialized() bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.initialized
}

func (kc *K8sClient) SetInitialized(initialized bool) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.initialized = initialized
}
