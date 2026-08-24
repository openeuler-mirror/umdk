/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildLabelSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector map[string]string
		want     string
	}{
		{"empty", map[string]string{}, ""},
		{"single", map[string]string{"app": "vllm"}, "app=vllm"},
		{"multiple", map[string]string{"a": "1", "b": "2"}, "a=1,b=2"},
		{"with special chars", map[string]string{"app": "vllm-router"}, "app=vllm-router"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLabelSelector(tt.selector)
			if tt.name == "multiple" {
				if got != "a=1,b=2" && got != "b=2,a=1" {
					t.Errorf("buildLabelSelector() = %q, want one of [a=1,b=2, b=2,a=1]", got)
				}
			} else if got != tt.want {
				t.Errorf("buildLabelSelector() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppendLabelSelector(t *testing.T) {
	baseURL := "http://localhost:8080/api/v1/namespaces/default/endpoints"

	tests := []struct {
		name     string
		url      string
		selector map[string]string
		want     string
	}{
		{"no selector", baseURL, map[string]string{}, baseURL},
		{"single selector", baseURL, map[string]string{"app": "vllm"}, baseURL + "?labelSelector=app%3Dvllm"},
		{"multiple selectors", baseURL, map[string]string{"app": "vllm", "role": "prefill"}, baseURL + "?labelSelector=app%3Dvllm%2Crole%3Dprefill"},
		{"with existing query", "http://localhost?existing=1", map[string]string{"app": "vllm"}, "http://localhost?existing=1&labelSelector=app%3Dvllm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendLabelSelector(tt.url, tt.selector)
			if got != tt.want {
				t.Errorf("appendLabelSelector() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestK8sClient_ListEndpoints(t *testing.T) {
	t.Run("successful list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/namespaces/default/endpoints" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			resp := `{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"12345"},"items":[{
				"metadata":{"name":"vllm-svc","namespace":"default","labels":{"app":"vllm","role":"prefill"}},
				"subsets":[{
					"addresses":[{"ip":"10.0.0.1","targetRef":{"kind":"Pod"}}],
					"ports":[{"port":8000,"name":"http"}]
				}]
			}]}`
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resp))
		}))
		defer server.Close()

		client := &K8sClient{
			baseURL:     server.URL,
			namespace:   "default",
			timeout:     30 * time.Second,
			initialized: true,
			httpClient:  server.Client(),
		}

		instances, err := client.ListEndpoints(context.Background(), "default", map[string]string{"app": "vllm"})
		if err != nil {
			t.Fatalf("ListEndpoints failed: %v", err)
		}
		if len(instances) != 1 {
			t.Fatalf("expected 1 endpoint, got %d", len(instances))
		}
		if instances[0].Name != "vllm-svc" {
			t.Errorf("expected name vllm-svc, got %s", instances[0].Name)
		}
		if instances[0].Addresses[0].IP != "10.0.0.1" {
			t.Errorf("expected IP 10.0.0.1, got %s", instances[0].Addresses[0].IP)
		}
	})

	t.Run("with label selector applied", func(t *testing.T) {
		var receivedURL string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedURL = r.URL.RequestURI()
			resp := `{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"12345"},"items":[]}`
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resp))
		}))
		defer server.Close()

		client := &K8sClient{
			baseURL:     server.URL,
			namespace:   "default",
			timeout:     30 * time.Second,
			initialized: true,
			httpClient:  server.Client(),
		}

		client.ListEndpoints(context.Background(), "default", map[string]string{"role": "prefill", "app": "vllm"})

		if receivedURL == "" {
			t.Fatal("no request was made")
		}
		expected := "/api/v1/namespaces/default/endpoints?labelSelector=role%3Dprefill%2Capp%3Dvllm"
		if receivedURL != expected {
			t.Errorf("expected URL %q, got %q", expected, receivedURL)
		}
	})
}

func TestK8sClient_WatchEndpoints_Streaming(t *testing.T) {
	t.Run("streams watch events correctly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("watch") != "true" {
				t.Errorf("expected watch=true, got %s", r.URL.RawQuery)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("expected http.Flusher")
			}

			events := []map[string]interface{}{
				{"type": "ADDED", "object": map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":            "vllm-svc",
						"namespace":       "default",
						"resourceVersion": "12345",
						"labels":          map[string]string{"app": "vllm"},
					},
					"subsets": []map[string]interface{}{
						{
							"addresses": []map[string]interface{}{{"ip": "10.0.0.1", "targetRef": map[string]string{"kind": "Pod"}}},
							"ports":     []map[string]interface{}{{"port": 8000, "name": "http"}},
						},
					},
				}},
				{"type": "MODIFIED", "object": map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":            "vllm-svc",
						"namespace":       "default",
						"resourceVersion": "12346",
						"labels":          map[string]string{"app": "vllm"},
					},
					"subsets": []map[string]interface{}{
						{
							"addresses": []map[string]interface{}{{"ip": "10.0.0.2", "targetRef": map[string]string{"kind": "Pod"}}},
							"ports":     []map[string]interface{}{{"port": 8000, "name": "http"}},
						},
					},
				}},
			}

			for _, e := range events {
				data, _ := json.Marshal(e)
				w.Write(data)
				w.Write([]byte("\n"))
				flusher.Flush()
			}
		}))
		defer server.Close()

		client := &K8sClient{
			baseURL:     server.URL,
			namespace:   "default",
			timeout:     30 * time.Second,
			initialized: true,
			httpClient:  server.Client(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		eventCh, err := client.WatchEndpoints(ctx, "default", nil)
		if err != nil {
			t.Fatalf("WatchEndpoints failed: %v", err)
		}

		var receivedEvents []K8sEndpointsEvent
		for event := range eventCh {
			receivedEvents = append(receivedEvents, event)
			if len(receivedEvents) >= 2 {
				cancel()
			}
		}

		if len(receivedEvents) != 2 {
			t.Errorf("expected 2 events, got %d", len(receivedEvents))
		}
		if receivedEvents[0].Type != WatchEventAdd {
			t.Errorf("expected ADD event, got %v", receivedEvents[0].Type)
		}
		if receivedEvents[1].Type != WatchEventModify {
			t.Errorf("expected MODIFY event, got %v", receivedEvents[1].Type)
		}
		if receivedEvents[0].Endpoints.Name != "vllm-svc" {
			t.Errorf("expected endpoint name vllm-svc, got %s", receivedEvents[0].Endpoints.Name)
		}
	})

	t.Run("handles DELETE events", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("expected http.Flusher")
			}

			event := map[string]interface{}{
				"type": "DELETED",
				"object": map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":            "vllm-svc",
						"namespace":       "default",
						"resourceVersion": "12347",
						"labels":          map[string]string{"app": "vllm"},
					},
					"subsets": []map[string]interface{}{
						{
							"addresses": []map[string]interface{}{{"ip": "10.0.0.1"}},
							"ports":     []map[string]interface{}{{"port": 8000}},
						},
					},
				},
			}
			data, _ := json.Marshal(event)
			w.Write(data)
			w.Write([]byte("\n"))
			flusher.Flush()
		}))
		defer server.Close()

		client := &K8sClient{
			baseURL:     server.URL,
			namespace:   "default",
			timeout:     30 * time.Second,
			initialized: true,
			httpClient:  server.Client(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		eventCh, err := client.WatchEndpoints(ctx, "default", nil)
		if err != nil {
			t.Fatalf("WatchEndpoints failed: %v", err)
		}

		event := <-eventCh
		if event.Type != WatchEventDelete {
			t.Errorf("expected DELETE event, got %v", event.Type)
		}
	})
}

func TestK8sClient_WatchEndpoints_LabelSelector(t *testing.T) {
	var receivedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("\n"))
	}))
	defer server.Close()

	client := &K8sClient{
		baseURL:     server.URL,
		namespace:   "default",
		timeout:     30 * time.Second,
		initialized: true,
		httpClient:  server.Client(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventCh, err := client.WatchEndpoints(ctx, "default", map[string]string{"role": "decode"})
	if err != nil {
		t.Fatalf("WatchEndpoints failed: %v", err)
	}
	<-eventCh

	if receivedURL == "" {
		t.Fatal("no request was made")
	}
	expectedPath := "/api/v1/namespaces/default/endpoints?watch=true&labelSelector=role%3Ddecode"
	if receivedURL != expectedPath {
		t.Errorf("expected URL %q, got %q", expectedPath, receivedURL)
	}
}

func TestK8sClient_Close(t *testing.T) {
	client := &K8sClient{
		initialized: true,
	}
	err := client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
	if client.initialized {
		t.Error("expected initialized=false after Close")
	}
}

func TestK8sEndpoints_Parsing(t *testing.T) {
	body := []byte(`{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"999"},
"items":[{
  "metadata":{"name":"vllm-svc","namespace":"default","labels":{"app":"vllm","role":"prefill","dp-rank":"0"}},
  "subsets":[{
    "addresses":[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}],
    "ports":[{"port":8000,"name":"http"},{"port":8001,"name":"metrics"}]
  }]
}]}`)

	client := &K8sClient{initialized: true}
	endpoints, err := client.parseEndpointsResponse(body)
	if err != nil {
		t.Fatalf("parseEndpointsResponse failed: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Name != "vllm-svc" {
		t.Errorf("expected name vllm-svc, got %s", ep.Name)
	}
	if ep.Namespace != "default" {
		t.Errorf("expected namespace default, got %s", ep.Namespace)
	}
	if len(ep.Labels) != 3 {
		t.Errorf("expected 3 labels, got %d", len(ep.Labels))
	}
	if ep.Labels["app"] != "vllm" {
		t.Errorf("expected label app=vllm, got %s", ep.Labels["app"])
	}
	if len(ep.Addresses) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(ep.Addresses))
	}
	if ep.Addresses[0].IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", ep.Addresses[0].IP)
	}
	if len(ep.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ep.Ports))
	}
	if ep.Ports[0].Port != 8000 {
		t.Errorf("expected port 8000, got %d", ep.Ports[0].Port)
	}
}