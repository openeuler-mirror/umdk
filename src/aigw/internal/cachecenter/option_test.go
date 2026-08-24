/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Unit tests for cache manager options.
 * Create: 2026-03-11
 */

package cachecenter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestWithRemoteCache tests the WithRemoteCache option
func TestWithRemoteCache(t *testing.T) {
	mockCache := &mockCentralCache{}
	cm := NewCacheManager(context.Background(), "test-model", WithRemoteCache(mockCache))

	assert.NotNil(t, cm.remoteCache)
	assert.Equal(t, mockCache, cm.remoteCache)
}

// TestWithRefreshInterval_Valid tests setting a valid refresh interval
func TestWithRefreshInterval_Valid(t *testing.T) {
	cm := NewCacheManager(context.Background(), "test-model", WithRefreshInterval(500))

	expectedInterval := 500 * time.Millisecond
	assert.Equal(t, expectedInterval, cm.refreshInterval)
}

// TestWithRefreshInterval_Zero tests that zero interval uses default
func TestWithRefreshInterval_Zero(t *testing.T) {
	cm := NewCacheManager(context.Background(), "test-model", WithRefreshInterval(0))

	assert.Equal(t, defaultRefreshInterval, cm.refreshInterval)
}

// mockCentralCache is a mock implementation of CentralCache for testing
type mockCentralCache struct{}

func (m *mockCentralCache) AddRequest(modelName string, instanceID string, infos []*RequestInfo) error {
	return nil
}

func (m *mockCentralCache) RemoveRequest(modelName, instanceID string, infos []*RequestInfo) error {
	return nil
}

func (m *mockCentralCache) UpdateRequest(modelName, instanceID string, infos []*RequestInfo) error {
	return nil
}

func (m *mockCentralCache) FetchRequestsInfoByInstance(modelName, instanceID string) (map[string]string, error) {
	return nil, nil
}

func (m *mockCentralCache) FetchAllInstanceRequests(modelName string, instanceIDs []string) (
	map[string]map[string]string, error) {
	return nil, nil
}
