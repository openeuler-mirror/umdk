/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: define the functions of central cache.
 * Create: 2026-01-20
 */

// Package cachecenter implements metadata operations using Redis via injected CacheDriverOps.
package cachecenter

import (
	"fmt"
)

// Constants for Redis keys prefix
const (
	// InstanceRequestInfo stores request info for a specific instance
	InstanceRequestInfo = "model:%s:instance:%s:requests_info"
)

// CacheDriverOps defines function pointers for operation on a Redis-like database
type CacheDriverOps struct {
	HGetAll      func(key string) (map[string]string, error)
	HSet         func(key string, fields map[string]string, ttl int) error
	HDel         func(key string, fields ...string) error
	HGetAllBatch func(keys []string) ([]map[string]string, error)
}

// RedisCacheCenter uses injected Redis operations to manage metadata
type RedisCacheCenter struct {
	ops    *CacheDriverOps
	reqTtl int // the survival duration for request in remote db, unit is second
}

// NewRedisCacheCenter creates a new RedisCacheCenter with injected Redis operations
func NewRedisCacheCenter(ops *CacheDriverOps, reqTtl int) *RedisCacheCenter {
	return &RedisCacheCenter{
		reqTtl: reqTtl,
		ops:    ops,
	}
}

// AddRequest adds a request with the given ID and info to an instance.
func (r *RedisCacheCenter) AddRequest(modelName string, instanceID string, infos []*RequestInfo) error {
	if len(infos) == 0 {
		return fmt.Errorf("add request failed: empty RequestInfo list")
	}
	key := r.instanceRequestsInfoKey(modelName, instanceID)
	value := make(map[string]string)
	for _, info := range infos {
		value[info.ReqId] = info.StringWithoutId()
	}

	if err := r.ops.HSet(key, value, r.reqTtl); err != nil {
		return fmt.Errorf("add request failed for model %s instance %s: failed to HSet requests info: %v",
			modelName, instanceID, err)
	}

	return nil
}

// RemoveRequest removes a request from an instance by request ID.
func (r *RedisCacheCenter) RemoveRequest(modelName, instanceID string, infos []*RequestInfo) error {
	if len(infos) == 0 {
		return fmt.Errorf("remove request failed: empty RequestInfo list")
	}
	key := r.instanceRequestsInfoKey(modelName, instanceID)
	var requestIds []string
	for _, info := range infos {
		requestIds = append(requestIds, info.ReqId)
	}

	if err := r.ops.HDel(key, requestIds...); err != nil {
		return fmt.Errorf("remove request failed for model %s: failed to delete metadata for requests %v: %v",
			modelName, requestIds, err)
	}

	return nil
}

// UpdateRequest update a request's info
func (r *RedisCacheCenter) UpdateRequest(modelName, instanceID string, infos []*RequestInfo) error {
	if len(infos) == 0 {
		return fmt.Errorf("update request failed: empty RequestInfo list")
	}
	key := r.instanceRequestsInfoKey(modelName, instanceID)
	value := make(map[string]string)
	for _, info := range infos {
		value[info.ReqId] = info.StringWithoutId()
	}

	if err := r.ops.HSet(key, value, r.reqTtl); err != nil {
		return fmt.Errorf("update request failed for model %s instance %s: failed to HSet requests info: %v",
			modelName, instanceID, err)
	}

	return nil
}

// FetchRequestsInfoByInstance retrieves all request information for a specific instance
func (r *RedisCacheCenter) FetchRequestsInfoByInstance(modelName, instanceID string) (map[string]string, error) {
	key := r.instanceRequestsInfoKey(modelName, instanceID)
	requestMetric, err := r.ops.HGetAll(key)
	if err != nil {
		return nil, fmt.Errorf("fetch requestsInfo failed for model %s instance %s: failed to HGetAll requests info: %v",
			modelName, instanceID, err)
	}
	return requestMetric, nil
}

// FetchAllInstanceRequests retrieves all request information for all instances of a model
// This method uses batch or concurrent reads to optimize performance
func (r *RedisCacheCenter) FetchAllInstanceRequests(modelName string, instanceIDs []string) (
	map[string]map[string]string, error) {
	if len(instanceIDs) == 0 {
		return make(map[string]map[string]string), nil
	}

	// Build keys for all instances
	keys := make([]string, 0, len(instanceIDs))
	for _, instanceID := range instanceIDs {
		keys = append(keys, r.instanceRequestsInfoKey(modelName, instanceID))
	}

	results, err := r.ops.HGetAllBatch(keys)
	if err != nil {
		return nil, fmt.Errorf("fetch all instance requests failed for model %s: %v", modelName, err)
	}

	// Map results back to instance IDs
	instanceRequests := make(map[string]map[string]string)
	for i, result := range results {
		if len(result) > 0 {
			instanceRequests[instanceIDs[i]] = result
		}
	}
	return instanceRequests, nil
}

func (r *RedisCacheCenter) instanceRequestsInfoKey(modelName, instanceID string) string {
	return fmt.Sprintf(InstanceRequestInfo, modelName, instanceID)
}
