/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: define the functions of central cache.
 * Create: 2026-01-20
 */

// Package cachecenter provides functions of cachecenter for AIGW.
package cachecenter

// Constants for Redis keys prefix

// CentralCache manages metadata and metrics related to instances and requests.
type CentralCache interface {
	// AddRequest adds a request with the given ID and info to an instance.
	AddRequest(modelName string, instanceID string, infos []*RequestInfo) error

	// RemoveRequest removes a request from an instance by request ID.
	RemoveRequest(modelName, instanceID string, infos []*RequestInfo) error

	// UpdateRequest update a request's information
	UpdateRequest(modelName, instanceID string, infos []*RequestInfo) error

	// FetchRequestsInfoByInstance retrieves all request information for a specific instance
	FetchRequestsInfoByInstance(modelName, instanceID string) (map[string]string, error)

	// FetchAllInstanceRequests retrieves all request information for all instances of a model
	FetchAllInstanceRequests(modelName string, instanceIDs []string) (map[string]map[string]string, error)
}
