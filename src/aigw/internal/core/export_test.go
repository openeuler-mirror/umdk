/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

package core

import "huawei.com/aigw/internal/apipool"

// ApiPoolStateForTest exposes the shared provider-pool State for integration tests
// (cross-pool quota assertions). Test-only: lives in a _test.go file.
func (manager *AigwManager) ApiPoolStateForTest() *apipool.State {
	return manager.apiPoolState
}
