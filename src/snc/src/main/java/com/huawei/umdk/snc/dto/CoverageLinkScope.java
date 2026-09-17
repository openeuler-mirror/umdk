/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File
 */
package com.huawei.umdk.snc.dto;

/**
 * Coverage link scope (coverage link universe) of a coverage-planning call.
 */
public enum CoverageLinkScope {
    /**
     * L1SW↔L2SW out-ports only — the scope of the original
     * {@code planPathsCoverage} interface.
     */
    L1_L2,

    /**
     * NPU↔L1SW plus L1SW↔L2SW out-ports — the scope of the extended
     * {@code planPathsCoverageEx} interface, which additionally hashes the
     * NPU→L1SW egress port with the {@code (DstCNA, jettyId)} two-tuple.
     */
    NPU_L1_L2
}
