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
 * Link layer of a coverage link, used to group out-ports into the NPU↔L1SW or
 * the L1SW↔L2SW segment.
 *
 * <p>The direction is not encoded here; it is derived from the device types at
 * both ends of the link: the owner being an NPU means NPU→L1SW, while an L1SW
 * owner with an NPU peer means L1SW→NPU.
 */
public enum CoverageLinkLayer {
    /** NPU↔L1SW (NPU uplink out-port, or L1SW out-port facing an NPU). */
    NPU_L1,

    /** L1SW↔L2SW. */
    L1_L2
}
