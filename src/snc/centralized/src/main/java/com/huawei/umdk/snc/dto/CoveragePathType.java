/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-09-13
 * Note:
 * History: 2026-09-13  Create File; 2026-09-17 rename to layer-based naming
 */
package com.huawei.umdk.snc.dto;

/**
 * Type of the path used by one EID pair of the extended coverage planning,
 * described by the forwarding layers the path traverses (NPU / L1 / L2),
 * independent of any physical chassis concept.
 *
 * <p>The extended planning runs in two phases:
 * <ol>
 *   <li>{@link #CROSS_L2} — paths that traverse the L2SW spine
 *       {@code NPU -> L1SW -> L2SW -> L1SW -> NPU}, which fully cover the
 *       L1SW&harr;L2SW segment. In a rack-based topology this corresponds to
 *       the inter-chassis (框间) scenario.</li>
 *   <li>{@link #LOCAL_L1} — paths that stay inside one L1SW domain
 *       {@code NPU -> L1SW -> NPU} (no L2SW hop), used afterwards to cover
 *       the NPU&harr;L1SW out-ports that the {@code CROSS_L2} phase left
 *       uncovered. In a rack-based topology this corresponds to the
 *       intra-chassis (框内) scenario.</li>
 * </ol>
 */
public enum CoveragePathType {
    /** Path traverses the L2SW layer: {@code NPU -> L1SW -> L2SW -> L1SW -> NPU}. */
    CROSS_L2,

    /** Path stays within one L1SW domain: {@code NPU -> L1SW -> NPU} (no L2SW hop). */
    LOCAL_L1
}
