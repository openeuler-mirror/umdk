/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.dto;

/**
 * 覆盖规划的覆盖要求（每链路最少覆盖次数）。
 *
 * <p>该枚举表达调用方的覆盖质量需求，而非具体算法；默认值为
 * {@link #MIN_COVERAGE}。
 */
public enum CoverageRequirement {
    /** 每条链路至少被覆盖 1 次（最小覆盖），倾向用尽量少的 EID pair 完成全覆盖（Phase 2 默认行为）。 */
    MIN_COVERAGE,

    /**
     * 每条链路至少被 ≥2 个 EID pair 覆盖（冗余），用于 RTT 故障隔离：
     * 当某个 EID pair 的 RTT 异常时，可用另一共享该 link 的 pair 做对照，
     * 隔离问题是出在 link、EID 端、还是 path 上其他 link。
     * 以「每条 link 覆盖 ≥2」为目标选 pair，打分带 EID/机框公平惩罚，
     * 选完后再裁剪冗余 pair 压低 EID 重复次数。
     */
    REDUNDANT;
}
