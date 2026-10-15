/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-08-18 replace active with convergedFlag
 */
package com.huawei.umdk.snc.entity;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class OutPortInfo {
    /**
     * 被动收敛：由 link 事件触发（端口 up/down）。
     */
    public static final int FLAG_PASSIVE_CONVERRGED = 1 << 0;

    /**
     * 主动收敛：由主动操作触发（如运维下发、策略变更）。
     */
    public static final int FLAG_ACTIVE_CONVERRGED = 1 << 1;

    private String portName;
    private String nextHop;
    private Integer preference;
    private Integer tag;
    private String protocol;
    private int convergedFlag;

    /**
     * 判断该出端口是否处于任意收敛状态（即不再用于转发）。
     */
    public boolean isConverged() {
        return convergedFlag != 0;
    }

    /**
     * 在 convergedFlag 上按位或指定 flag，不影响其它位。
     */
    public void setFlag(int flag) {
        this.convergedFlag |= flag;
    }

    /**
     * 在 convergedFlag 上清掉指定 flag，保留其它位。
     */
    public void clearFlag(int flag) {
        this.convergedFlag &= ~flag;
    }
}
