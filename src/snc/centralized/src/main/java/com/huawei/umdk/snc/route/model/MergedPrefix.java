/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: merge prefix
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.model;

import lombok.Data;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 单个地址前缀的合并结果：入接口并集与通告来源芯片并集（作为继续通告时的回传保护排除方向）。
 */
@Data
public class MergedPrefix {
    private Set<String> inPorts = new LinkedHashSet<>();
    private Set<String> fromChips = new LinkedHashSet<>();

    public void merge(Set<String> inPorts, String fromChipKey) {
        this.inPorts.addAll(inPorts);
        this.fromChips.add(fromChipKey);
    }
}
