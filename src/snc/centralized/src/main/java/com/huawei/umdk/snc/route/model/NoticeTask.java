/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: notice task
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */
package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.entity.RoutePrefix;
import lombok.Data;

import java.util.Set;

/**
 * 芯片级通告任务
 */
@Data
public class NoticeTask {
    private ChipRef fromChip;
    private ChipRef toChip;
    private Set<String> inPorts;
    private Set<RoutePrefix> prefixes;

    public NoticeTask(ChipRef fromChip, ChipRef toChip,
               Set<String> inPorts, Set<RoutePrefix> prefixes) {
        this.fromChip = fromChip;
        this.toChip = toChip;
        this.inPorts = inPorts;
        this.prefixes = prefixes;
    }
}
