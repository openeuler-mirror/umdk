/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: merge notice info
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.entity.RoutePrefix;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 同层合并后的芯片级通告批次：同一轮从队列取出、发往同一芯片的全部NoticeTask按地址前缀合并的结果。
 * 合并目的：把一个芯片的数据合并到一起统一处理，避免同一芯片被多个任务先后处理产生错误结果
 */
@Data
public class MergedNotice {
    private ChipRef chip;
    /** 前缀 → 该前缀合并后的入接口与通告来源芯片 */
    private Map<RoutePrefix, MergedPrefix> prefixes = new LinkedHashMap<>();

    public MergedNotice(ChipRef chip) {
        this.chip = chip;
    }

    public void merge(NoticeTask task) {
        String fromChipKey = task.getFromChip().routeKey();
        for (RoutePrefix prefix : task.getPrefixes()) {
            prefixes.computeIfAbsent(prefix, k -> new MergedPrefix())
                .merge(task.getInPorts(), fromChipKey);
        }
    }
}
