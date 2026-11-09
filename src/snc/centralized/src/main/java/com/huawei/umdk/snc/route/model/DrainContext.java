/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: drain context
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.entity.ConvergedNodeRoute;
import com.huawei.umdk.snc.entity.SuperNode;
import lombok.Data;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

/**
 * 一次切流的上下文：承载整个计算与传播过程中不变的输入、去重状态与结果收集。
 */
@Data
public class DrainContext {
    private SuperNode supernode;

    /** 本次切流动作（enable/disable）。 */
    private String action;

    /** 已通告的芯片级方向（from→to#prefix），防止重复通告。 */
    private Set<String> notified = new HashSet<>();

    /** 待处理的通告任务队列。 */
    private Queue<NoticeTask> queue = new LinkedList<>();

    /** 收敛明细收集：key = 设备名称，value = 该设备各出接口的前缀明细 */
    private Map<String, ConvergedNodeRoute> changeMap = new LinkedHashMap<>();

    private Map<String, ConvergedNodeRoute> noticeMap = new LinkedHashMap<>();

    public DrainContext(SuperNode supernode, String action) {
        this.supernode = supernode;
        this.action = action;
    }
}
