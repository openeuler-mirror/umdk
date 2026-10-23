/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: converged routes
 * Create: 2026-10-23
 * Note:
 * History: 2026-10-23  Create File
 */
package com.huawei.umdk.snc.entity;

import java.util.LinkedHashMap;
import java.util.Map;

import lombok.Data;

/**
 * 切流收敛结果：本次切流中影响设备的路由明细集合。
 * key = 设备名称，value = 该设备的收敛配置（各出接口的前缀明细）。
 * 无路由受影响时 changes 为空 Map，不作为失败。
 */
@Data
public class ConvergedRouteResult {
    private final Map<String, ConvergedNodeRoute> routeMap;

    public ConvergedRouteResult() {
        this.routeMap = new LinkedHashMap<>();
    }

    public ConvergedRouteResult(Map<String, ConvergedNodeRoute> changes) {
        this.routeMap = changes != null ? changes : new LinkedHashMap<>();
    }
}