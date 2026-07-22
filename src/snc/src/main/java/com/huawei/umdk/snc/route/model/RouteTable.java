/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route description
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.model;

import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import lombok.Getter;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;

@Getter
public class RouteTable {
    @NonNull
    private final Map<Prefix, RouteEntry> routeEntries = new HashMap<>();
}
