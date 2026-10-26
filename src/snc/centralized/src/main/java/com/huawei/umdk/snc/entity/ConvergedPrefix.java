/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route prefix
 * Create: 2026-10-23
 * Note:
 * History: 2026-10-23  Create File
 */

package com.huawei.umdk.snc.entity;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ConvergedPrefix {
    private boolean allConverged;

    private List<RoutePrefix> routePrefixList = new ArrayList<>();
}
