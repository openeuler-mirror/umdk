/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import java.util.Collections;
import java.util.List;
import java.util.Map;
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
public class RoutingTable {
    private String deviceName;
    private Integer chipIndex;
    private Map<RoutePrefix, RoutingEntry> routes;
    private List<Integer> maskLengths;

    public Map<RoutePrefix, RoutingEntry> getRoutes() {
        return routes == null ? null : Collections.unmodifiableMap(routes);
    }

    public List<Integer> getMaskLengths() {
        return maskLengths == null ? null : Collections.unmodifiableList(maskLengths);
    }
}
