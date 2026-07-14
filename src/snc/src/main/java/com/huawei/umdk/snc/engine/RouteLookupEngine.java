/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.engine;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.util.AddressUtils;

public class RouteLookupEngine {

    public RoutingEntry lookup(String targetAddr, Map<RoutePrefix, RoutingEntry> routes,
                               List<Integer> maskLengths) {
        if (routes == null || routes.isEmpty()) {
            return null;
        }
        if (maskLengths == null) {
            return null;
        }

        for (int maskLen : maskLengths) {
            String networkAddr = AddressUtils.applyMask(targetAddr, maskLen);
            RoutePrefix prefix = new RoutePrefix(networkAddr, maskLen);
            RoutingEntry entry = routes.get(prefix);
            if (entry != null) {
                return entry;
            }
        }

        RoutePrefix defaultPrefix = new RoutePrefix("0.0.0.0", 0);
        if (!maskLengths.contains(0)) {
            RoutingEntry entry = routes.get(defaultPrefix);
            if (entry != null) {
                return entry;
            }
        }

        return null;
    }
}
