/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.engine;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.util.AddressUtils;

public class RouteLookupEngine {

    private static final Logger LOG = new Logger(RouteLookupEngine.class);

    public RoutingEntry lookup(String targetAddr, Map<RoutePrefix, RoutingEntry> routes,
                               List<Integer> maskLengths) {
        LOG.debug("lookup: targetAddr=" + targetAddr
            + ", maskLengthsCount=" + (maskLengths != null ? maskLengths.size() : 0)
            + ", routesCount=" + (routes != null ? routes.size() : 0));
        if (routes == null || routes.isEmpty()) {
            LOG.warn("lookup: warning=routes is null or empty, result=null");
            return null;
        }
        if (maskLengths == null) {
            LOG.warn("lookup: warning=maskLengths is null, result=null");
            return null;
        }

        for (int maskLen : maskLengths) {
            String networkAddr = AddressUtils.applyMask(targetAddr, maskLen);
            RoutePrefix prefix = new RoutePrefix(networkAddr, maskLen);
            RoutingEntry entry = routes.get(prefix);
            if (entry != null) {
                LOG.debug("lookup: found route, mask=" + maskLen + ", prefix=" + prefix);
                return entry;
            }
        }

        RoutePrefix defaultPrefix = new RoutePrefix("0.0.0.0", 0);
        if (!maskLengths.contains(0)) {
            RoutingEntry entry = routes.get(defaultPrefix);
            if (entry != null) {
                LOG.debug("lookup: found default route (0.0.0.0/0)");
                return entry;
            }
        }

        LOG.warn("lookup: warning=no route found, targetAddr=" + targetAddr);
        return null;
    }
}
