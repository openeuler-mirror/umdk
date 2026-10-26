/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: structure related to topology definition
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.model;

import lombok.Getter;

@Getter
public enum AddrType {
    NODE_ADDR(1),
    PORT_ADDR(2),
    BONDING_ADDR(3),
    PORT_GROUP_ADDR(4),
    PREFIX_ADDR(5),
    EXTERNAL_PORT_ADDR(6),
    INTERNAL_PORT_ADDR(7),
    AGGREGATE_ADDR(8),
    ALL(9);

    private final int value;

    AddrType(int value) {
        this.value = value;
    }

    public static boolean isNodeAddress(AddrType addrTypeEnum) {
        return addrTypeEnum == NODE_ADDR || addrTypeEnum == AGGREGATE_ADDR;
    }

    public static AddrType getAddrType(String addrDescription) {
        AddrType addrType = null;
        if (addrDescription == null) {
            return addrType;
        }

        switch (addrDescription) {
            case "Node":
                addrType = NODE_ADDR;
                break;
            case "Port":
                addrType = PORT_ADDR;
                break;
            case "Bond":
                addrType = BONDING_ADDR;
                break;
            case "PG":
                addrType = PORT_GROUP_ADDR;
                break;
            case "Prefix":
                addrType = PREFIX_ADDR;
                break;
            case "ExternalPort":
                addrType = EXTERNAL_PORT_ADDR;
                break;
            case "InternalPort":
                addrType = INTERNAL_PORT_ADDR;
                break;
            case "Aggregate":
                addrType = AGGREGATE_ADDR;
                break;
            case "All":
                addrType = ALL;
                break;
            default:
                break;
        }

        return addrType;
    }
}
