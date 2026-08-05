/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-29
 * Note:
 */

package com.huawei.umdk.snc.route;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.NextHopPort;
import com.huawei.umdk.snc.route.model.RouteEntry;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.Address;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestUtils {
    private static final Logger log = new Logger(TestUtils.class);

    private static boolean compareAddressAndPrefix(Address address, Prefix prefix) {
        return address.getAddr() == prefix.getAddr() &&
            address.getMask() == prefix.getMask() &&
            address.getMaskLen() == prefix.getMaskLen();
    }

    private static String addrToLabelDescription(SncTopology topology, Prefix prefix) {
        StringBuilder result = new StringBuilder();
        String separator = " || ";
        for (SncNode node : topology.getNodeMap().values()) {
            for (Address address : node.getAddrList()) {
                if (compareAddressAndPrefix(address, prefix)) {
                    result.append(node.getLabel()).append(' ')
                        .append(address.getAddrType()).append(separator);
                }
            }

            for (SncPort port : node.getPortMap().values()) {
                for (Address address : port.getAddrList()) {
                    if (compareAddressAndPrefix(address, prefix)) {
                        result.append(port.getLabel()).append(' ')
                            .append(address.getAddrType()).append(separator);
                    }
                }
            }
        }

        if (result.isEmpty()) {
            result.append("unknown addr maybe inter-chassis address");
        } else {
            int length = result.length();
            result.delete(length - separator.length(), length);
        }

        return result.toString();
    }

    public static void printFormatNodeRouteInfo(SncTopology topology, RouteTable routeTable) {
        Map<Prefix, RouteEntry> routeEntries = routeTable.getRouteEntries();
        for (Map.Entry<Prefix, RouteEntry> entry : routeEntries.entrySet()) {
            List<String> outIfList = new ArrayList<>();
            for (NextHopPort nhp : entry.getValue().getNhpSet()) {
                outIfList.add(nhp.getOutPortId() + ":" + nhp.getCost());
            }
            Collections.sort(outIfList);
            String destAddrDetail = "addr description " + addrToLabelDescription(topology, entry.getKey());
            String addr = "addr " + String.format("0x%x", entry.getKey().getAddr()) + " : maskLen " + entry.getKey().getMaskLen()
                + " : mask " + Long.toHexString(entry.getKey().getMask());
            String outPortId = "outPortId" + outIfList;
            log.info("%-40s %-40s %-80s", addr, outPortId, destAddrDetail);
        }
    }

    public static Map<String, SncTopology> parseTopoTemplate() {
        Map<String, SncTopology> topologyMap = new HashMap<>();

        List<String> templateFiles = new ArrayList<>();
        templateFiles.add("128_npu_rack.json");
        templateFiles.add("128_npu_inter_rack.json");

        for (String template : templateFiles) {
            SncTopology topology = TopoTemplateService.parseTemplateFile(template);
            topologyMap.put(topology.getLabel().getNames().get("type"), topology);
        }

        return topologyMap;
    }
}
