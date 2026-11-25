/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: calculate route test
 * Author: jiang wen jiang
 * Create: 2026-07-29
 * Note:
 */

package com.huawei.umdk.snc.route;

import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.NextHopPort;
import com.huawei.umdk.snc.route.model.RouteEntry;
import com.huawei.umdk.snc.route.model.RouteTable;
import com.huawei.umdk.snc.route.topo.template.model.Address;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import com.huawei.umdk.snc.route.topo.template.model.SncNode;
import com.huawei.umdk.snc.route.topo.template.model.SncPort;
import com.huawei.umdk.snc.route.topo.template.model.SncTopology;
import com.huawei.umdk.snc.route.topo.template.model.SuperNodeType;
import com.huawei.umdk.snc.route.topo.template.service.TopoTemplateService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
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
        templateFiles.add(SuperNodeType.ATLAS950_GALAXY_RACK32_OF_128.getValue() + ".json");
        templateFiles.add(SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue() + ".json");

        templateFiles.add(SuperNodeType.ATLAS950_GALAXY_RACK32_OF_512.getValue() + ".json");
        templateFiles.add(SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_512.getValue() + ".json");

        for (String template : templateFiles) {
            SncTopology topology = TopoTemplateService.parseTemplateFile(template);
            topologyMap.put(topology.getLabel().getNames().get("type"), topology);
        }

        return topologyMap;
    }

    public static String getNpuDeviceName(String superNodeName, int rack, int board, int device) {
        return String.format("%s#rack%d#board%d#npu%d", superNodeName, rack, board, device);
    }

    public static String getL1SwName(String superNodeName, int rack, int index) {
        return String.format("%s#rack%d#l1sw%d", superNodeName, rack, index);
    }

    public static String getL2SwName(String superNodeName, int index) {
        return String.format("%s#l2sw%d", superNodeName, index);
    }

    public static void constructSuperNode(SuperNode superNode, Map<String, SncTopology> topologyMap,
                                           int rackCount, int l2SwitchCount) {
        superNode.setName("SuperNode1");

        boolean is128 = rackCount <= 4;
        SncTopology rackTopology = topologyMap.get(is128
            ? SuperNodeType.ATLAS950_GALAXY_RACK32_OF_128.getValue()
            : SuperNodeType.ATLAS950_GALAXY_RACK32_OF_512.getValue());
        SncTopology interRackTopology = topologyMap.get(is128
            ? SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_128.getValue()
            : SuperNodeType.ATLAS950_GALAXY_RACK32_SUPERNODE_512.getValue());

        Map<String, NpuDevice> npuDevices = new HashMap<>();
        Map<String, SwDevice> swDevices = new HashMap<>();

        // 1. 创建NPU设备：rackCount个rack × 8个board × 4个NPU
        for (int rack = 1; rack <= rackCount; rack++) {
            for (int board = 1; board <= 8; board++) {
                for (int npuIndex = 1; npuIndex <= 4; npuIndex++) {
                    int boardIndex = board * 2 - 1;
                    String deviceName = getNpuDeviceName(superNode.getName(), rack, boardIndex, npuIndex);
                    Map<Integer, NpuForwardingChip> chips = new HashMap<>();
                    NpuForwardingChip iodie2 = new NpuForwardingChip(2);
                    iodie2.setPorts(new LinkedHashMap<>());
                    chips.put(2, iodie2);
                    NpuDevice npuDevice = new NpuDevice(deviceName, null, String.valueOf(rack),
                        chips, "os0", null, boardIndex, 0, npuIndex);
                    npuDevices.put(deviceName, npuDevice);
                }
            }
        }

        // 2. 创建L1 switch设备：rackCount个rack × 4个L1 sw
        for (int rack = 1; rack <= rackCount; rack++) {
            for (int index = 1; index <= 4; index++) {
                String deviceName = getL1SwName(superNode.getName(), rack, index);
                Map<Integer, SwForwardingChip> chips = new HashMap<>();
                SwForwardingChip chip1 = new SwForwardingChip(1);
                chip1.setPorts(new LinkedHashMap<>());
                chips.put(1, chip1);
                SwDevice swDevice = new SwDevice(deviceName, null, String.valueOf(rack),
                    chips, SwitchLevel.L1, index);
                swDevices.put(deviceName, swDevice);
            }
        }

        // 3. 创建L2 switch设备：每个含chip 1和chip 2
        for (int index = 1; index <= l2SwitchCount; index++) {
            String deviceName = getL2SwName(superNode.getName(), index);
            Map<Integer, SwForwardingChip> chips = new HashMap<>();
            SwForwardingChip chip1 = new SwForwardingChip(1);
            chip1.setPorts(new LinkedHashMap<>());
            SwForwardingChip chip2 = new SwForwardingChip(2);
            chip2.setPorts(new LinkedHashMap<>());
            chips.put(1, chip1);
            chips.put(2, chip2);
            SwDevice swDevice = new SwDevice(deviceName, null, null,
                chips, SwitchLevel.L2, index);
            swDevices.put(deviceName, swDevice);
        }

        // 4. 根据框内模板连接 NPU ↔ L1 sw（每框复制一份）
        for (SncNode npuNode : rackTopology.getNodeMap().values()) {
            if (!"npu".equals(npuNode.type())) {
                continue;
            }
            int slot = Integer.parseInt(npuNode.getLabel().getNames().get("slot"));
            int ubpu = Integer.parseInt(npuNode.getLabel().getNames().get("ubpu"));
            int die = Integer.parseInt(npuNode.getLabel().getNames().get("die"));

            for (int rack = 1; rack <= rackCount; rack++) {
                String npuDeviceName = getNpuDeviceName(superNode.getName(), rack, slot, ubpu);
                NpuDevice npuDevice = npuDevices.get(npuDeviceName);
                NpuForwardingChip chip = npuDevice.getForwardingChips().get(die);
                Map<String, NpuPortEntity> ports = chip.getPorts();

                for (SncPort sncPort : npuNode.getPortMap().values()) {
                    String peerLabel = sncPort.getPeerNodeId();
                    int peerL1Index = Label.getL1SwIndex(peerLabel);
                    String l1DeviceName = getL1SwName(superNode.getName(), rack, peerL1Index);
                    SwDevice l1Sw = swDevices.get(l1DeviceName);
                    SwForwardingChip l1Chip = l1Sw.getForwardingChips().get(1);
                    Map<String, SwPortEntity> l1Ports = l1Chip.getPorts();

                    SncNode l1Node = rackTopology.getNodeMap().get(peerLabel);
                    SncPort peerSncPort = l1Node.getPortMap().get(sncPort.getPeerPortId());
                    String peerPortName = peerSncPort.getPortName();

                    // NPU侧端口
                    NpuPortEntity npuPort = new NpuPortEntity();
                    npuPort.setPortName(sncPort.getPortName());
                    npuPort.setId(sncPort.getId());
                    npuPort.setChipIndex(die);
                    npuPort.setRemoteDevice(l1DeviceName);
                    npuPort.setRemotePort(peerPortName);
                    ports.put(sncPort.getPortName(), npuPort);

                    // L1 sw侧端口（NPU-facing）
                    if (!l1Ports.containsKey(peerPortName)) {
                        SwPortEntity l1Port = new SwPortEntity();
                        l1Port.setPortName(peerPortName);
                        l1Port.setId(peerSncPort.getId());
                        l1Port.setChipIndex(1);
                        l1Port.setRemoteDevice(npuDeviceName);
                        l1Port.setRemotePort(sncPort.getPortName());
                        l1Ports.put(peerPortName, l1Port);
                    }
                }
            }
        }

        // 5. 根据框间模板连接 L1 sw ↔ L2 sw
        //    模板中L1 sw索引1-4对应rack1，5-8对应rack2，9-12对应rack3，13-16对应rack4
        for (SncNode l1Node : interRackTopology.getNodeMap().values()) {
            if (!"l1_sw".equals(l1Node.type())) {
                continue;
            }
            int globalL1Index = Label.getL1SwIndex(l1Node.getLabel().toString());
            int rack = (globalL1Index - 1) / 4 + 1;
            int localL1Index = (globalL1Index - 1) % 4 + 1;

            String l1DeviceName = getL1SwName(superNode.getName(), rack, localL1Index);
            SwDevice l1Sw = swDevices.get(l1DeviceName);
            SwForwardingChip l1Chip = l1Sw.getForwardingChips().get(1);
            Map<String, SwPortEntity> l1Ports = l1Chip.getPorts();

            for (SncPort sncPort : l1Node.getPortMap().values()) {
                String peerLabel = sncPort.getPeerNodeId();
                if (!peerLabel.contains("l2_sw")) {
                    continue;
                }

                Label peerL2Label = new Label();
                peerL2Label.refreshAllNames(peerLabel);
                int peerL2Index = Integer.parseInt(peerL2Label.getNames().get("index"));
                int peerL2Chip = Integer.parseInt(peerL2Label.getNames().get("chip"));
                String l2DeviceName = getL2SwName(superNode.getName(), peerL2Index);
                SwDevice l2Sw = swDevices.get(l2DeviceName);
                SwForwardingChip l2Chip = l2Sw.getForwardingChips().get(peerL2Chip);
                Map<String, SwPortEntity> l2Ports = l2Chip.getPorts();

                SncNode l2Node = interRackTopology.getNodeMap().get(peerLabel);
                SncPort peerSncPort = l2Node.getPortMap().get(sncPort.getPeerPortId());
                String peerPortName = peerSncPort.getPortName();

                // L1 sw侧端口（L2-facing）
                if (!l1Ports.containsKey(sncPort.getPortName())) {
                    SwPortEntity l1Port = new SwPortEntity();
                    l1Port.setPortName(sncPort.getPortName());
                    l1Port.setId(sncPort.getId());
                    l1Port.setChipIndex(1);
                    l1Port.setRemoteDevice(l2DeviceName);
                    l1Port.setRemotePort(peerPortName);
                    l1Ports.put(sncPort.getPortName(), l1Port);
                }

                // L2 sw侧端口
                if (!l2Ports.containsKey(peerPortName)) {
                    SwPortEntity l2Port = new SwPortEntity();
                    l2Port.setPortName(peerPortName);
                    l2Port.setId(peerSncPort.getId());
                    l2Port.setChipIndex(peerL2Chip);
                    l2Port.setRemoteDevice(l1DeviceName);
                    l2Port.setRemotePort(sncPort.getPortName());
                    l2Ports.put(peerPortName, l2Port);
                }
            }
        }

        superNode.setNpuDevices(npuDevices);
        superNode.setSwDevices(swDevices);
    }
}
