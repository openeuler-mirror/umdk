/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: test data loader
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DeviceType;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.MgmtInfo;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;

public class TestDataLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static SuperNode loadSuperNode(String resourcePath) throws Exception {
        try (InputStream is = TestDataLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            JsonNode root = MAPPER.readTree(is);
            String name = root.get("name").asText();
            String version = root.get("version").asText();
            Map<String, DeviceEntity> devices = new LinkedHashMap<>();

            JsonNode devicesNode = root.get("devices");
            Iterator<String> deviceNames = devicesNode.fieldNames();
            while (deviceNames.hasNext()) {
                String deviceKey = deviceNames.next();
                JsonNode deviceNode = devicesNode.get(deviceKey);
                String type = deviceNode.get("deviceType").asText();
                DeviceEntity device = parseDevice(deviceNode, type);
                devices.put(device.getDeviceName(), device);
            }

            Map<String, NpuDevice> npuDevices = new LinkedHashMap<>();
            Map<String, SwDevice> swDevices = new LinkedHashMap<>();
            for (DeviceEntity device : devices.values()) {
                if (device instanceof NpuDevice) {
                    npuDevices.put(device.getDeviceName(), (NpuDevice) device);
                } else if (device instanceof SwDevice) {
                    swDevices.put(device.getDeviceName(), (SwDevice) device);
                }
            }
            return new SuperNode(name, version, npuDevices, swDevices);
        }
    }

    private static DeviceEntity parseDevice(JsonNode node, String type) {
        String deviceName = node.get("deviceName").asText();
        String rack = node.has("rack") ? node.get("rack").asText() : null;
        MgmtInfo mgmtInfo = parseMgmtInfo(node.get("mgmtInfo"));

        if ("NPU".equals(type)) {
            return parseNpuDevice(node, deviceName, rack, mgmtInfo);
        } else if ("SW".equals(type)) {
            return parseSwDevice(node, deviceName, rack, mgmtInfo);
        }

        throw new IllegalArgumentException("Unknown device type: " + type + " for " + deviceName);
    }

    private static NpuDevice parseNpuDevice(JsonNode node, String deviceName, String rack, MgmtInfo mgmtInfo) {
        NpuDevice npu = new NpuDevice();
        npu.setDeviceName(deviceName);
        npu.setRack(rack);
        npu.setMgmtInfo(mgmtInfo);
        npu.setOsName(node.has("osName") ? node.get("osName").asText() : null);
        npu.setOsIp(node.has("osIp") ? node.get("osIp").asText() : null);
        npu.setBoardId(node.has("boardId") ? node.get("boardId").asInt() : null);
        npu.setModuleId(node.has("moduleId") ? node.get("moduleId").asInt() : null);
        npu.setBoardIndex(node.has("boardIndex") ? node.get("boardIndex").asInt() : null);

        JsonNode fcNode = node.get("forwardingChip").get(0);
        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(fcNode.get("chipIndex").asInt());
        chip.setPorts(parseNpuPorts(fcNode.get("ports"), chip.getChipIndex()));

        addRoutingTable(node, deviceName, chip);

        Map<Integer, NpuForwardingChip> chips = new LinkedHashMap<>();
        chips.put(chip.getChipIndex(), chip);
        npu.setForwardingChips(chips);

        return npu;
    }

    private static SwDevice parseSwDevice(JsonNode node, String deviceName, String rack, MgmtInfo mgmtInfo) {
        SwDevice sw = new SwDevice();
        sw.setDeviceName(deviceName);
        sw.setRack(rack);
        sw.setMgmtInfo(mgmtInfo);
        String level = node.has("level") ? node.get("level").asText() : "L1";
        sw.setSwitchLevel("L2".equals(level) ? SwitchLevel.L2 : SwitchLevel.L1);
        sw.setIndex(node.has("index") ? node.get("index").asInt() : null);

        JsonNode fcNode = node.get("forwardingChip").get(0);
        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(fcNode.get("chipIndex").asInt());
        chip.setPorts(parseSwPorts(fcNode.get("ports"), chip.getChipIndex()));

        addRoutingTable(node, deviceName, chip);

        Map<Integer, SwForwardingChip> chips = new LinkedHashMap<>();
        chips.put(chip.getChipIndex(), chip);
        sw.setForwardingChips(chips);

        return sw;
    }

    private static void addRoutingTable(JsonNode deviceNode, String deviceName, ForwardingChip chip) {
        if (!deviceNode.has("routingTables") || !deviceNode.get("routingTables").isArray()) {
            return;
        }
        RoutingTable rt = new RoutingTable();
        rt.setDeviceName(deviceName);
        rt.setChipIndex(chip.getChipIndex());
        Map<RoutePrefix, RoutingEntry> routes = new LinkedHashMap<>();

        for (JsonNode rtNode : deviceNode.get("routingTables")) {
            JsonNode prefixNode = rtNode.get("prefix");
            RoutePrefix prefix = new RoutePrefix(
                prefixNode.get("dstAddress").asText(),
                prefixNode.get("maskLength").asInt()
            );

            Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();
            for (JsonNode opiNode : rtNode.get("outPortInfos")) {
                String outInterface = opiNode.get("outInterface").asText();
                OutPortInfo opi = new OutPortInfo(
                    outInterface,
                    opiNode.has("nextHop") ? opiNode.get("nextHop").asText() : "",
                    opiNode.has("preference") ? opiNode.get("preference").asInt() : 60,
                    opiNode.has("tag") ? opiNode.get("tag").asInt() : 0,
                    opiNode.has("protocol") ? opiNode.get("protocol").asText() : "static",
                    0
                );
                outPortInfos.put(outInterface, opi);
            }

            RoutingEntry entry = new RoutingEntry(prefix, outPortInfos, true);
            routes.put(prefix, entry);
        }

        rt.setRoutes(routes);
        List<Integer> masks = routes.keySet().stream()
            .map(RoutePrefix::getMaskLength)
            .sorted(Comparator.reverseOrder())
            .collect(Collectors.toList());
        rt.setMaskLengths(masks);

        chip.setRoutingTable(rt);
    }

    private static Map<String, NpuPortEntity> parseNpuPorts(JsonNode portsArray, int chipIndex) {
        Map<String, NpuPortEntity> ports = new LinkedHashMap<>();
        for (JsonNode portNode : portsArray) {
            NpuPortEntity port = new NpuPortEntity(
                portNode.has("eid") ? portNode.get("eid").asText() : null,
                portNode.has("upi") ? portNode.get("upi").asText() : null
            );
            port.setPortName(portNode.get("portName").asText());
            port.setId(portNode.get("id").asInt());
            port.setChipIndex(chipIndex);
            port.setRemoteDevice(portNode.get("remoteDevice").asText());
            port.setRemotePort(portNode.get("remotePort").asText());
            port.setCna(portNode.has("cna") ? portNode.get("cna").asText() : null);
            ports.put(port.getPortName(), port);
        }
        return ports;
    }

    private static Map<String, SwPortEntity> parseSwPorts(JsonNode portsArray, int chipIndex) {
        Map<String, SwPortEntity> ports = new LinkedHashMap<>();
        for (JsonNode portNode : portsArray) {
            SwPortEntity port = new SwPortEntity();
            port.setPortName(portNode.get("portName").asText());
            port.setId(portNode.get("id").asInt());
            port.setChipIndex(chipIndex);
            port.setRemoteDevice(portNode.get("remoteDevice").asText());
            port.setRemotePort(portNode.get("remotePort").asText());
            port.setCna(null);
            ports.put(port.getPortName(), port);
        }
        return ports;
    }

    private static MgmtInfo parseMgmtInfo(JsonNode node) {
        if (node == null) {
            return null;
        }
        return new MgmtInfo(
            node.get("ip").asText(),
            node.get("port").asInt(),
            node.get("username").asText(),
            node.get("password").asText()
        );
    }
}
