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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.InternalPathHop;
import com.huawei.umdk.snc.entity.InternalPathInfo;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.exception.SuperNodeNotFoundException;

public class PathEngine {

    public InternalPathInfo resolveDirectPath(NpuDevice srcDevice,
                                              NpuPortEntity srcPort, NpuDevice destDevice,
                                              NpuPortEntity destPort) {
        InternalPathInfo pathInfo = new InternalPathInfo();
        List<InternalPathHop> hops = new ArrayList<>();

        InternalPathHop srcHop = new InternalPathHop();
        srcHop.setDeviceName(srcDevice.getDeviceName());
        srcHop.setDeviceType(srcDevice.getDeviceType());
        srcHop.setInPort(null);
        srcHop.setOutPort(srcPort.getPortName());
        srcHop.setCna(srcPort.getCna());
        srcHop.setEid(srcPort.getEid());
        srcHop.setHopIndex(0);
        hops.add(srcHop);

        InternalPathHop destHop = new InternalPathHop();
        destHop.setDeviceName(destDevice.getDeviceName());
        destHop.setDeviceType(destDevice.getDeviceType());
        destHop.setInPort(destPort.getPortName());
        destHop.setOutPort(null);
        destHop.setCna(destPort.getCna());
        destHop.setEid(destPort.getEid());
        destHop.setHopIndex(1);
        hops.add(destHop);

        pathInfo.setHops(hops);
        pathInfo.setSrcEid(srcPort.getEid());
        pathInfo.setDstEid(destPort.getEid());
        pathInfo.setSourceCna(srcPort.getCna());
        pathInfo.setDestCna(destPort.getCna());

        return pathInfo;
    }

    public InternalPathInfo resolveMultiHopPath(NpuDevice srcDevice,
                                                NpuPortEntity srcPort, NpuDevice destDevice,
                                                NpuPortEntity destPort,
                                                Map<String, String> interDevices,
                                                Map<String, DeviceEntity> allDevices) {
        List<InternalPathHop> hops = new ArrayList<>();

        Map<String, String> orderedInterDevices = new LinkedHashMap<>(interDevices);

        List<String> orderedDevices = new ArrayList<>();
        orderedDevices.add(srcDevice.getDeviceName());
        orderedDevices.addAll(orderedInterDevices.keySet());
        if (!orderedDevices.contains(destDevice.getDeviceName())) {
            orderedDevices.add(destDevice.getDeviceName());
        }

        for (int i = 0; i < orderedDevices.size(); i++) {
            String devName = orderedDevices.get(i);
            DeviceEntity device = allDevices.get(devName);
            if (device == null) {
                throw new SuperNodeNotFoundException("Device not found: " + devName);
            }

            InternalPathHop hop = new InternalPathHop();
            hop.setDeviceName(devName);
            hop.setDeviceType(device.getDeviceType());
            hop.setHopIndex(i);

            PortEntity port = null;
            if (i == 0) {
                port = srcPort;
                hop.setInPort(null);
                hop.setOutPort(srcPort.getPortName());
            } else if (i == orderedDevices.size() - 1) {
                port = destPort;
                hop.setInPort(destPort.getPortName());
                hop.setOutPort(null);
            } else {
                String interPortName = orderedInterDevices.get(devName);
                if (interPortName != null) {
                    port = findPortByName(device, interPortName);
                }
                if (port == null) {
                    port = findPortByConnection(device);
                    if (port == null) {
                        throw new SuperNodeNotFoundException(
                            "Port not found: " + interPortName + " in " + devName); // NOPMD
                    }
                }
                hop.setInPort(null);
                hop.setOutPort(port.getPortName());
            }

            if (port != null) {
                hop.setCna(port.getCna());
                if (port instanceof NpuPortEntity) {
                    hop.setEid(((NpuPortEntity) port).getEid());
                }
                hop.setRemoteDevice(port.getRemoteDevice());
                hop.setRemotePort(port.getRemotePort());
            }

            if (device.getRack() != null) {
                hop.setRack(device.getRack());
            }

            hops.add(hop);
        }

        for (int i = 0; i < hops.size() - 1; i++) {
            InternalPathHop current = hops.get(i);
            InternalPathHop next = hops.get(i + 1);
            if (current.getRemoteDevice() != null) {
                if (!current.getRemoteDevice().equals(next.getDeviceName())) {
                    throw new SuperNodeNotFoundException(
                        "Connection mismatch between " + current.getDeviceName()
                            + " and " + next.getDeviceName());
                }
            }
        }

        InternalPathInfo pathInfo = new InternalPathInfo();
        pathInfo.setHops(hops);
        pathInfo.setSrcEid(srcPort.getEid());
        pathInfo.setDstEid(destPort.getEid());
        pathInfo.setSourceCna(srcPort.getCna());
        pathInfo.setDestCna(destPort.getCna());

        return pathInfo;
    }

    public List<InternalPathHop> reverseHops(List<InternalPathHop> hops) {
        List<InternalPathHop> reversed = new ArrayList<>();
        for (int i = hops.size() - 1; i >= 0; i--) {
            InternalPathHop original = hops.get(i);
            InternalPathHop reversedHop = new InternalPathHop();
            reversedHop.setDeviceName(original.getDeviceName());
            reversedHop.setDeviceType(original.getDeviceType());
            reversedHop.setInPort(original.getOutPort());
            reversedHop.setOutPort(original.getInPort());
            reversedHop.setCna(original.getCna());
            reversedHop.setEid(original.getEid());
            reversedHop.setRemoteDevice(original.getRemoteDevice());
            reversedHop.setRemotePort(original.getRemotePort());
            reversedHop.setRack(original.getRack());
            reversedHop.setHopIndex(reversed.size());
            reversed.add(reversedHop);
        }
        return reversed;
    }

    public PortEntity findPortByName(DeviceEntity device, String portName) {
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip.getPorts() != null) {
                PortEntity port = chip.getPorts().get(portName);
                if (port != null) {
                    return port;
                }
            }
        }
        return null;
    }

    public PortEntity findPortByConnection(DeviceEntity device) {
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip.getPorts() != null) {
                for (PortEntity port : chip.getPorts().values()) {
                    if (port.getRemoteDevice() != null && port.getRemotePort() != null) {
                        return port;
                    }
                }
            }
        }
        return null;
    }
}
