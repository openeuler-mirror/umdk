/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04  Create File
 */
package com.huawei.umdk.snc.service;

import java.util.Map;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.LinkEvent;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.store.SuperNodeStore;

public class LinkEventService {

    private static final Logger LOG = new Logger(LinkEventService.class);

    private static final String LINK_STATUS_UP = "up";

    private static final String LINK_STATUS_DOWN = "down";

    private final SuperNodeStore store;

    public LinkEventService(SuperNodeStore store) {
        this.store = store;
    }

    /**
     * 处理链路事件：定位端口并更新 linkStatus 与 updateAt。
     * 路由收敛传播预留（本期不实现）。
     */
    public void notifyLinkEvent(SuperNode supernode, LinkEvent event) {
        if (event.getDeviceName() == null || event.getDeviceName().isEmpty()) {
            LOG.error("notifyLinkEvent: error=deviceName must not be null or empty");
            throw new IllegalArgumentException("deviceName must not be null or empty");
        }
        if (event.getPortName() == null || event.getPortName().isEmpty()) {
            LOG.error("notifyLinkEvent: error=portName must not be null or empty");
            throw new IllegalArgumentException("portName must not be null or empty");
        }
        String eventType = event.getEventType();
        if (!LINK_STATUS_UP.equals(eventType) && !LINK_STATUS_DOWN.equals(eventType)) {
            LOG.error("notifyLinkEvent: error=invalid eventType=%s, expected=up|down", eventType);
            throw new IllegalArgumentException("invalid eventType: " + eventType + ", expected: up|down");
        }

        DeviceEntity device = supernode.getAllDevices().get(event.getDeviceName());
        if (device == null) {
            LOG.error("notifyLinkEvent: device=%s, error=device not found", event.getDeviceName());
            throw new IllegalStateException("Device not found: " + event.getDeviceName());
        }

        PortEntity port = findPortByName(device, event.getPortName());
        if (port == null) {
            LOG.error("notifyLinkEvent: device=%s, port=%s, error=port not found",
                event.getDeviceName(), event.getPortName());
            throw new IllegalStateException(
                "Port not found: " + event.getPortName() + " in device " + event.getDeviceName());
        }

        port.setLinkStatus(eventType);
        port.setUpdateAt(event.getEventTime());
        LOG.info("notifyLinkEvent: device=%s, port=%s, status=%s, updateAt=%s",
            event.getDeviceName(), event.getPortName(), eventType, event.getEventTime());

        // 路由收敛传播预留（本期不实现）
    }

    private PortEntity findPortByName(DeviceEntity device, String portName) {
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip == null || chip.getPorts() == null) {
                continue;
            }
            Map<String, ? extends PortEntity> ports = chip.getPorts();
            PortEntity port = ports.get(portName);
            if (port != null) {
                return port;
            }
        }
        return null;
    }
}
