/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: drain event
 * Create: 2026-10-23
 * Note:
 * History: 2026-10-23  Create File
 */

package com.huawei.umdk.snc.entity;

import java.util.Set;

import lombok.Data;

/**
 * 切流事件：设备切流与链路切流共用，由 eventType 区分。
 *
 * <p>设备切流（eventType = "device"）：将指定设备承载的流量整体切走（disable）
 * 或切回（enable）。约束：一次执行 1 个设备的操作；仅交换机支持设备切流，
 * NPU 不支持。
 *
 * <p>链路切流（eventType = "link"）：对 portNames 与其共同对端设备之间的若干条
 * 链路执行切走/切回。仅需本端 deviceName + portNames，对端设备与端口信息由
 * SuperNode 拓扑查询。约束：所有端口的对端必须属于同一个设备（两侧端口可分布在
 * 多个芯片上）；portNames 为 Set，天然无重复。
 */
@Data
public class DrainEvent {
    /**
     * 切流动作：切出（流量切走，对应原 drain）。
     */
    public static final String ACTION_DISABLE = "disable";

    /**
     * 切流动作：切回（流量恢复，对应原 recovery）。
     */
    public static final String ACTION_ENABLE = "enable";

    /**
     * 事件类型：设备切流。
     */
    public static final String EVENT_TYPE_DEVICE = "device";

    /**
     * 事件类型：链路切流。
     */
    public static final String EVENT_TYPE_LINK = "link";

    /**
     * 切流动作：enable / disable，取值见 ACTION_*。
     */
    private String action;

    /**
     * 事件类型：device / link，取值见 EVENT_TYPE_*。
     */
    private String eventType;

    /**
     * 设备名（SuperNode 内；设备切流须为交换机）。
     */
    private String deviceName;

    /**
     * 链路切流的端口集合（eventType=link 时须非空）。
     */
    private Set<String> portNames;

    /**
     * 全参构造：eventType=link 时 portNames 须非空；eventType=device 时 portNames 传 null。
     */
    public DrainEvent(String action, String eventType, String deviceName, Set<String> portNames) {
        this.action = action;
        this.eventType = eventType;
        this.deviceName = deviceName;
        this.portNames = portNames;
    }
}