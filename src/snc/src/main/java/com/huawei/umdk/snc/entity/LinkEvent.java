/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04  Create File
 */
package com.huawei.umdk.snc.entity;

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
public class LinkEvent {
    private String deviceName;   // 设备名（SuperNode 内的设备名）
    private String portName;     // 端口名
    private String eventType;    // 事件类型："up" 或 "down"
    private String eventTime;    // 事件时间戳（由调用方定义格式）
}
