/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: converged route of one device
 * Create: 2026-10-23
 * Note:
 * History: 2026-10-23  Create File
 */

package com.huawei.umdk.snc.entity;

import java.util.LinkedHashMap;
import java.util.Map;

import lombok.Data;

/**
 * 单设备收敛配置：一个设备上、各出接口被收敛/恢复的 CNA 地址前缀。
 * key = 出接口名称（被置位/清位的出端口），
 * value = 该出接口的收敛前缀明细 {@link ConvergedPrefix}（一个端口可有多个 prefix）。
 * action 与本次切流事件的 action 保持一致（enable/disable）。
 */
@Data
public class ConvergedNodeRoute {
    /**
     * 设备名称。
     */
    private String deviceName;

    /**
     * 本次切流动作：enable / disable，与传入 DrainEvent.action 一致。
     */
    private String action;

    private final Map<String, ConvergedPrefix> portPrefixes = new LinkedHashMap<>();

    /**
     * 追加一条明细：同 (portName, prefix) 已存在时不重复添加（幂等）。
     *
     * @param portName 出接口名称
     * @param prefix   受影响的 CNA 地址前缀
     */
    public void addPrefix(String portName, RoutePrefix prefix) {
        ConvergedPrefix converged = portPrefixes.computeIfAbsent(portName, k -> new ConvergedPrefix());
        if (!converged.getRoutePrefixList().contains(prefix)) {
            converged.getRoutePrefixList().add(prefix);
        }
    }
}