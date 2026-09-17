/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: parse topology template file
 * Author: jiang wen jiang
 * Create: 2026-07-21
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.loader;

import com.alibaba.fastjson2.annotation.JSONField;

import lombok.Data;

@Data
public class PortLoader {
    @JSONField(name = "port_id")
    int portId;

    @JSONField(name = "port_name")
    String portName;

    @JSONField(name = "port_cna")
    String portCna;

    /**
     * Jetty id of this physical port, in {@code [32, 1023]}.
     * Optional: when absent the loader falls back to {@code 32 + portId}.
     */
    @JSONField(name = "jetty_id")
    Integer jettyId;

    @JSONField(name = "mask")
    String mask;

    @JSONField(name = "peer_node_label")
    String peerNodeLabel;

    @JSONField(name = "peer_port_id")
    int peerPortId;
}
