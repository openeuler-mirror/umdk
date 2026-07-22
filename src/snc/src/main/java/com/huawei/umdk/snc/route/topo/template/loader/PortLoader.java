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

    @JSONField(name = "mask")
    String mask;

    @JSONField(name = "peer_node_label")
    String peerNodeLabel;

    @JSONField(name = "peer_port_id")
    int peerPortId;
}
