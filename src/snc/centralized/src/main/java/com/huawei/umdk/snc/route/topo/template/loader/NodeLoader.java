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

import java.util.ArrayList;
import java.util.List;

@Data
public class NodeLoader {
    @JSONField(name = "node_label")
    String nodeLabel;

    @JSONField(name = "node_cna")
    String nodeCna;

    @JSONField(name = "mask")
    String mask;

    @JSONField(name = "ports")
    List<PortLoader> portLoaders = new ArrayList<>();

    @JSONField(name = "logical_ports")
    List<LogicalPortLoader> logicalPortLoaders = new ArrayList<>();
}
