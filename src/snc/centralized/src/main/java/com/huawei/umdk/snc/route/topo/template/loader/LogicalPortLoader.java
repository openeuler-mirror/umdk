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

import java.util.List;

@Data
public class LogicalPortLoader {
    @JSONField(name = "port_type")
    String portType;

    @JSONField(name = "port_id")
    int portId;

    @JSONField(name = "port_cna")
    String portCna;

    @JSONField(name = "mask")
    String mask;

    @JSONField(name = "members")
    List<Integer> members;
}
