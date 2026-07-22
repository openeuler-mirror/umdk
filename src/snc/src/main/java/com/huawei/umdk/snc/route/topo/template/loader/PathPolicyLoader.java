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
import com.huawei.umdk.snc.route.topo.template.model.Label;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class PathPolicyLoader {
    @JSONField(name = "node_labels", deserializeUsing = Deserializers.LabelListReader.class)
    List<Label> nodeLabels = new ArrayList<>();

    @JSONField(name = "policies")
    List<PathPolicyItemsLoader> policies = new ArrayList<>();
}
