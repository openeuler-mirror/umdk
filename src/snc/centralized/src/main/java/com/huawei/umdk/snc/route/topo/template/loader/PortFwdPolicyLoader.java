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
public class PortFwdPolicyLoader {
    @JSONField(name = "node_labels", deserializeUsing = Deserializers.LabelListReader.class)
    List<Label> nodeLabels = new ArrayList<>();

    @JSONField(name = "default_policy")
    String defaultPolicy;

    @JSONField(name = "permit_policies")
    List<PermitOrDenyPolicy> permitPolicies = new ArrayList<>();

    @JSONField(name = "deny_policies")
    List<PermitOrDenyPolicy> denyPolicies = new ArrayList<>();
}
