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
public class PolicyLoader {
    @JSONField(name = "path_control_policies")
    List<PathPolicyLoader> pathPolicies = new ArrayList<>();

    @JSONField(name = "port_fwd_policies")
    List<PortFwdPolicyLoader> portFwdPolicyLoader = new ArrayList<>();

    @JSONField(name = "prefix_announce_policies")
    List<PrefixPolicyLoader> prefixPolicyLoader = new ArrayList<>();
}
