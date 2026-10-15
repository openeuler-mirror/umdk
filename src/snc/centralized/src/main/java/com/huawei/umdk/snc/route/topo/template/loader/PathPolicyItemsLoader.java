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
import com.huawei.umdk.snc.route.topo.template.model.AddrType;
import com.huawei.umdk.snc.route.topo.template.model.Label;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class PathPolicyItemsLoader {
    @JSONField(name = "dst_node_labels", deserializeUsing = Deserializers.LabelListReader.class)
    List<Label> dstNodeLabels = new ArrayList<>();

    @JSONField(name = "dst_address_types", deserializeUsing = Deserializers.AddrTypeListReader.class)
    List<AddrType> dstAddressTypes = new ArrayList<>();

    @JSONField(name = "dst_addresses")
    List<PrefixLoader> dstAddresses = new ArrayList<>();

    @JSONField(name = "path_types")
    List<String> pathTypes = new ArrayList<>();
}
