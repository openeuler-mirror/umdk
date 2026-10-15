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
import com.huawei.umdk.snc.route.topo.template.model.Prefix;
import lombok.Data;

@Data
public class PrefixLoader {
    @JSONField(name = "address", deserializeUsing = Deserializers.HexLongReader.class)
    long address;

    @JSONField(name = "mask_len")
    int maskLen;

    @JSONField(name = "mask", deserializeUsing = Deserializers.HexLongReader.class)
    long mask;

    public Prefix asPrefix() {
        return new Prefix(address, maskLen, mask);
    }
}
