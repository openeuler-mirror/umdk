/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: parse topology template file
 * Author: jiang wen jiang
 * Create: 2026-10-20
 * Note:
 */

package com.huawei.umdk.snc.route.topo.template.loader;

import com.alibaba.fastjson2.annotation.JSONField;
import lombok.Data;

@Data
public class CnaLoader {
    @JSONField(name = "address")
    private String address;

    @JSONField(name = "mask")
    private String mask;

    @JSONField(name = "length")
    private int length;
}
