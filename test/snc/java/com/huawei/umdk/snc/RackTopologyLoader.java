/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: rack topology loader
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc;

import com.huawei.umdk.snc.entity.SuperNode;

/**
 * Loads the full 148-device rack topology into an in-memory {@link SuperNode}.
 *
 * <p>Delegates to {@link FullRackTopologyGenerator#buildRawTopology()} which
 * constructs the object graph directly in memory without any intermediate
 * JSON file.
 */
public final class RackTopologyLoader {

    private RackTopologyLoader() {
    }

    /**
     * Build the full rack topology in memory.
     *
     * @return a SuperNode containing all 148 devices
     */
    public static SuperNode loadRawTopology() {
        return FullRackTopologyGenerator.buildRawTopology();
    }
}
