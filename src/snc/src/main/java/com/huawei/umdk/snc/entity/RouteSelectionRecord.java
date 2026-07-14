/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.entity;

import java.util.Collections;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RouteSelectionRecord {
    private String deviceName;
    private RoutePrefix prefix;
    private List<CandidateOutPort> candidateOutPorts;
    private String scna;
    private String dcna;
    private String hashInfo;
    private Direction direction;

    public List<CandidateOutPort> getCandidateOutPorts() {
        return candidateOutPorts == null ? null : Collections.unmodifiableList(candidateOutPorts);
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @EqualsAndHashCode
    @ToString
    public static class CandidateOutPort {
        private String portName;
        private String nextHop;
        private boolean selected;
    }

    public enum Direction {
        FORWARD, REVERSE
    }
}
