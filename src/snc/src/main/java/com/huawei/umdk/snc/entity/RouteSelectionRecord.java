package com.huawei.umdk.snc.entity;

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
