package com.huawei.umdk.snc.entity;

import java.util.List;
import java.util.Map;
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
public class RoutingTable {
    private String deviceName;
    private Integer chipIndex;
    private Map<RoutePrefix, RoutingEntry> routes;
    private List<Integer> maskLengths;
}
