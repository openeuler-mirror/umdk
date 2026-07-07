package com.huawei.umdk.snc.entity;

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
public class RoutingEntry {
    private RoutePrefix prefix;
    private Map<String, OutPortInfo> outPortInfos;
}
