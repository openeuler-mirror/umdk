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
public class InternalPathInfo {
    private List<InternalPathHop> hops;
    private String sourceEid;
    private String destEid;
    private String sourceCna;
    private String destCna;
    private int hopCount;
}
