package com.huawei.umdk.snc.entity;

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
public class OutPortInfo {
    private String portName;
    private String nextHop;
    private Integer preference;
    private Integer tag;
    private String protocol;
}
