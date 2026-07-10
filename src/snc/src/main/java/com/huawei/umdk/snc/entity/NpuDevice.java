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
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuDevice extends DeviceEntity {
    private String osName;
    private String osIp;
    private Integer boardId;
    private Integer moduleId;
    private Integer boardIndex;

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.NPU;
    }
}
