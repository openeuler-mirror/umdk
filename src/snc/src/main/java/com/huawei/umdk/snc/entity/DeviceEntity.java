package com.huawei.umdk.snc.entity;

import java.util.Map;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class DeviceEntity {
    private String deviceName;
    @Setter(AccessLevel.NONE)
    private DeviceType deviceType;
    private MgmtInfo mgmtInfo;
    private String rack;
    private Map<Integer, ForwardingChip> forwardingChips;

    protected DeviceEntity(String deviceName, DeviceType deviceType) {
        this.deviceName = deviceName;
        this.deviceType = deviceType;
    }
}
