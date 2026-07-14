/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.config.SNCConfig;
import com.huawei.umdk.snc.dto.PathPlanRequest;
import com.huawei.umdk.snc.dto.PathPlanResult;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.TpAclEntity;

public interface SNCService {

    void init(SNCConfig config);

    void uninit();

    void setSuperNode(SuperNode superNode);

    void addNpuDevices(String superNodeName, List<NpuDevice> devices);

    void addSwDevices(String superNodeName, List<SwDevice> devices);

    void removeDevices(String superNodeName, List<String> deviceNames);

    void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                           List<RoutingEntry> entries);

    void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                              List<RoutePrefix> prefixes);

    void setAclData(AclData aclData);

    void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules);

    void removeAclRules(String superNodeName, List<AclKey> keys);

    SuperNode getSuperNode(String name);

    void removeSuperNode(String name);

    AclData getAclData(String superNodeName);

    void removeAclData(String superNodeName);

    PathPlanResult planPath(PathPlanRequest request);
}
