/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Author: OpenCode
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.service;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.TpAclEntity;
import com.huawei.umdk.snc.store.AclStore;

public class AclService {

    private final AclStore store;

    public AclService(AclStore store) {
        this.store = store;
    }

    public void importAclData(AclData aclData) {
        if (aclData == null) {
            throw new IllegalArgumentException("AclData must not be null");
        }
        if (aclData.getSuperNodeName() == null || aclData.getSuperNodeName().isEmpty()) {
            throw new IllegalArgumentException("AclData superNodeName must not be null or empty");
        }
        store.replace(aclData);
    }

    public void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (rules == null) {
            throw new IllegalArgumentException("rules must not be null");
        }
        for (Map.Entry<AclKey, TpAclEntity> rule : rules.entrySet()) {
            if (rule.getKey() == null || rule.getValue() == null) {
                throw new IllegalArgumentException("rule key and value must not be null");
            }
            store.addAclRule(superNodeName, rule.getKey(), rule.getValue());
        }
    }

    public void removeAclRules(String superNodeName, List<AclKey> keys) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (keys == null) {
            throw new IllegalArgumentException("keys must not be null");
        }
        for (AclKey key : keys) {
            if (key == null) {
                throw new IllegalArgumentException("key in list must not be null");
            }
            store.removeAclRule(superNodeName, key);
        }
    }

    public AclData getAclData(String superNodeName) {
        return store.getAclData(superNodeName);
    }

    public void removeAclData(String superNodeName) {
        store.removeAclData(superNodeName);
    }
}
