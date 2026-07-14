/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File
 */
package com.huawei.umdk.snc.store;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.TpAclEntity;

public class AclStore {

    private Map<String, Map<AclKey, TpAclEntity>> store;

    public void init() {
        this.store = new ConcurrentHashMap<>();
    }

    public void replace(AclData aclData) {
        Map<AclKey, TpAclEntity> internalMap = new ConcurrentHashMap<>();
        if (aclData.getTpAcls() != null) {
            internalMap.putAll(aclData.getTpAcls());
        }
        store.put(aclData.getSuperNodeName(), internalMap);
    }

    public void clear() {
        if (store != null) {
            store.clear();
        }
    }

    public void removeAclData(String superNodeName) {
        if (store != null) {
            store.remove(superNodeName);
        }
    }

    public AclData getAclData(String superNodeName) {
        if (store == null) {
            return null;
        }
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            return null;
        }
        return new AclData(superNodeName, internalMap);
    }

    public void addAclRule(String superNodeName, AclKey key, TpAclEntity entity) {
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            throw new IllegalStateException(
                "ACL data not found for superNode: " + superNodeName + ". Call setAclData() first.");
        }
        internalMap.put(key, entity);
    }

    public void removeAclRule(String superNodeName, AclKey key) {
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            throw new IllegalStateException(
                "ACL data not found for superNode: " + superNodeName + ". Call setAclData() first.");
        }
        internalMap.remove(key);
    }
}
