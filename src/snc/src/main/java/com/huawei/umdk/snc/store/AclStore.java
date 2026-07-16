/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.store;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.TpAclEntity;

public class AclStore {

    private static final Logger LOG = new Logger(AclStore.class);

    private Map<String, Map<AclKey, TpAclEntity>> store;

    public void init() {
        this.store = new ConcurrentHashMap<>();
        LOG.info("init: AclStore initialized");
    }

    public void replace(AclData aclData) {
        LOG.info("replace: superNode=" + aclData.getSuperNodeName()
            + ", tpAclCount=" + (aclData.getTpAcls() != null ? aclData.getTpAcls().size() : 0));
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
        LOG.info("clear: AclStore cleared");
    }

    public void removeAclData(String superNodeName) {
        LOG.info("removeAclData: superNode=" + superNodeName);
        if (store != null) {
            store.remove(superNodeName);
        }
    }

    public AclData getAclData(String superNodeName) {
        if (store == null) {
            LOG.warn("getAclData: superNode=" + superNodeName + ", warning=store is null, result=null");
            return null;
        }
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            LOG.debug("getAclData: superNode=" + superNodeName + ", result=no ACL data found");
            return null;
        }
        LOG.debug("getAclData: superNode=" + superNodeName + ", ruleCount=" + internalMap.size());
        return new AclData(superNodeName, internalMap);
    }

    public void addAclRule(String superNodeName, AclKey key, TpAclEntity entity) {
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            LOG.error("addAclRule: superNode=" + superNodeName
                + ", error=ACL data not found, hint=Call setAclData() first");
            throw new IllegalStateException(
                "ACL data not found for superNode: " + superNodeName + ". Call setAclData() first.");
        }
        internalMap.put(key, entity);
        LOG.info("addAclRule: superNode=" + superNodeName);
    }

    public void removeAclRule(String superNodeName, AclKey key) {
        Map<AclKey, TpAclEntity> internalMap = store.get(superNodeName);
        if (internalMap == null) {
            LOG.error("removeAclRule: superNode=" + superNodeName
                + ", error=ACL data not found, hint=Call setAclData() first");
            throw new IllegalStateException(
                "ACL data not found for superNode: " + superNodeName + ". Call setAclData() first.");
        }
        internalMap.remove(key);
        LOG.info("removeAclRule: superNode=" + superNodeName);
    }
}
