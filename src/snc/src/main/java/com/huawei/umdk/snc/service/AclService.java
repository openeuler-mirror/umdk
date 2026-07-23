/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.service;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.TpAclEntity;
import com.huawei.umdk.snc.store.AclStore;

public class AclService {

    private static final Logger LOG = new Logger(AclService.class);

    private final AclStore store;

    public AclService(AclStore store) {
        this.store = store;
    }

    public void importAclData(AclData aclData) {
        if (aclData == null) {
            LOG.error("importAclData: error=AclData must not be null");
            throw new IllegalArgumentException("AclData must not be null");
        }
        if (aclData.getSuperNodeName() == null || aclData.getSuperNodeName().isEmpty()) {
            LOG.error("importAclData: error=AclData superNodeName must not be null or empty");
            throw new IllegalArgumentException("AclData superNodeName must not be null or empty");
        }
        LOG.info("importAclData: superNode=%s, tpAclCount=%d",
            aclData.getSuperNodeName(),
            aclData.getTpAcls() != null ? aclData.getTpAcls().size() : 0);
        store.replace(aclData);
    }

    public void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("addAclRules: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (rules == null) {
            LOG.error("addAclRules: error=rules must not be null");
            throw new IllegalArgumentException("rules must not be null");
        }
        LOG.info("addAclRules: superNode=%s, count=%d", superNodeName, rules.size());
        for (Map.Entry<AclKey, TpAclEntity> rule : rules.entrySet()) {
            if (rule.getKey() == null || rule.getValue() == null) {
                LOG.error("addAclRules: error=rule key and value must not be null");
                throw new IllegalArgumentException("rule key and value must not be null");
            }
        }
        for (Map.Entry<AclKey, TpAclEntity> rule : rules.entrySet()) {
            LOG.debug("addAclRules: superNode=%s", superNodeName);
            store.addAclRule(superNodeName, rule.getKey(), rule.getValue());
        }
    }

    public void removeAclRules(String superNodeName, List<AclKey> keys) {
        if (superNodeName == null || superNodeName.isEmpty()) {
            LOG.error("removeAclRules: error=superNodeName must not be null or empty");
            throw new IllegalArgumentException("superNodeName must not be null or empty");
        }
        if (keys == null) {
            LOG.error("removeAclRules: error=keys must not be null");
            throw new IllegalArgumentException("keys must not be null");
        }
        LOG.info("removeAclRules: superNode=%s, count=%d", superNodeName, keys.size());
        for (AclKey key : keys) {
            if (key == null) {
                LOG.error("removeAclRules: error=key in list must not be null");
                throw new IllegalArgumentException("key in list must not be null");
            }
        }
        for (AclKey key : keys) {
            LOG.debug("removeAclRules: superNode=%s", superNodeName);
            store.removeAclRule(superNodeName, key);
        }
    }

    public AclData getAclData(String superNodeName) {
        LOG.debug("getAclData: superNode=%s", superNodeName);
        return store.getAclData(superNodeName);
    }

    public void removeAclData(String superNodeName) {
        LOG.info("removeAclData: superNode=%s", superNodeName);
        store.removeAclData(superNodeName);
    }
}