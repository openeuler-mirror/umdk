/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-07
 * Note:
 * History: 2026-07-07  Create File; 2026-07-16 key=value log format
 */
package com.huawei.umdk.snc.engine;

import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.entity.AclData;
import com.huawei.umdk.snc.entity.AclKey;
import com.huawei.umdk.snc.entity.TpAclEntity;
import com.huawei.umdk.snc.entity.TransportType;

public class AclCheckEngine {

    private static final Logger LOG = new Logger(AclCheckEngine.class);

    public boolean checkBothDirection(AclData aclData, String srcEid, String dstEid,
                             String sourceCna, String destCna) {
        LOG.debug("checkBothDirection: srcEid=" + srcEid + ", dstEid=" + dstEid
            + ", srcCna=" + sourceCna + ", dstCna=" + destCna);
        if (aclData == null || aclData.getTpAcls() == null) {
            LOG.warn("checkBothDirection: warning=aclData or tpAcls is null");
            return false;
        }
        if (srcEid == null || dstEid == null || sourceCna == null || destCna == null) {
            LOG.warn("checkBothDirection: warning=one or more parameters are null");
            return false;
        }

        AclKey forwardKey = new AclKey(srcEid, dstEid, TransportType.RCTP);
        TpAclEntity forwardEntity = aclData.getTpAcls().get(forwardKey);
        if (forwardEntity == null) {
            LOG.warn("checkBothDirection: warning=forward ACL entity not found");
            return false;
        }
        if (!sourceCna.equals(forwardEntity.getSourceCna())
            || !destCna.equals(forwardEntity.getDestCna())) {
            LOG.warn("checkBothDirection: warning=forward ACL CNA mismatch"
                + ", expectedSrcCna=" + sourceCna + ", expectedDstCna=" + destCna
                + ", gotSrcCna=" + forwardEntity.getSourceCna() + ", gotDstCna=" + forwardEntity.getDestCna());
            return false;
        }

        AclKey reverseKey = new AclKey(dstEid, srcEid, TransportType.RCTP);
        TpAclEntity reverseEntity = aclData.getTpAcls().get(reverseKey);
        if (reverseEntity == null) {
            LOG.warn("checkBothDirection: warning=reverse ACL entity not found");
            return false;
        }
        if (!destCna.equals(reverseEntity.getSourceCna())
            || !sourceCna.equals(reverseEntity.getDestCna())) {
            LOG.warn("checkBothDirection: warning=reverse ACL CNA mismatch"
                + ", expectedSrcCna=" + destCna + ", expectedDstCna=" + sourceCna
                + ", gotSrcCna=" + reverseEntity.getSourceCna() + ", gotDstCna=" + reverseEntity.getDestCna());
            return false;
        }

        LOG.debug("checkBothDirection: result=ACL bidirectional check passed");
        return true;
    }
}
