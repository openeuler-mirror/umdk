/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add cam_moe_distribute_dispatch_recv interface header file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#ifndef ACLNN_CAM_MOE_DISTRIBUTE_DISPATCH_RECV_H_
#define ACLNN_CAM_MOE_DISTRIBUTE_DISPATCH_RECV_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamMoeDistributeDispatchRecvGetWorkspaceSize
 * parameters :
 * x : required
 * commArgs : required
 * magic : required
 * maxSeqLen : required
 * hiddenSize : required
 * topk : required
 * moeRankNum : required
 * attnRankNum : required
 * routeExpertNumPerMoe : required
 * moeRankId : required
 * worldSize : required
 * tpSize : required
 * dynamicQuant : required
 * hcclGroupName : required
 * expandXOut : required
 * dynamicScalesOut : required
 * batchInfoOut : required
 * epRecvCountRoutedOut : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default")))
aclnnStatus aclnnCamMoeDistributeDispatchRecvGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t maxSeqLen,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t moeRankId,
    int64_t worldSize,
    int64_t tpSize,
    int64_t dynamicQuant,
    char *hcclGroupName,
    const aclTensor *expandXOut,
    const aclTensor *dynamicScalesOut,
    const aclTensor *batchInfoOut,
    const aclTensor *epRecvCountRoutedOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnCamMoeDistributeDispatchRecv
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default")))
aclnnStatus aclnnCamMoeDistributeDispatchRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
