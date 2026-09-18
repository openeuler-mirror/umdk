/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add cam_moe_distribute_dispatch_send interface header file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#ifndef ACLNN_CAM_MOE_DISTRIBUTE_DISPATCH_SEND_H_
#define ACLNN_CAM_MOE_DISTRIBUTE_DISPATCH_SEND_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamMoeDistributeDispatchSendGetWorkspaceSize
 * parameters :
 * x : required
 * expertIds : required
 * commArgs : required
 * magic : required
 * maxSeqLen : required
 * batchSize : required
 * hiddenSize : required
 * topk : required
 * moeRankNum : required
 * attnRankNum : required
 * routeExpertNumPerMoe : required
 * attnRankId : required
 * worldSize : required
 * layerIndex : required
 * tpSize : required
 * dynamicQuant : required
 * hcclGroupName : required
 * out : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default")))
aclnnStatus aclnnCamMoeDistributeDispatchSendGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t maxSeqLen,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t attnRankId,
    int64_t worldSize,
    int64_t layerIndex,
    int64_t tpSize,
    int64_t dynamicQuant,
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnCamMoeDistributeDispatchSend
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default")))
aclnnStatus aclnnCamMoeDistributeDispatchSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
