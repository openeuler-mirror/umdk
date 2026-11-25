/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add afd_async_combine_send interface header file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#ifndef ACLNN_AFD_ASYNC_COMBINE_SEND_H_
#define ACLNN_AFD_ASYNC_COMBINE_SEND_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnAfdAsyncCombineSendGetWorkspaceSize
 * parameters :
 * expandX : required
 * commArgs : required
 * batchInfo : required
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
 * hcclGroupName : required
 * out : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default")))
aclnnStatus aclnnAfdAsyncCombineSendGetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *commArgs,
    const aclTensor *batchInfo,
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
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnAfdAsyncCombineSend
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default")))
aclnnStatus aclnnAfdAsyncCombineSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
