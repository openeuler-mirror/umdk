/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add afd_async_combine_recv interface header file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#ifndef ACLNN_AFD_ASYNC_COMBINE_RECV_H_
#define ACLNN_AFD_ASYNC_COMBINE_RECV_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnAfdAsyncCombineRecvGetWorkspaceSize
 * parameters :
 * expandX : required
 * expertIds : required
 * expertScales : required
 * commArgs : required
 * magic : required
 * batchSize : required
 * hiddenSize : required
 * topk : required
 * moeRankNum : required
 * attnRankNum : required
 * routeExpertNumPerMoe : required
 * attnRankId : required
 * worldSize : required
 * hcclGroupName : required
 * out : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default")))
aclnnStatus aclnnAfdAsyncCombineRecvGetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *expertIds,
    const aclTensor *expertScales,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t attnRankId,
    int64_t worldSize,
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnAfdAsyncCombineRecv
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default")))
aclnnStatus aclnnAfdAsyncCombineRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
