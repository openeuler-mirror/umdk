#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnnInner_swiglu_clip_quant.h"
#include "aclnn_swiglu_clip_quant.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnSwigluClipQuantGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *groupIndex,
    const aclTensor *groupAlpha,
    bool activateLeft,
    char *quantModeOptional,
    int64_t clampMode,
    const aclTensor *yOut,
    const aclTensor *scaleOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerSwigluClipQuantGetWorkspaceSize(x, groupIndex, groupAlpha, activateLeft, quantModeOptional, clampMode,
        yOut, scaleOut, workspaceSize, executor);
}

aclnnStatus aclnnSwigluClipQuant(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerSwigluClipQuant(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif