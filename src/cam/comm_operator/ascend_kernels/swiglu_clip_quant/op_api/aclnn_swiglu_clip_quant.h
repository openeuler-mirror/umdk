/*
 * calution: this file was generated automaticlly donot change it.
*/

#ifndef ACLNN_SWIGLU_CLIP_QUANT_H_
#define ACLNN_SWIGLU_CLIP_QUANT_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* funtion: aclnnSwigluClipQuantGetWorkspaceSize
 * parameters :
 * x : required
 * groupIndex : required
 * groupAlpha : required
 * activateLeft : optional
 * quantModeOptional : optional
 * clampMode : optional
 * yOut : required
 * scaleOut : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default")))
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
    aclOpExecutor **executor);

/* funtion: aclnnSwigluClipQuant
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default")))
aclnnStatus aclnnSwigluClipQuant(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif