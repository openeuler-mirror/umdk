/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom tilingData definition file
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom tilingData definition file
 */

#ifndef GATHER_SELECTION_KV_CACHE_CUSTOM_TILING_H_
#define GATHER_SELECTION_KV_CACHE_CUSTOM_TILING_H_

#define OPS_UTILS_LOG_SUB_MOD_NAME "GATHER_SELECTION_KV_CACHE_CUSTOM"
#define OPS_UTILS_LOG_PACKAGE_TYPE "[CAM]"

#include "ops_error.h"
#include "tiling/tiling_api.h"
#include "platform/platform_info.h"
#include "exe_graph/runtime/tiling_context.h"
#include "register/op_def_registry.h"
#include "register/tilingdata_base.h"
#include "tiling/platform/platform_ascendc.h"

namespace optiling {

BEGIN_TILING_DATA_DEF(GatherSelectionKvCacheCustomTilingData)
TILING_DATA_FIELD_DEF(int64_t, usedCoreNum);
TILING_DATA_FIELD_DEF(int64_t, tokenNum);
TILING_DATA_FIELD_DEF(int64_t, topk);
TILING_DATA_FIELD_DEF(int64_t, selKvBlockSize);
TILING_DATA_FIELD_DEF(int64_t, selMaxBlockNum);
TILING_DATA_FIELD_DEF(int64_t, fullKvBlockSize);
TILING_DATA_FIELD_DEF(int64_t, fullMaxBlockNum);
TILING_DATA_FIELD_DEF(int64_t, kRopeDim);
TILING_DATA_FIELD_DEF(int64_t, kvCacheDim);
TILING_DATA_FIELD_DEF(int64_t, kRopeUbSize);
TILING_DATA_FIELD_DEF(int64_t, kvCacheUbSize);
TILING_DATA_FIELD_DEF(int64_t, buffNum);
TILING_DATA_FIELD_DEF(int64_t, ifQuant);
TILING_DATA_FIELD_DEF(int64_t, planItemNum);
TILING_DATA_FIELD_DEF(int64_t, planValidNumOffset);
TILING_DATA_FIELD_DEF(int64_t, planTopkIdOffset);
TILING_DATA_FIELD_DEF(int64_t, planInsertIdxOffset);
TILING_DATA_FIELD_DEF(int64_t, planActionOffset);
TILING_DATA_FIELD_DEF(int64_t, workspaceSize);
END_TILING_DATA_DEF;

REGISTER_TILING_DATA_CLASS(GatherSelectionKvCacheCustom, GatherSelectionKvCacheCustomTilingData)

struct GatherSelectionKvCacheCustomCompileInfo {};

class GatherSelectionKvCacheCustomTiling {
public:
    explicit GatherSelectionKvCacheCustomTiling(gert::TilingContext* context) : context_(context) {}
    ge::graphStatus RunTiling();

private:
    ge::graphStatus GetPlatformInfo();
    ge::graphStatus GetAttrsAndShapes();
    ge::graphStatus CheckDtypes();
    ge::graphStatus DoTiling();
    ge::graphStatus PostTiling();

    gert::TilingContext* context_ = nullptr;
    GatherSelectionKvCacheCustomTilingData tilingData_;
    int64_t coreNum_ = 0;
    int64_t ubSize_ = 0;
    int64_t systemWorkspaceSize_ = 0;
    static constexpr int64_t UB_BLOCK_SIZE = 32;
    int64_t ubBlockSize_ = UB_BLOCK_SIZE;
    int64_t tokenNum_ = 0;
    int64_t topk_ = 0;
    int64_t selTopKBlockSize_ = 0;
    ge::DataType cacheDtype_ = ge::DT_FLOAT16;
};

} // namespace optiling

#endif // GATHER_SELECTION_KV_CACHE_CUSTOM_TILING_H_
