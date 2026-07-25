/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add gather selection kv cache kernel
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create file
 */

/*!
 * \file gather_selection_kv_cache_tiling.h
 * \brief
 */
#ifndef GATHER_SELECTION_KV_CACHE_TILING_H_
#define GATHER_SELECTION_KV_CACHE_TILING_H_

#define OPS_UTILS_LOG_SUB_MOD_NAME "GATHER_SELECTION_KV_CACHE"
#define OPS_UTILS_LOG_PACKAGE_TYPE "[CAM]"

#include "exe_graph/runtime/tiling_context.h"
#include "tiling/platform/platform_ascendc.h"
#include "register/op_def_registry.h"
#include "register/tilingdata_base.h"
#include "tiling/tiling_api.h"
#include "ops_error.h"
#include "platform/platform_info.h"

namespace optiling {
BEGIN_TILING_DATA_DEF(GatherSelectionKvCacheTilingData)
TILING_DATA_FIELD_DEF(int64_t, usedCoreNum);
TILING_DATA_FIELD_DEF(int64_t, mainCoreBsLoopNum);
TILING_DATA_FIELD_DEF(int64_t, tailCoreBsLoopNum);
TILING_DATA_FIELD_DEF(int64_t, selTopKBlockSize);
TILING_DATA_FIELD_DEF(int64_t, fullKvBlockNum);
TILING_DATA_FIELD_DEF(int64_t, fullKvBlockSize);
TILING_DATA_FIELD_DEF(int64_t, kRopeDim);
TILING_DATA_FIELD_DEF(int64_t, kvCacheDim);
TILING_DATA_FIELD_DEF(int64_t, selKvBlockNum);
TILING_DATA_FIELD_DEF(int64_t, selKvBlockSize);
TILING_DATA_FIELD_DEF(int64_t, fullMaxBlockNum);
TILING_DATA_FIELD_DEF(int64_t, selMaxBlockNum);
TILING_DATA_FIELD_DEF(int64_t, batchsize);
TILING_DATA_FIELD_DEF(int64_t, seq);
TILING_DATA_FIELD_DEF(int64_t, rawSeq);
TILING_DATA_FIELD_DEF(int64_t, headnum);
TILING_DATA_FIELD_DEF(int64_t, topk);
TILING_DATA_FIELD_DEF(int64_t, kRopeUbSize);
TILING_DATA_FIELD_DEF(int64_t, kvCacheUbSize);
TILING_DATA_FIELD_DEF(int64_t, buffNum);
TILING_DATA_FIELD_DEF(int64_t, layOut);
TILING_DATA_FIELD_DEF(int64_t, ifQuant);
END_TILING_DATA_DEF;

REGISTER_TILING_DATA_CLASS(GatherSelectionKvCache, GatherSelectionKvCacheTilingData)

enum class DataLayout : uint32_t {
    BSND = 0,
    TND = 1
};

struct GatherSelectionKvCacheCompileInfo {
};

class GatherSelectionKvCacheTiling {
public:
    explicit GatherSelectionKvCacheTiling(gert::TilingContext* context) : context_(context)
    {}
    ~GatherSelectionKvCacheTiling()
    {}
    ge::graphStatus RunTiling();

protected:
    ge::graphStatus DoOpTiling();
    uint64_t GetTilingKey() const;
    ge::graphStatus GetPlatformInfo();
    ge::graphStatus GetShapeAttrsInfo();
    ge::graphStatus PostTiling();

private:
    void PrintTilingDatas();
    ge::graphStatus GetInputAttrs();
    ge::graphStatus GetSelKvCacheShape();
    ge::graphStatus GetSelBlockTable();
    ge::graphStatus GetTopkIndices();
    ge::graphStatus CheckSelInfo();
    ge::graphStatus GetFullKvCacheShape();
    ge::graphStatus GetFullKvBlkTable();
    ge::graphStatus GetSeqLenIn();
    ge::graphStatus GetInputDtypeInfo();

private:
    GatherSelectionKvCacheTilingData tilingData_;
    int64_t selTopKBlockSize_ = 0;

    int64_t coreNum_ = 0;
    int64_t ubSize_ = 0;
    int64_t ubBlockSize_ = 0;

    int64_t t_ = 0;
    int64_t batchSize_ = 0;
    int64_t seq_ = 0;
    int64_t headnum_ = 0;
    int64_t topk_ = 0;
    int64_t selKvBlockTableRow_ = 0;
    DataLayout topKLayout_ = DataLayout::BSND;

    ge::DataType selKRopeDtype_;

    gert::TilingContext *context_ = nullptr;
    uint64_t tilingKey_{0};
};

} // namespace optiling

#endif // GATHER_SELECTION_KV_CACHE_TILING_H_
