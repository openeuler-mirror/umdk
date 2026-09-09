/**
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

/*!
 * \file gather_selection_sparse_flash_attention_tiling.cpp
 * \brief
 */

#include <map>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <limits>
#include <graph/utils/type_utils.h>
#include "err/ops_err.h"
#include "register/op_def_registry.h"
#include "../op_kernel/gather_selection_sparse_flash_attention_template_tiling_key.h"
#include "gather_selection_sparse_flash_attention_tiling.h"

using std::map;
using std::pair;
using std::string;

using namespace ge;
using namespace AscendC;
namespace optiling {

constexpr uint32_t PRE_LOAD_NUM = 2;
constexpr uint32_t BLOCK_TABLE_ELEM_BYTE = 4;
constexpr int32_t SPARSE_MODE_BAND = 4;

static const std::string QUERY_NAME = "query";
static const std::string KEY_NAME = "key";
static const std::string VALUE_NAME = "value";
static const std::string SPARSE_INDICES_NAME = "sparse_indices";
static const std::string BLOCK_TABLE_NAME = "block_table";
static const std::string ATTEN_OUT_NAME = "attention_out";
static const std::string SINKS_NAME = "sinks";

const std::map<std::string, std::vector<ge::DataType>> DTYPE_SUPPORT_MAP = {
    {QUERY_NAME, {ge::DT_FLOAT16, ge::DT_BF16}},
    {KEY_NAME, {ge::DT_INT8, ge::DT_FLOAT8_E4M3FN, ge::DT_HIFLOAT8}},
    {VALUE_NAME, {ge::DT_INT8, ge::DT_FLOAT8_E4M3FN, ge::DT_HIFLOAT8}},
    {ATTEN_OUT_NAME, {ge::DT_FLOAT16, ge::DT_BF16}},
    {SPARSE_INDICES_NAME, {ge::DT_INT32}},
    {SINKS_NAME, {ge::DT_FLOAT}}};

const std::map<std::string, std::vector<QSFALayout>> LAYOUT_SUPPORT_MAP = {
    {QUERY_NAME, {QSFALayout::BSND, QSFALayout::TND}},
    {KEY_NAME, {QSFALayout::BSND, QSFALayout::TND, QSFALayout::PA_BSND}},
    {VALUE_NAME, {QSFALayout::BSND, QSFALayout::TND, QSFALayout::PA_BSND}},
    {ATTEN_OUT_NAME, {QSFALayout::BSND, QSFALayout::TND}},
};

const std::map<ge::DataType, std::string> DATATYPE_TO_STRING_MAP = {
    {ge::DT_FLOAT, "DT_FLOAT"},                   // float type
    {ge::DT_UNDEFINED, "DT_UNDEFINED"},           // Used to indicate a DataType field has not been set.
    {ge::DT_FLOAT16, "DT_FLOAT16"},               // fp16 type
    {ge::DT_INT8, "DT_INT8"},                     // int8 type
    {ge::DT_INT16, "DT_INT16"},                   // int16 type
    {ge::DT_FLOAT8_E4M3FN, "DT_FLOAT8_E4M3FN"},   // fp8_e4m3 type
    {ge::DT_HIFLOAT8, "DT_HIFLOAT8"},             // hifloat8 type
    {ge::DT_UINT16, "DT_UINT16"},                 // uint16 type
    {ge::DT_UINT8, "DT_UINT8"},                   // uint8 type
    {ge::DT_INT64, "DT_INT64"},                   // int64 type
    {ge::DT_INT32, "DT_INT32"},                   // int32 type
    {ge::DT_UINT64, "DT_UINT64"},                 // unsigned int64
    {ge::DT_UINT32, "DT_UINT32"},                 // unsigned int32
    {ge::DT_BOOL, "DT_BOOL"},                     // bool type
    {ge::DT_DOUBLE, "DT_DOUBLE"},                 // double type
    {ge::DT_DUAL, "DT_DUAL"},                     // dual output type
    {ge::DT_COMPLEX32, "DT_COMPLEX32"},           // complex32 type
    {ge::DT_COMPLEX64, "DT_COMPLEX64"},           // complex64 type
    {ge::DT_COMPLEX128, "DT_COMPLEX128"},         // complex128 type
    {ge::DT_DUAL_SUB_INT8, "DT_DUAL_SUB_INT8"},   // dual output int8 type
    {ge::DT_DUAL_SUB_UINT8, "DT_DUAL_SUB_UINT8"}, // dual output uint8 type
    {ge::DT_QUINT8, "DT_QUINT8"},                 // quint8 type
    {ge::DT_QUINT16, "DT_QUINT16"},               // quint16 type
    {ge::DT_QINT8, "DT_QINT8"},                   // qint8 type
    {ge::DT_QINT16, "DT_QINT16"},                 // qint16 type
    {ge::DT_QINT32, "DT_QINT32"},                 // qint32 type
    {ge::DT_RESOURCE, "DT_RESOURCE"},             // resource type
    {ge::DT_STRING_REF, "DT_STRING_REF"},         // string ref type
    {ge::DT_BF16, "DT_BFLOAT16"},                 // dt_bfloat16 type
    {ge::DT_STRING, "DT_STRING"},                 // string type
    {ge::DT_VARIANT, "DT_VARIANT"},               // dt_variant type
    {ge::DT_INT2, "DT_INT2"},                     // dt_variant type
    {ge::DT_UINT2, "DT_UINT2"},                   // dt_variant type
    {ge::DT_INT4, "DT_INT4"},                     // dt_variant type
    {ge::DT_UINT1, "DT_UINT1"}                    // dt_variant type
};

struct GatherSelectionSparseFlashAttentionCompileInfo {
    int64_t coreNum;
};

static const std::map<QSFALayout, std::vector<QSFAAxis>> QSFA_LAYOUT_AXIS_MAP = {
    {QSFALayout::BSND, {QSFAAxis::B, QSFAAxis::S, QSFAAxis::N, QSFAAxis::D}},
    {QSFALayout::TND, {QSFAAxis::T, QSFAAxis::N, QSFAAxis::D}},
    {QSFALayout::PA_BSND, {QSFAAxis::Bn, QSFAAxis::Bs, QSFAAxis::N, QSFAAxis::D}},
};

static const std::map<QSFALayout, size_t> QSFA_LAYOUT_DIM_MAP = {
    {QSFALayout::BSND, DIM_NUM_FOUR},
    {QSFALayout::TND, DIM_NUM_THREE},
    {QSFALayout::PA_BSND, DIM_NUM_FOUR},
};

static std::vector<int64_t> ToVector(const gert::Shape &shape)
{
    size_t shapeSize = shape.GetDimNum();
    std::vector<int64_t> shapeVec(shapeSize, 0);

    for (size_t i = 0; i < shapeSize; i++) {
        shapeVec[i] = shape.GetDim(i);
    }
    return shapeVec;
}

static std::string ToStringRaw(const gert::Shape &shape)
{
    std::ostringstream oss;
    auto v = ToVector(shape);
    if (v.size() > 0) {
        for (size_t i = 0; i < v.size() - 1; ++i) {
            oss << v[i] << ", ";
        }
        oss << v[v.size() - 1];
    }
    return oss.str();
}

template <typename T>
static std::string GetShapeStr(const T &shape)
{
    std::ostringstream qsfaOss;
    qsfaOss << "[";
    if (shape.GetDimNum() > 0) {
        for (size_t i = 0; i < shape.GetDimNum() - 1; ++i) {
            qsfaOss << shape.GetDim(i) << ", ";
        }
        qsfaOss << shape.GetDim(shape.GetDimNum() - 1);
    }
    qsfaOss << "]";
    return qsfaOss.str();
}

static std::string QSFADataTypeToSerialString(ge::DataType type)
{
    const auto qsfaIt = DATATYPE_TO_STRING_MAP.find(type);
    if (qsfaIt != DATATYPE_TO_STRING_MAP.end()) {
        return qsfaIt->second;
    } else {
        OPS_LOG_E("SparseFlashAttention", "datatype %d not support", type);
        return "UNDEFINED";
    }
}

string QSFATensorDesc2String(const gert::StorageShape *shape, const gert::CompileTimeTensorDesc *tensor)
{
    if (shape == nullptr || tensor == nullptr) {
        return "nil ";
    }

    std::ostringstream qsfaOss;
    qsfaOss << "(dtype: " << ge::TypeUtils::DataTypeToAscendString(tensor->GetDataType()).GetString() << "), ";
    qsfaOss << "(shape:" << GetShapeStr(shape->GetStorageShape()) << "), ";
    qsfaOss << "(ori_shape:" << GetShapeStr(shape->GetOriginShape()) << "), ";
    qsfaOss << "(format: "
            << ge::TypeUtils::FormatToAscendString(
                static_cast<ge::Format>(ge::GetPrimaryFormat(tensor->GetStorageFormat())))
                .GetString()
            << "), ";
    qsfaOss << "(ori_format: " << ge::TypeUtils::FormatToAscendString(tensor->GetOriginFormat()).GetString() << ") ";

    return qsfaOss.str();
}

string QSFADebugTilingContext(const gert::TilingContext *context)
{
    std::ostringstream qsfaOss;
    for (size_t i = 0; i < context->GetComputeNodeInfo()->GetInputsNum(); ++i) {
        qsfaOss << "input" << i << ": ";
        qsfaOss << QSFATensorDesc2String(context->GetInputShape(i), context->GetInputDesc(i));
    }

    for (size_t i = 0; i < context->GetComputeNodeInfo()->GetOutputsNum(); ++i) {
        qsfaOss << "output" << i << ": ";
        qsfaOss << QSFATensorDesc2String(context->GetOutputShape(i), context->GetOutputDesc(i));
    }
    return qsfaOss.str();
}

std::string QSFALayoutToSerialString(QSFALayout layout)
{
    switch (layout) {
        case QSFALayout::BSND:
            return "BSND";
        case QSFALayout::TND:
            return "TND";
        case QSFALayout::PA_BSND:
            return "PA_BSND";
        default:
            return "UNKNOWN";
    }
}

static uint32_t GetTypeSize(ge::DataType dtype)
{
    uint32_t qsfaTypeSize = NUM_BYTES_FLOAT16;
    switch (dtype) {
        case ge::DT_FLOAT16:
            qsfaTypeSize = NUM_BYTES_FLOAT16;
            break;
        case ge::DT_BF16:
            qsfaTypeSize = NUM_BYTES_BF16;
            break;
        default:
            qsfaTypeSize = NUM_BYTES_FLOAT16;
    }
    return qsfaTypeSize;
}

ge::graphStatus QSFAMlaTiling::SetBlockDim(uint32_t blockDim) const
{
    context_->SetBlockDim(blockDim);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAMlaTiling::SetTilingKey(uint64_t tilingKey) const
{
    context_->SetTilingKey(tilingKey);
    context_->SetScheduleMode(1); // 1: batchmode模式
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAMlaTiling::SetWorkspaceSize(uint64_t workspaceSize) const
{
    OP_CHECK(context_->GetWorkspaceSizes(1) == nullptr,
                OPS_REPORT_VECTOR_INNER_ERR(context_->GetNodeName(), "workSpaceSize got from ge is nullptr"),
                return ge::GRAPH_FAILED);
    size_t *workSpaces = context_->GetWorkspaceSizes(1);
    workSpaces[0] = workspaceSize;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAMlaTiling::SetTilingData(TilingDef &tilingData) const
{
    OP_CHECK(context_->GetRawTilingData() == nullptr,
                OPS_REPORT_VECTOR_INNER_ERR(context_->GetNodeName(), "RawTilingData got from GE context is nullptr."),
                return ge::GRAPH_FAILED);

    tilingData.SaveToBuffer(context_->GetRawTilingData()->GetData(), context_->GetRawTilingData()->GetCapacity());
    context_->GetRawTilingData()->SetDataSize(tilingData.GetDataSize());

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAMlaTiling::GetPlatformInfo()
{
    OP_CHECK(qsfaInfo_->platformInfo == nullptr,
                OPS_REPORT_VECTOR_INNER_ERR(qsfaInfo_->opName, "GetPlatformInfo is nullptr."), return ge::GRAPH_FAILED);

    auto qsfaAscendcPlatform = platform_ascendc::PlatformAscendC(qsfaInfo_->platformInfo);
    libapiSize_ = qsfaAscendcPlatform.GetLibApiWorkSpaceSize();
    aivNum_ = qsfaAscendcPlatform.GetCoreNumAiv();
    aicNum_ = qsfaAscendcPlatform.GetCoreNumAic();

    OP_CHECK(aicNum_ == 0 || aivNum_ == 0,
                OPS_REPORT_VECTOR_INNER_ERR(qsfaInfo_->opName, "num of core obtained is 0."), return GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

void QSFAMlaTiling::GenTilingKey()
{
    uint32_t layoutQuery = static_cast<uint32_t>(qsfaInfo_->qLayout);
    uint32_t layoutKV = static_cast<uint32_t>(qsfaInfo_->kvLayout);
    uint32_t pageAttention = 0U;
    if (qsfaInfo_->kvLayout == QSFALayout::PA_BSND) {
        pageAttention = 1U;
    }

    tilingKey_ =
        GET_TPL_TILING_KEY(0U, pageAttention, layoutQuery, layoutKV, perfMode_ == QSFAPerfMode::V_TEMPLATE_MODE,
                           static_cast<uint32_t>(qsfaInfo_->gSize > 64)); // G大于64时核间切G

    OPS_LOG_I(qsfaInfo_->opName, "QSFA tilingKey_: %lu.", tilingKey_);
}

void QSFAMlaTiling::ZeroTensorProcess() const
{
    if (qsfaInfo_->s2Size == 0) {
        /*
         * 1024，空tensor场景下，作为默认值完成后续计算
         * 避免matmal tiling  softmax tiling异常
         * kernel计算使用真实的seqSize=0, 与actuseq_len流程归一
         */
        qsfaInfo_->s2Size = 1024;
    }
}

void QSFAMlaTiling::InitParams()
{
    perfMode_ = QSFAPerfMode::V_TEMPLATE_MODE;
    coreNum_ = aicNum_;

    headDimAlign_ = Align(qsfaInfo_->qHeadDim, BYTE_BLOCK); // 元素个数按照基本块大小对齐
    ZeroTensorProcess();
}

void QSFAMlaTiling::CalcUbBmm()
{
    uint32_t qsfaCubeMSize = qsfaInfo_->gSize * qsfaInfo_->s1Size;
    uint32_t qsfaMaxMSize = mBaseSize_;
    if (qsfaCubeMSize > qsfaMaxMSize) {
        qsfaCubeMSize = qsfaMaxMSize;
    }
    mmResUbSize_ = sInnerSizeAlign_ * Align(qsfaCubeMSize, 16U); // kernel按照16对齐写出，tiling按照这个原则分配内存
    bmm2ResUbSize_ = headDimAlign_ * Align(qsfaCubeMSize, 16U); // kernel按照16对齐写出，tiling按照这个原则分配内存

    qPreSizeMla_ = qsfaInfo_->gSize * (headDimAlign_ + 64U) * qsfaInfo_->s1Size;
}

void QSFAMlaTiling::CheckUbSpace() { CalcUbBmm(); }

void QSFAMlaTiling::CalcInnerSize(uint32_t qsfaS2Size)
{
    sInnerSize_ = 512; // 512:s2默认切分大小
    // FlashDecode时，如果S2的计算量>=256(确保切分后不小于128)但又不足以分2次计算时，则修改sInnerSize_，均分为2份进行计算，确保Nbuffer=2
    if (splitKVFlag_ && qsfaInfo_->qLayout != QSFALayout::TND) {
        if (qsfaS2Size == 256) { // 256:s2Size的阈值，判断sInnerSize_是否切分
            sInnerSize_ = 128;   // 128:sInnerSize_值为s2Size的一半，均分为2份进行计算，
        } else if (qsfaS2Size > 256 && qsfaS2Size <= sInnerSize_) { // 256:s2Size的阈值，判断sInnerSize_是否切分
            sInnerSize_ = (sInnerSize_ + 1) / 2;                    // 2:减半
        }
    }

    sInnerLoopTimes_ = (qsfaS2Size + sInnerSize_ - 1) / sInnerSize_;
    sInnerSizeTail_ = qsfaS2Size - (sInnerLoopTimes_ - 1) * sInnerSize_;
    if (sInnerSize_ > qsfaS2Size) {
        sInnerSize_ = qsfaS2Size;
    }
    sInnerSizeAlign_ = Align(sInnerSize_, BYTE_BLOCK); // 元素个数按照基本块大小对齐
    CheckUbSpace();
}

void QSFAMlaTiling::SplitBalanced()
{
    CalcInnerSize(qsfaInfo_->s2Size);
    InnerSplitParams qsfaInnerSplitParams;
    qsfaInnerSplitParams.s1GBaseSize = qsfaInfo_->gSize;
    tilingData_.innerSplitParams.set_mBaseSize(qsfaInnerSplitParams.s1GBaseSize);

    qsfaInnerSplitParams.s2BaseSize = sInnerSize_;
    tilingData_.innerSplitParams.set_s2BaseSize(qsfaInnerSplitParams.s2BaseSize);

    usedCoreNum_ = aicNum_;
}

void QSFAMlaTiling::Split() { SplitBalanced(); }

void QSFAMlaTiling::FillTilingBaseParamsMla()
{
    tilingData_.baseParams.set_batchSize(qsfaInfo_->bSize);
    tilingData_.baseParams.set_seqSize(qsfaInfo_->s2Size);
    tilingData_.baseParams.set_qSeqSize(qsfaInfo_->s1Size);
    tilingData_.baseParams.set_blockSize(qsfaInfo_->blockSize);
    tilingData_.baseParams.set_maxBlockNumPerBatch(qsfaInfo_->maxBlockNumPerBatch);
    tilingData_.baseParams.set_scaleValue(qsfaInfo_->scaleValue);
    tilingData_.baseParams.set_nNumOfQInOneGroup(qsfaInfo_->n1Size / qsfaInfo_->n2Size);
    tilingData_.baseParams.set_actualLenDimsQ(qsfaInfo_->actualLenDimsQ);
    tilingData_.baseParams.set_actualLenDimsKV(qsfaInfo_->actualLenDimsKV);
    tilingData_.baseParams.set_outputLayout(static_cast<uint32_t>(qsfaInfo_->outLayout));
    tilingData_.baseParams.set_sparseMode(qsfaInfo_->sparseMode);
    tilingData_.baseParams.set_sparseBlockSize(qsfaInfo_->sparseBlockSize);
    tilingData_.baseParams.set_sparseBlockCount(qsfaInfo_->sparseBlockCount);
    tilingData_.baseParams.set_dSizeVInput(qsfaInfo_->dSizeVInput);
    tilingData_.baseParams.set_isActualLenDimsNull(qsfaInfo_->actualQSeqLenFlag ? 0U : 1U);
    tilingData_.baseParams.set_isActualLenDimsKVNull(qsfaInfo_->actualSeqLenFlag ? 0U : 1U);
    tilingData_.baseParams.set_keyStride0(qsfaInfo_->keyStride0);
    tilingData_.baseParams.set_selectionStatusStride(qsfaInfo_->selectionStatusStride);
    tilingData_.baseParams.set_selectionMaxBlockNum(qsfaInfo_->selectionMaxBlockNum);
    tilingData_.baseParams.set_selectionBlockSize(qsfaInfo_->selectionBlockSize);
    tilingData_.baseParams.set_selectionPhysicalBlockCount(qsfaInfo_->selectionPhysicalBlockCount);
    tilingData_.baseParams.set_fullMaxBlockNum(qsfaInfo_->fullMaxBlockNum);
    tilingData_.baseParams.set_fullBlockSize(qsfaInfo_->fullBlockSize);
    tilingData_.baseParams.set_fullPhysicalBlockCount(qsfaInfo_->fullPhysicalBlockCount);
}

// for flash decode
void QSFAMlaTiling::FillTilingSplitKVMla()
{
    tilingData_.splitKVParams.set_s2(kvSplitPart_);
    // 2:每个核可能有头规约和尾规约，一共两份规约信息
    tilingData_.splitKVParams.set_accumOutSize(aicNum_ * 2 * qsfaInfo_->n2Size * mBaseSize_ * headDimAlign_);
    // 2:每个核可能有头规约和尾规约，一共两份规约信息;sum + max
    tilingData_.splitKVParams.set_logSumExpSize(2 * aicNum_ * 2 * qsfaInfo_->n2Size * mBaseSize_ *
                                                (BYTE_BLOCK / BLOCK_TABLE_ELEM_BYTE));

    if (!splitKVFlag_) {
        tilingData_.splitKVParams.set_s2(0);
    }
}

void QSFAMlaTiling::FillTilingSingleCoreParamsMla() { tilingData_.singleCoreParams.set_usedCoreNum(usedCoreNum_); }

void QSFAMlaTiling::FillTilingSingleCoreTensorSizeMla()
{
    tilingData_.singleCoreTensorSize.set_mmResUbSize(mmResUbSize_);
    tilingData_.singleCoreTensorSize.set_bmm2ResUbSize(bmm2ResUbSize_);
}

void QSFAMlaTiling::FillTiling()
{
    FillTilingBaseParamsMla();
    FillTilingSplitKVMla();
    FillTilingSingleCoreParamsMla();
    FillTilingSingleCoreTensorSizeMla();
}

uint32_t QSFAMlaTiling::CalcBalanceFDParamNums(const uint32_t actCoreNum) const
{
    return actCoreNum * 2 * qsfaInfo_->n2Size * mBaseSize_; // 2:每个核可能有头规约和尾规约，一共两份规约信息
}

void QSFAMlaTiling::NormalCalcFDWorkSpace(const uint32_t actCoreNum)
{
    if (splitKVFlag_) {
        uint32_t accumOutSize = 0;
        uint32_t logSumExpSize = 0;
        uint32_t FDParamNums = CalcBalanceFDParamNums(actCoreNum);
        accumOutSize = FDParamNums * headDimAlign_;
        logSumExpSize =
            2 * FDParamNums * (BYTE_BLOCK / qsfaInfo_->blockTypeSize); // log和sum的存储空间一致，共需要2份内存
        workspaceSize_ += (accumOutSize + logSumExpSize) * qsfaInfo_->blockTypeSize;
        if (qsfaInfo_->npuArch == NpuArch::DAV_2002) {              // 310P
            workspaceSize_ += static_cast<size_t>(actCoreNum) * 32; // 每个核SyncAll软同步需要32Byte记录状态
        }
    }
}

void QSFAMlaTiling::CalcFDWorkSpace(const uint32_t actCoreNum) { NormalCalcFDWorkSpace(actCoreNum); }

void QSFAMlaTiling::GetWorkspaceSize()
{
    uint32_t actCoreNum = coreNum_;
    if (qsfaInfo_->isA5) {
        workspaceSize_ = libapiSize_;
        constexpr uint32_t TRIPLE_BUFFER_NUM = 3;
        constexpr uint32_t S2_BASE_SIZE = 128; // S2轴基本块大小
        constexpr uint32_t D_SIZE = 576;
        auto ascendcPlatform = platform_ascendc::PlatformAscendC(qsfaInfo_->platformInfo);
        uint32_t aicNum = ascendcPlatform.GetCoreNumAic();
        if (qsfaInfo_->gSize > 64) { // G大于64时核间切G，V0结果出核，需申请GM空间
            workspaceSize_ +=
                (S2_BASE_SIZE * D_SIZE * GetTypeSize(qsfaInfo_->inputQType) * TRIPLE_BUFFER_NUM * (aicNum >> 1));
        }
    } else {
        uint32_t mmResElemSize = 4;       // 4:fp32
        uint32_t vec1ResElemSize = 2;     // 2:fp16/bf16
        uint32_t bmm2ResElemSize = 4;     // 4:fp32
        uint32_t qPreProcResElemSize = 0; // 普通场景不涉及Q预处理
        uint32_t softmaxSumElemSize = 4;  // 4:int32
        workspaceSize_ = libapiSize_;
        uint32_t preLoadNum = 1;
        preLoadNum = PRE_LOAD_NUM;

        workspaceSize_ += static_cast<size_t>(preLoadNum) * mmResUbSize_ * actCoreNum * mmResElemSize;
        workspaceSize_ += static_cast<size_t>(preLoadNum) * mmResUbSize_ * actCoreNum * vec1ResElemSize;
        workspaceSize_ += static_cast<size_t>(preLoadNum) * bmm2ResUbSize_ * actCoreNum * bmm2ResElemSize;
        workspaceSize_ += static_cast<size_t>(preLoadNum) * qPreSizeMla_ * actCoreNum * qPreProcResElemSize;
        workspaceSize_ += static_cast<size_t>(preLoadNum) * mBaseSize_ * actCoreNum * softmaxSumElemSize;
        workspaceSize_ += static_cast<size_t>(preLoadNum) * bmm2ResUbSize_ * actCoreNum * bmm2ResElemSize;
        // topk BlkSize == 1场景, 需要额外空间缓存离散聚合的值
        //              bufNum  s2Base   D   dRope  sizeOf(half)
        // 4:bufNum  512:s2Base  512:D  64:dRope  2:sizeOf(half)
        workspaceSize_ += 4 * 512 * (512 + 64) * 2 * actCoreNum;
        // 缓存有效mte2 size的长度 份数  512B对齐的长度  sizeof(int32_t)   aiv核数
        workspaceSize_ +=
            4 * 128 * 4 * (2 * actCoreNum); // 4:缓存有效mte2 size的长度 128:份数  4:512B对齐的长度  2:aiv核数
    }

    CalcFDWorkSpace(actCoreNum);
}

void QSFAMlaTiling::CalcBlockDim()
{
    auto ascendcPlatform = platform_ascendc::PlatformAscendC(qsfaInfo_->platformInfo);
    auto aicNum = usedCoreNum_;
    auto aivNum = 2 * usedCoreNum_;

    blockDim_ = ascendcPlatform.CalcTschBlockDim(aivNum, aicNum, aivNum);
    OPS_LOG_I(qsfaInfo_->opName, "QSFA block dim: %u aiv Num: %u aic Num: %u.", blockDim_, aivNum, aicNum);
}

ge::graphStatus QSFAMlaTiling::DoOpTiling(QSFATilingInfo *qsfaInfo)
{
    qsfaInfo_ = qsfaInfo;
    if (GetPlatformInfo() != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    InitParams();
    Split();
    FillTiling();
    CalcBlockDim();
    GetWorkspaceSize();
    GenTilingKey();

    if ((SetBlockDim(blockDim_) != ge::GRAPH_SUCCESS) || (SetTilingKey(tilingKey_) != ge::GRAPH_SUCCESS) ||
        (SetWorkspaceSize(workspaceSize_) != ge::GRAPH_SUCCESS) || (SetTilingData(tilingData_) != ge::GRAPH_SUCCESS)) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus TilingGatherSelectionSparseFlashAttention(gert::TilingContext *context)
{
    QSFATilingInfo qsfaInfo;
    QSFAInfoParser qsfaInfoParser(context);
    if (qsfaInfoParser.Parse(qsfaInfo) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    QSFATilingCheck tilingChecker(qsfaInfo);
    if (tilingChecker.Process() != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    QSFAMlaTiling tiling(context);
    return tiling.DoOpTiling(&qsfaInfo);
}

ge::graphStatus TilingPrepareForGatherSelectionSparseFlashAttention(gert::TilingParseContext *const context)
{
    (void)context;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::GetExpectedShape(gert::Shape &shapeExpected, const QSFATilingShapeCompareParam &param,
                                                  const QSFALayout &layout) const
{
    if (layout == QSFALayout::BSND) {
        shapeExpected = gert::Shape({param.B, param.S, param.N, param.D});
    } else if (layout == QSFALayout::TND) {
        shapeExpected = gert::Shape({param.T, param.N, param.D});
    } else if (layout == QSFALayout::PA_BSND) {
        shapeExpected = gert::Shape({param.Bn, param.Bs, param.N, param.D});
    } else {
        OPS_LOG_E(opName_, "layout %s is unsupported", QSFALayoutToSerialString(layout).c_str());
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CompareShape(QSFATilingShapeCompareParam &param, const gert::Shape &shape,
                                              const QSFALayout &layout, const std::string &name) const
{
    gert::Shape qsfaShapeExpected;
    if (GetExpectedShape(qsfaShapeExpected, param, layout) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    if (shape.GetDimNum() != qsfaShapeExpected.GetDimNum()) {
        OpLogeForInvalidShapedimWithReason(
            opName_, name.c_str(), std::to_string(shape.GetDimNum()).c_str(),
            "The shape dim of " + name + " must be " + std::to_string(qsfaShapeExpected.GetDimNum()));

        return ge::GRAPH_FAILED;
    }

    for (size_t i = 0; i < shape.GetDimNum(); i++) {
        if (shape.GetDim(i) != qsfaShapeExpected.GetDim(i)) {
            OpLogeForInvalidShape(opName_, name.c_str(), ToStringRaw(shape).c_str(),
                                  ToStringRaw(qsfaShapeExpected).c_str());
            return ge::GRAPH_FAILED;
        }
    }

    return ge::GRAPH_SUCCESS;
}

void QSFATilingCheck::LogErrorDtypeSupport(const std::vector<ge::DataType> &expectDtypeList,
                                           const ge::DataType &actualDtype, const std::string &name) const
{
    std::ostringstream qsfaOss;
    for (size_t i = 0; i < expectDtypeList.size(); ++i) {
        qsfaOss << QSFADataTypeToSerialString(expectDtypeList[i]);
        if (i < expectDtypeList.size() - 1) {
            qsfaOss << ", ";
        }
    }
    OpLogeForInvalidDtypeWithReason(opName_, name.c_str(), QSFADataTypeToSerialString(actualDtype).c_str(),
                                    "The dtype of " + name + " must be " + qsfaOss.str());
}

ge::graphStatus QSFATilingCheck::CheckDtypeSupport(const gert::CompileTimeTensorDesc *qsfaDesc,
                                                   const std::string &name) const
{
    if (qsfaDesc != nullptr) {
        const auto &qsfaIt = DTYPE_SUPPORT_MAP.find(name);
        OP_CHECK(qsfaIt == DTYPE_SUPPORT_MAP.end(),
                    OPS_LOG_E(opName_, "%s datatype support list should be specify in DTYPE_SUPPORT_MAP", name.c_str()),
                    return ge::GRAPH_FAILED);
        auto &qsfaExpectDtypeList = qsfaIt->second;
        OP_CHECK(std::find(qsfaExpectDtypeList.begin(), qsfaExpectDtypeList.end(), qsfaDesc->GetDataType()) ==
                        qsfaExpectDtypeList.end(),
                    LogErrorDtypeSupport(qsfaExpectDtypeList, qsfaDesc->GetDataType(), name), return ge::GRAPH_FAILED);
    }
    return ge::GRAPH_SUCCESS;
}

template <typename T>
void QSFATilingCheck::LogErrorNumberSupport(const std::vector<T> &expectNumberList, const T &actualValue,
                                            const std::string &name, const std::string subName) const
{
    std::ostringstream qsfaOssNum;
    size_t count = expectNumberList.size();
    for (size_t i = 0; i < count; ++i) {
        if (i > 0) {
            if (i == count - 1) {
                qsfaOssNum << " or ";
            } else {
                qsfaOssNum << ", ";
            }
        }
        qsfaOssNum << std::to_string(expectNumberList[i]);
    }

    OpLogeForInvalidValue(opName_, (name + " " + subName).c_str(), std::to_string(actualValue).c_str(),
                          qsfaOssNum.str());
}

template <typename T>
void QSFATilingCheck::LogErrorDimNumSupport(const std::vector<T> &expectNumberList, const T &actualValue,
                                            const std::string &name) const
{
    LogErrorNumberSupport(expectNumberList, actualValue, name, "dimension");
}

ge::graphStatus QSFATilingCheck::CheckDimNumInLayoutSupport(const QSFALayout &layout, const gert::StorageShape *shape,
                                                            const std::string &name) const
{
    const auto &qsfaDimIt = QSFA_LAYOUT_DIM_MAP.find(layout);
    OP_CHECK(shape->GetStorageShape().GetDimNum() != qsfaDimIt->second,
                OpLogeForInvalidShapedimWithReason(
                    opName_, name.c_str(), std::to_string(shape->GetStorageShape().GetDimNum()).c_str(),
                    "When layout is " + QSFALayoutToSerialString(layout) + ", the shape dim of " + name +
                        " should be " + std::to_string(qsfaDimIt->second)),
                return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckDimNumSupport(const gert::StorageShape *shape,
                                                    const std::vector<size_t> &qsfaExpectDimNumList,
                                                    const std::string &name) const
{
    if (shape == nullptr) {
        return ge::GRAPH_SUCCESS;
    }

    if (std::find(qsfaExpectDimNumList.begin(), qsfaExpectDimNumList.end(), shape->GetStorageShape().GetDimNum()) ==
        qsfaExpectDimNumList.end()) {
        LogErrorDimNumSupport(qsfaExpectDimNumList, shape->GetStorageShape().GetDimNum(), name);
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

void QSFATilingCheck::LogErrorLayoutSupport(const std::vector<QSFALayout> &expectLayoutList,
                                            const QSFALayout &actualLayout, const std::string &name) const
{
    std::ostringstream qsfaOssLayout;
    for (size_t i = 0; i < expectLayoutList.size(); ++i) {
        qsfaOssLayout << QSFALayoutToSerialString(expectLayoutList[i]);
        if (i < expectLayoutList.size() - 1) {
            qsfaOssLayout << ", ";
        }
    }
    OpLogeForInvalidValueWithReason(opName_, name.c_str(), QSFALayoutToSerialString(actualLayout).c_str(),
                                    "Tensor " + name + " only supports layout " + qsfaOssLayout.str());
}

ge::graphStatus QSFATilingCheck::CheckLayoutSupport(const QSFALayout &actualLayout, const std::string &name) const
{
    const auto &qsfaItLayout = LAYOUT_SUPPORT_MAP.find(name);
    OP_CHECK(qsfaItLayout == LAYOUT_SUPPORT_MAP.end(),
                OPS_LOG_E(opName_, "%s layout support list should be specify in LAYOUT_SUPPORT_MAP", name.c_str()),
                return ge::GRAPH_FAILED);
    auto &qsfaExpectLayoutList = qsfaItLayout->second;
    OP_CHECK(
        std::find(qsfaExpectLayoutList.begin(), qsfaExpectLayoutList.end(), actualLayout) == qsfaExpectLayoutList.end(),
        LogErrorLayoutSupport(qsfaExpectLayoutList, actualLayout, name), return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaQuery() const
{
    const std::vector<size_t> qsfaQueryDimNumList = {DIM_NUM_THREE, DIM_NUM_FOUR};
    if (ge::GRAPH_SUCCESS != CheckDtypeSupport(opParamInfo_.query.desc, QUERY_NAME) ||
        ge::GRAPH_SUCCESS != CheckLayoutSupport(qLayout_, QUERY_NAME) ||
        ge::GRAPH_SUCCESS != CheckDimNumSupport(opParamInfo_.query.shape, qsfaQueryDimNumList, QUERY_NAME) ||
        ge::GRAPH_SUCCESS != CheckDimNumInLayoutSupport(qLayout_, opParamInfo_.query.shape, QUERY_NAME)) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaKey() const
{
    const std::vector<size_t> qsfaKeyDimNumList = {DIM_NUM_THREE, DIM_NUM_FOUR};
    if (ge::GRAPH_SUCCESS != CheckDtypeSupport(opParamInfo_.key.desc, KEY_NAME) ||
        ge::GRAPH_SUCCESS != CheckLayoutSupport(kvLayout_, KEY_NAME) ||
        ge::GRAPH_SUCCESS != CheckDimNumSupport(opParamInfo_.key.shape, qsfaKeyDimNumList, KEY_NAME) ||
        ge::GRAPH_SUCCESS != CheckDimNumInLayoutSupport(kvLayout_, opParamInfo_.key.shape, KEY_NAME)) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaNumHeads() const { return ge::GRAPH_SUCCESS; }

ge::graphStatus QSFATilingCheck::CheckSingleParaKvHeadNums() const { return ge::GRAPH_SUCCESS; }

ge::graphStatus QSFATilingCheck::CheckSingleParaSparseMode() const
{
    OP_CHECK(
        (*opParamInfo_.sparseMode != 3 && *opParamInfo_.sparseMode != 0),
        OpLogeForInvalidValueWithReason(opName_, "sparse_mode", std::to_string(*opParamInfo_.sparseMode).c_str(),
                                              "Sparse_mode must be 0 or 3"),
        return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaSparseBlockSize() const
{
    OP_CHECK((npuArch_ == NpuArch::DAV_2201) &&
                    ((*opParamInfo_.sparseBlockSize <= 0 || *opParamInfo_.sparseBlockSize > 16) ||
                     (static_cast<uint64_t>(*opParamInfo_.sparseBlockSize) &
                      static_cast<uint64_t>(*opParamInfo_.sparseBlockSize - 1L)) != 0UL),
                OpLogeForInvalidValueWithReason(opName_, "sparse_block_size",
                                                      std::to_string(*opParamInfo_.sparseBlockSize).c_str(),
                                                      "Sparse_block_size must be in range [1, 16] and be a power of 2"),
                return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaSparseIndices() const
{
    if (ge::GRAPH_SUCCESS != CheckDtypeSupport(opParamInfo_.sparseIndices.desc, SPARSE_INDICES_NAME)) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSingleParaSinks() const
{
    if (opParamInfo_.sinks.tensor == nullptr or opParamInfo_.sinks.desc == nullptr) {
        return ge::GRAPH_SUCCESS;
    }

    OP_CHECK(
        !isA5_,
        OpLogeForInvalidArgumentWithReason(
            opName_, SINKS_NAME.c_str(), "sinks is not supported on the current platform. It should be nullptr."),
        return ge::GRAPH_FAILED);

    if (ge::GRAPH_SUCCESS != CheckDtypeSupport(opParamInfo_.sinks.desc, SINKS_NAME)) {
        return ge::GRAPH_FAILED;
    }

    const gert::Shape &sinksShape = opParamInfo_.sinks.tensor->GetStorageShape();
    OP_CHECK(sinksShape.GetDimNum() != DIM_NUM_ONE,
                OpLogeForInvalidShapedimWithReason(opName_, SINKS_NAME.c_str(),
                                                         std::to_string(sinksShape.GetDimNum()).c_str(),
                                                         "The shape dim of sinks must be 1"),
                return ge::GRAPH_FAILED);

    OP_CHECK(sinksShape.GetShapeSize() != n1Size_,
                OpLogeForInvalidShape(opName_, SINKS_NAME.c_str(), GetShapeStr(sinksShape).c_str(),
                                          GetShapeStr(gert::Shape({n1Size_})).c_str()),
                return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckSinglePara() const
{
    if (ge::GRAPH_SUCCESS != CheckSingleParaQuery() || ge::GRAPH_SUCCESS != CheckSingleParaKey() ||
        ge::GRAPH_SUCCESS != CheckSingleParaSparseIndices() || ge::GRAPH_SUCCESS != CheckSingleParaNumHeads() ||
        ge::GRAPH_SUCCESS != CheckSingleParaKvHeadNums() || ge::GRAPH_SUCCESS != CheckSingleParaSparseMode() ||
        ge::GRAPH_SUCCESS != CheckSingleParaSinks() || ge::GRAPH_SUCCESS != CheckSingleParaSparseBlockSize()) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckDequantScaleNotExistence()
{
    if (quantScaleRepoMode_ == 1) {
        OP_CHECK(
            (opParamInfo_.keyDequantScale.tensor != nullptr || opParamInfo_.valueDequantScale.tensor != nullptr),
            OpLogeForInvalidArgumentWithReason(
                opName_, "key_dequant_scale and value_dequant_scale",
                "When quant_scale_repo_mode is 1(combine), "
                "key_dequant_scale and value_dequant_scale must be stored in packed KV and omitted"),
            return ge::GRAPH_FAILED);
    }
    return ge::GRAPH_SUCCESS;
}

template <typename T>
ge::graphStatus QSFATilingCheck::CheckAttrValueByMap(std::map<std::string, std::pair<const T *, T>> &attrMap) const
{
    for (auto const &kv : attrMap) {
        const std::string &qsfaAttrName = kv.first;
        const std::pair<const T *, T> &qsfaPointerValuePair = kv.second;
        if (qsfaPointerValuePair.first == nullptr) {
            OpLogeForInvalidArgumentWithReason(opName_, qsfaAttrName.c_str(),
                                               qsfaAttrName + " should not be nullptr");
            return ge::GRAPH_FAILED;
        }

        if (*(qsfaPointerValuePair.first) != qsfaPointerValuePair.second) {
            std::ostringstream qsfaOssExpect;
            qsfaOssExpect << std::to_string(qsfaPointerValuePair.second);
            std::ostringstream qsfaOssActual;
            qsfaOssActual << std::to_string(*(qsfaPointerValuePair.first));
            OPS_LOG_E(opName_, "%s value should be %s, but got %s", qsfaAttrName.c_str(),
                      qsfaOssExpect.str().c_str(), qsfaOssActual.str().c_str());
            return ge::GRAPH_FAILED;
        }
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckParaExistenceMlaAntiquant() const
{
    if (kvLayout_ == QSFALayout::BSND) {
        return ge::GRAPH_SUCCESS;
    } else if (kvLayout_ == QSFALayout::TND) {
        OP_CHECK(
            opParamInfo_.actualSeqLengths.tensor == nullptr,
            OpLogeForInvalidArgumentWithReason(opName_, "actual_seq_lengths_kv",
                                                     "When layout_kv is TND, actual_seq_lengths_kv must not be null"),
            return ge::GRAPH_FAILED);
    } else if (kvLayout_ == QSFALayout::PA_BSND) {
        OP_CHECK(
            opParamInfo_.actualSeqLengths.tensor == nullptr,
            OpLogeForInvalidArgumentWithReason(
                opName_, "actual_seq_lengths_kv", "When layout_kv is PA_BSND, actual_seq_lengths_kv must not be null"),
            return ge::GRAPH_FAILED);
        OP_CHECK(opParamInfo_.blockTable.tensor == nullptr,
                    OpLogeForInvalidArgumentWithReason(opName_, "block_table",
                                                             "When layout_kv is PA_BSND, block_table must not be null"),
                    return ge::GRAPH_FAILED);
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckParaExistenceMla() const { return CheckParaExistenceMlaAntiquant(); }

ge::graphStatus QSFATilingCheck::CheckParaExistence()
{
    if (ge::GRAPH_SUCCESS != CheckDequantScaleNotExistence()) {
        return ge::GRAPH_FAILED;
    }

    return CheckParaExistenceMla();
}

static ge::graphStatus GetActualSeqLenSize(uint32_t &size, const gert::Tensor *tensor,
                                           const gert::StorageShape *shape, const std::string &name,
                                           const char *opName)
{
    if (tensor == nullptr || shape == nullptr) {
        OpLogeForInvalidArgumentWithReason(opName, name.c_str(), name + " must be provided");
        return ge::GRAPH_FAILED;
    }
    int64_t qsfaShapeSize = shape->GetStorageShape().GetShapeSize();
    if (qsfaShapeSize <= 0) {
        OpLogeForInvalidShapesizeWithReason(opName, name.c_str(), std::to_string(qsfaShapeSize).c_str(),
                                            "The shape size of " + name + " should be greater than 0");
        return ge::GRAPH_FAILED;
    }
    size = static_cast<uint32_t>(qsfaShapeSize);
    return ge::GRAPH_SUCCESS;
}

void QSFATilingCheck::SetQSFAShapeCompare()
{
    queryShapeCmp_ = opParamInfo_.query.shape->GetStorageShape();
    topkShapeCmp_ = opParamInfo_.sparseIndices.shape->GetStorageShape();
    keyShapeCmp_ = opParamInfo_.key.shape->GetStorageShape();
    valueShapeCmp_ = opParamInfo_.value.shape->GetStorageShape();
    attenOutShapeCmp_ = opParamInfo_.attenOut.shape->GetStorageShape();
}

ge::graphStatus QSFATilingCheck::CheckBlockTable() const
{
    if (kvStorageMode_ != KvStorageMode::PAGE_ATTENTION) {
        OP_CHECK(
            opParamInfo_.blockTable.tensor != nullptr,
            OpLogeForInvalidArgumentWithReason(
                opName_, BLOCK_TABLE_NAME.c_str(),
                "When the layout_kv is " + QSFALayoutToSerialString(kvLayout_) + ", block_table should be null"),
            return ge::GRAPH_FAILED);
        return ge::GRAPH_SUCCESS;
    }

    uint32_t blockTableBatch = opParamInfo_.blockTable.tensor->GetStorageShape().GetDim(0);
    OP_CHECK(
        blockTableBatch != bSize_,
        OpLogeForInvalidShapeWithReason(
            opName_, BLOCK_TABLE_NAME.c_str(), ToStringRaw(opParamInfo_.blockTable.tensor->GetStorageShape()).c_str(),
            "The first dim of " + BLOCK_TABLE_NAME + " should be equal to batch size " + std::to_string(bSize_)),
        return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckDTypeConsistency(const ge::DataType &actualDtype, const ge::DataType &expectDtype,
                                                       const std::string &name) const
{
    if (actualDtype != expectDtype) {
        OpLogeForInvalidDtypeWithReason(
            opName_, name.c_str(), QSFADataTypeToSerialString(actualDtype).c_str(),
            "The dtype of " + name + " must be " + QSFADataTypeToSerialString(expectDtype));
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckTopkShape()
{
    QSFATilingShapeCompareParam qsfaShapeParams;
    qsfaShapeParams.B = bSize_;
    qsfaShapeParams.N = n2Size_;
    qsfaShapeParams.S = s1Size_;
    qsfaShapeParams.D = sparseBlockCount_;
    qsfaShapeParams.T = qTSize_;
    return CompareShape(qsfaShapeParams, topkShapeCmp_, topkLayout_, SPARSE_INDICES_NAME);
}

ge::graphStatus QSFATilingCheck::CheckAttenOutShape()
{
    QSFATilingShapeCompareParam shapeParams;
    shapeParams.B = bSize_;
    shapeParams.N = n1Size_;
    shapeParams.S = s1Size_;
    shapeParams.D = 512; // 512:输出的head_dim
    shapeParams.T = qTSize_;
    if (CompareShape(shapeParams, attenOutShapeCmp_, outLayout_, ATTEN_OUT_NAME) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckAttenOut()
{
    if (ge::GRAPH_SUCCESS !=
            CheckDTypeConsistency(opParamInfo_.attenOut.desc->GetDataType(), inputQType_, ATTEN_OUT_NAME) ||
        ge::GRAPH_SUCCESS != CheckAttenOutShape()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckTopK()
{
    if (ge::GRAPH_SUCCESS != CheckTopkShape()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckKVShapeForBatchContinuous()
{
    QSFATilingShapeCompareParam shapeParams;
    shapeParams.B = bSize_;
    shapeParams.N = n2Size_;
    shapeParams.S = s2Size_;
    shapeParams.D = vHeadDim_;
    shapeParams.T = kvTSize_;
    if (CompareShape(shapeParams, valueShapeCmp_, kvLayout_, VALUE_NAME) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckKVShapeForPageAttention()
{
    int64_t blockNum = keyShapeCmp_.GetDim(0);
    QSFATilingShapeCompareParam shapeParams;
    shapeParams.Bn = blockNum;
    shapeParams.N = n2Size_;
    shapeParams.Bs = blockSize_;
    shapeParams.T = kvTSize_;
    shapeParams.D = vHeadDim_;
    if (CompareShape(shapeParams, valueShapeCmp_, kvLayout_, VALUE_NAME) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckKVShape()
{
    if (kvStorageMode_ == KvStorageMode::BATCH_CONTINUOUS) {
        return CheckKVShapeForBatchContinuous();
    }

    if (kvStorageMode_ == KvStorageMode::PAGE_ATTENTION) {
        return CheckKVShapeForPageAttention();
    }

    OpLogeForInvalidArgumentWithReason(opName_, "key",
                                       "Storage mode of key and value is " +
                                           std::to_string(static_cast<int32_t>(kvStorageMode_)) +
                                           ", it is incorrect");
    return ge::GRAPH_FAILED;
}

ge::graphStatus QSFATilingCheck::CheckKV()
{
    if (ge::GRAPH_SUCCESS != CheckDTypeConsistency(opParamInfo_.value.desc->GetDataType(), inputKvType_, VALUE_NAME)) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLensQ()
{
    if (opParamInfo_.actualSeqLengthsQ.tensor == nullptr) {
        return ge::GRAPH_SUCCESS;
    }
    if (ge::GRAPH_SUCCESS != CheckActualSeqLensQDType() || ge::GRAPH_SUCCESS != CheckActualSeqLensQShape()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLensQDType()
{
    if (opParamInfo_.actualSeqLengthsQ.desc == nullptr) {
        OpLogeForInvalidArgumentWithReason(
            opName_, "actual_seq_lengths_query",
            "Actual_seq_lengths_query is not empty, but the dtype of actual_seq_lengths_query is nullptr");
        return ge::GRAPH_FAILED;
    }

    if (opParamInfo_.actualSeqLengthsQ.desc->GetDataType() != ge::DT_INT32) {
        OpLogeForInvalidDtypeWithReason(
            opName_, "actual_seq_lengths_query",
            QSFADataTypeToSerialString(opParamInfo_.actualSeqLengthsQ.desc->GetDataType()).c_str(),
            "The dtype of actual_seq_lengths_query must be DT_INT32");
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLensQShape()
{
    uint32_t qsfaShapeSize = 0;
    if (GetActualSeqLenSize(qsfaShapeSize, opParamInfo_.actualSeqLengthsQ.tensor,
                            opParamInfo_.actualSeqLengthsQ.shape, "actual_seq_lengths_query", opName_) !=
        ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    if (qsfaShapeSize != bSize_) {
        OpLogeForInvalidShapesizeWithReason(
            opName_, "actual_seq_lengths_query", std::to_string(qsfaShapeSize).c_str(),
            "The shape size of actual_seq_lengths_query should be equal to batch size " + std::to_string(bSize_));
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLens()
{
    if (opParamInfo_.actualSeqLengths.tensor == nullptr) {
        return ge::GRAPH_SUCCESS;
    }
    if (ge::GRAPH_SUCCESS != CheckActualSeqLensDType() || ge::GRAPH_SUCCESS != CheckActualSeqLensShape()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLensDType()
{
    if (opParamInfo_.actualSeqLengths.desc == nullptr) {
        OpLogeForInvalidArgumentWithReason(
            opName_, "actual_seq_lengths_kv",
            "Actual_seq_lengths_kv is not empty, but the dtype of actual_seq_lengths_kv is nullptr");
        return ge::GRAPH_FAILED;
    }
    if (opParamInfo_.actualSeqLengths.desc->GetDataType() != ge::DT_INT32) {
        OpLogeForInvalidDtypeWithReason(
            opName_, "actual_seq_lengths_kv",
            QSFADataTypeToSerialString(opParamInfo_.actualSeqLengthsQ.desc->GetDataType()).c_str(),
            "The dtype of actual_seq_lengths_kv must be DT_INT32");
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckActualSeqLensShape()
{
    uint32_t qsfaShapeSizeKv = 0;
    if (GetActualSeqLenSize(qsfaShapeSizeKv, opParamInfo_.actualSeqLengths.tensor,
                            opParamInfo_.actualSeqLengths.shape, "actual_seq_lengths_kv", opName_) !=
        ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    if (qsfaShapeSizeKv != bSize_) {
        OpLogeForInvalidShapesizeWithReason(
            opName_, "actual_seq_lengths_kv", std::to_string(qsfaShapeSizeKv).c_str(),
            "The shape size of actual_seq_lengths_kv should be equal to batch size " + std::to_string(bSize_));
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckMultiParaConsistency()
{
    SetQSFAShapeCompare();
    if (ge::GRAPH_SUCCESS != CheckKV() || ge::GRAPH_SUCCESS != CheckTopK() || ge::GRAPH_SUCCESS != CheckAttenOut() ||
        ge::GRAPH_SUCCESS != CheckActualSeqLensQ() || ge::GRAPH_SUCCESS != CheckActualSeqLens() ||
        ge::GRAPH_SUCCESS != CheckBlockTable()) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantShape() const
{
    if (ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantShapeSizes() ||
        ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantShapeSparseAndHeadDim()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantShapeSizes() const
{
    OP_CHECK(bSize_ <= 0,
                OpLogeForInvalidShapeWithReason(
                    opName_, "query", ToStringRaw(opParamInfo_.query.shape->GetStorageShape()).c_str(),
                    "Batch_size of query should be greater than 0, but got " + std::to_string(bSize_)),
                return ge::GRAPH_FAILED);

    OP_CHECK(qTSize_ <= 0 && (qLayout_ == QSFALayout::TND),
                OpLogeForInvalidShapeWithReason(
                    opName_, "query", ToStringRaw(opParamInfo_.query.shape->GetStorageShape()).c_str(),
                    "T_size of query should be greater than 0, but got " + std::to_string(qTSize_)),
                return ge::GRAPH_FAILED);

    OP_CHECK(n1Size_ <= 0,
                OpLogeForInvalidShapeWithReason(
                    opName_, "query", ToStringRaw(opParamInfo_.query.shape->GetStorageShape()).c_str(),
                    "The head num of query should be greater than 0, but got " + std::to_string(n1Size_)),
                return ge::GRAPH_FAILED);

    OP_CHECK(n2Size_ != 1,
                OpLogeForInvalidShapeWithReason(
                    opName_, "key", ToStringRaw(opParamInfo_.key.shape->GetStorageShape()).c_str(),
                    "The head num of key should be 1, but got " + std::to_string(n2Size_)),
                return ge::GRAPH_FAILED);

    OP_CHECK(n1Size_ % n2Size_ != 0,
                OpLogeForInvalidShapesWithReason(
                    opName_, "query and key",
                    ToStringRaw(opParamInfo_.query.shape->GetStorageShape()) + " and " +
                        ToStringRaw(opParamInfo_.key.shape->GetStorageShape()),
                    "The head num of query(" + std::to_string(n1Size_) + ") must be divisible by the head num of key(" +
                        std::to_string(n2Size_) + ")"),
                return ge::GRAPH_FAILED);

    if (isA5_) {
        std::vector<uint32_t> gSizeSupportList = {1, 2, 4, 8, 16, 32, 48, 64, 128};
        OP_CHECK(std::find(gSizeSupportList.begin(), gSizeSupportList.end(), gSize_) == gSizeSupportList.end(),
                    OpLogeForInvalidShapesWithReason(
                        opName_, "query and key",
                        ToStringRaw(opParamInfo_.query.shape->GetStorageShape()) + " and " +
                            ToStringRaw(opParamInfo_.key.shape->GetStorageShape()),
                        "The value of (the head num of query ceildivided by the head num of key) "
                        "should be in [1, 2, 4, 8, 16, 32, 48, 64, 128], but got " +
                            std::to_string(gSize_)),
                    return ge::GRAPH_FAILED);
    } else {
        std::vector<uint32_t> gSizeSupportList = {1, 2, 4, 8, 16, 32, 64, 128};
        OP_CHECK(std::find(gSizeSupportList.begin(), gSizeSupportList.end(), gSize_) == gSizeSupportList.end(),
                    OpLogeForInvalidShapesWithReason(
                        opName_, "query and key",
                        ToStringRaw(opParamInfo_.query.shape->GetStorageShape()) + " and " +
                            ToStringRaw(opParamInfo_.key.shape->GetStorageShape()),
                        "The value of (the head num of query ceildivided by the head num of key) "
                        "should be in [1, 2, 4, 8, 16, 32, 64, 128], but got " +
                            std::to_string(gSize_)),
                    return ge::GRAPH_FAILED);
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantShapeSparseAndHeadDim() const
{
    if (isA5_) {
        if (inputKvType_ == ge::DT_HIFLOAT8) {
            OP_CHECK(
                sparseBlockCount_ != 2048,
                OpLogeForInvalidShapeWithReason(
                    opName_, "sparse_indices", ToStringRaw(opParamInfo_.sparseIndices.shape->GetStorageShape()).c_str(),
                    "When the dtypes of key and value are hifloat8, sparse block count must be 2048, but got " +
                        std::to_string(sparseBlockCount_)),
                return ge::GRAPH_FAILED);
        }
        OP_CHECK(
            sparseBlockSize_ != 1,
            OpLogeForInvalidValueWithReason(
                opName_, "sparse_block_size", std::to_string(sparseBlockSize_).c_str(), "Sparse_block_size must be 1"),
            return ge::GRAPH_FAILED);
    } else {
        std::vector<uint32_t> sparseBlockSizeSupportList = {1, 2, 4, 8, 16};
        OP_CHECK(std::find(sparseBlockSizeSupportList.begin(), sparseBlockSizeSupportList.end(), sparseBlockSize_) ==
                        sparseBlockSizeSupportList.end(),
                    OpLogeForInvalidValueWithReason(opName_, "sparse_block_size",
                                                          std::to_string(sparseBlockSize_).c_str(),
                                                          "Group num should be in [1, 2, 4, 8, 16]"),
                    return ge::GRAPH_FAILED);
    }

    OP_CHECK(qHeadDim_ != 576, // 576:当前不泛化
                OpLogeForInvalidShapeWithReason(
                    opName_, "query", ToStringRaw(opParamInfo_.query.shape->GetStorageShape()).c_str(),
                    "The head num of query only support 576, but got " + std::to_string(qHeadDim_)),
                return ge::GRAPH_FAILED);

    OP_CHECK(kHeadDim_ != 656, // 656:当前不泛化
                OpLogeForInvalidShapeWithReason(
                    opName_, "key", ToStringRaw(opParamInfo_.key.shape->GetStorageShape()).c_str(),
                    "The head num of key only support 656, but got " + std::to_string(kHeadDim_)),
                return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantLayout() const
{
    const std::vector<std::string> qsfaLayoutSupportList = {"BSND", "TND"};
    std::string layoutQuery = opParamInfo_.layoutQuery;
    OP_CHECK(std::find(qsfaLayoutSupportList.begin(), qsfaLayoutSupportList.end(), layoutQuery) ==
                    qsfaLayoutSupportList.end(),
                OpLogeForInvalidValueWithReason(opName_, "layout_query", layoutQuery.c_str(),
                                                      "Layout_query only supports BSND or TND"),
                return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantDtype() const
{
    OP_CHECK(
        inputQType_ != ge::DT_BF16 && inputQType_ != ge::DT_FLOAT16,
        OpLogeForInvalidDtypeWithReason(opName_, "query", QSFADataTypeToSerialString(inputQType_).c_str(),
                                              "The dtype of query must be " + QSFADataTypeToSerialString(ge::DT_BF16) +
                                                  " and " + QSFADataTypeToSerialString(ge::DT_FLOAT16)),
        return ge::GRAPH_FAILED);

    if (isA5_) {
        OP_CHECK(
            inputKvType_ != ge::DT_FLOAT8_E4M3FN && inputKvType_ != ge::DT_HIFLOAT8 && inputKvType_ != ge::DT_INT8,
            OpLogeForInvalidDtypesWithReason(
                opName_, "key and value", QSFADataTypeToSerialString(inputKvType_).c_str(),
                "The dtype of key and value must be " + QSFADataTypeToSerialString(ge::DT_FLOAT8_E4M3FN) + ", " +
                    QSFADataTypeToSerialString(ge::DT_HIFLOAT8) + " or " + QSFADataTypeToSerialString(ge::DT_INT8)),
            return ge::GRAPH_FAILED);
    } else {
        OP_CHECK(inputKvType_ != ge::DT_INT8,
                    OpLogeForInvalidDtypesWithReason(
                        opName_, "key and value", QSFADataTypeToSerialString(inputKvType_).c_str(),
                        "The dtype of key and value must be " + QSFADataTypeToSerialString(ge::DT_INT8)),
                    return ge::GRAPH_FAILED);
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantAttr() const
{
    OP_CHECK(attentionMode_ != 2, // 2:MLA-absorb
                OpLogeForInvalidValueWithReason(opName_, "attention_mode", std::to_string(attentionMode_).c_str(),
                                                      "Attention_mode should be 2(MLA-absorb)"),
                return ge::GRAPH_FAILED);

    OP_CHECK(keyQuantMode_ != 2, // 2:per-tile
                OpLogeForInvalidValueWithReason(opName_, "key_quant_mode", std::to_string(keyQuantMode_).c_str(),
                                                      "Key_quant_mode should be 2(per-tile)"),
                return ge::GRAPH_FAILED);

    OP_CHECK(
        valueQuantMode_ != 2, // 2:per-tile
        OpLogeForInvalidValueWithReason(opName_, "value_quant_mode", std::to_string(valueQuantMode_).c_str(),
                                              "Value_quant_mode should be 2(per-tile)"),
        return ge::GRAPH_FAILED);

    OP_CHECK(quantScaleRepoMode_ != 1, // 1:combine
                OpLogeForInvalidValueWithReason(opName_, "quant_scale_repo_mode",
                                                      std::to_string(quantScaleRepoMode_).c_str(),
                                                      "Quant_scale_repo_mode should be 1(combine)"),
                return ge::GRAPH_FAILED);

    OP_CHECK(preTokens_ != INT64_MAX,
                OpLogeForInvalidValueWithReason(opName_, "pre_tokens", std::to_string(preTokens_).c_str(),
                                                      "Pre_tokens should be INT64_MAX"),
                return ge::GRAPH_FAILED);

    OP_CHECK(nextTokens_ != INT64_MAX,
                OpLogeForInvalidValueWithReason(opName_, "next_tokens", std::to_string(nextTokens_).c_str(),
                                                      "Next_tokens should be INT64_MAX"),
                return ge::GRAPH_FAILED);

    OP_CHECK(tileSize_ != 128, // 128:当前不泛化
                OpLogeForInvalidValueWithReason(opName_, "tile_size", std::to_string(tileSize_).c_str(),
                                                      "Tile_size should be 128"),
                return ge::GRAPH_FAILED);

    OP_CHECK(ropeHeadDim_ != 64, // 64:当前不泛化
                OpLogeForInvalidValueWithReason(opName_, "rope_head_dim", std::to_string(ropeHeadDim_).c_str(),
                                                      "Rope_head_dim should be 64"),
                return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquantPa() const
{
    if (kvStorageMode_ != KvStorageMode::PAGE_ATTENTION) {
        return ge::GRAPH_SUCCESS;
    }

    OP_CHECK(blockSize_ <= 0 || blockSize_ > static_cast<int32_t>(MAX_BLOCK_SIZE),
                OpLogeForInvalidShapeWithReason(
                    opName_, "key", ToStringRaw(opParamInfo_.key.shape->GetStorageShape()).c_str(),
                    "When page attention is enabled, block_size(" + std::to_string(blockSize_) +
                        ") should be in range (0, " + std::to_string(MAX_BLOCK_SIZE) + "]"),
                return ge::GRAPH_FAILED);

    OP_CHECK(
        blockSize_ % 16 > 0,
        OpLogeForInvalidShapeWithReason(
            opName_, "key", ToStringRaw(opParamInfo_.key.shape->GetStorageShape()).c_str(),
            "When page attention is enabled, block_size(" + std::to_string(blockSize_) + ") should be 16-aligned"),
        return ge::GRAPH_FAILED);

    OP_CHECK(blockSize_ % sparseBlockSize_ > 0,
                OpLogeForInvalidShapeWithReason(
                    opName_, "key", ToStringRaw(opParamInfo_.key.shape->GetStorageShape()).c_str(),
                    "When page attention is enabled, block_size(" + std::to_string(blockSize_) +
                        ") must be divided by sparse_block_size(" + std::to_string(sparseBlockSize_) +
                        "), but now the remainder is " + std::to_string(blockSize_ % sparseBlockSize_)),
                return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMlaAntiquant() const
{
    if (ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantAttr() || ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantShape() ||
        ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantLayout() || ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantDtype() ||
        ge::GRAPH_SUCCESS != CheckFeatureMlaAntiquantPa()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFATilingCheck::CheckFeatureMla() const { return CheckFeatureMlaAntiquant(); }

ge::graphStatus QSFATilingCheck::CheckFeature() const { return CheckFeatureMla(); }

void QSFATilingCheck::Init()
{
    opName_ = qsfaInfo_.opName;
    platformInfo_ = qsfaInfo_.platformInfo;
    opParamInfo_ = qsfaInfo_.opParamInfo;
    npuArch_ = qsfaInfo_.npuArch;
    isA5_ = qsfaInfo_.isA5;

    bSize_ = qsfaInfo_.bSize;
    n1Size_ = qsfaInfo_.n1Size;
    n2Size_ = qsfaInfo_.n2Size;
    s1Size_ = qsfaInfo_.s1Size;
    s2Size_ = qsfaInfo_.s2Size;
    gSize_ = qsfaInfo_.gSize;
    qHeadDim_ = qsfaInfo_.qHeadDim;
    kHeadDim_ = qsfaInfo_.kHeadDim;
    vHeadDim_ = qsfaInfo_.vHeadDim;
    ropeHeadDim_ = qsfaInfo_.ropeHeadDim;
    maxBlockNumPerBatch_ = qsfaInfo_.maxBlockNumPerBatch;
    qTSize_ = qsfaInfo_.qTSize;
    kvTSize_ = qsfaInfo_.kvTSize;
    blockSize_ = qsfaInfo_.blockSize;
    sparseBlockCount_ = qsfaInfo_.sparseBlockCount;
    sparseBlockSize_ = qsfaInfo_.sparseBlockSize;

    attentionMode_ = qsfaInfo_.attentionMode;
    keyQuantMode_ = qsfaInfo_.keyQuantMode;
    valueQuantMode_ = qsfaInfo_.valueQuantMode;
    quantScaleRepoMode_ = qsfaInfo_.quantScaleRepoMode;
    tileSize_ = qsfaInfo_.tileSize;
    preTokens_ = qsfaInfo_.preTokens;
    nextTokens_ = qsfaInfo_.nextTokens;

    inputQType_ = qsfaInfo_.inputQType;
    inputKvType_ = qsfaInfo_.inputKvType;
    outputType_ = qsfaInfo_.outputType;

    qLayout_ = qsfaInfo_.qLayout;
    topkLayout_ = qsfaInfo_.topkLayout;
    kvLayout_ = qsfaInfo_.kvLayout;
    outLayout_ = qsfaInfo_.outLayout;

    kvStorageMode_ = qsfaInfo_.kvStorageMode;
    l2CacheSize_ = qsfaInfo_.l2CacheSize;
}

ge::graphStatus QSFATilingCheck::Process()
{
    Init();
    if (CheckSinglePara() != ge::GRAPH_SUCCESS || CheckParaExistence() != ge::GRAPH_SUCCESS ||
        CheckFeature() != ge::GRAPH_SUCCESS || CheckMultiParaConsistency() != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

static constexpr int64_t kInvalidDimValue = std::numeric_limits<int64_t>::min();

static bool HasAxis(const QSFAAxis &axis, const QSFALayout &layout, const gert::Shape &shape)
{
    const auto &qsfaLayoutIt = QSFA_LAYOUT_AXIS_MAP.find(layout);
    if (qsfaLayoutIt == QSFA_LAYOUT_AXIS_MAP.end()) {
        return false;
    }

    const std::vector<QSFAAxis> &qsfaAxes = qsfaLayoutIt->second;
    const auto &qsfaAxisIt = std::find(qsfaAxes.begin(), qsfaAxes.end(), axis);
    if (qsfaAxisIt == qsfaAxes.end()) {
        return false;
    }

    const auto &qsfaDimIt = QSFA_LAYOUT_DIM_MAP.find(layout);
    if (qsfaDimIt == QSFA_LAYOUT_DIM_MAP.end() || qsfaDimIt->second != shape.GetDimNum()) {
        return false;
    }

    return true;
}

static size_t GetAxisIdx(const QSFAAxis &axis, const QSFALayout &layout)
{
    const std::vector<QSFAAxis> &axes = QSFA_LAYOUT_AXIS_MAP.find(layout)->second;
    const auto &axisIt = std::find(axes.begin(), axes.end(), axis);

    return std::distance(axes.begin(), axisIt);
}

static uint32_t GetAxisNum(const gert::Shape &shape, const QSFAAxis &axis, const QSFALayout &layout)
{
    return HasAxis(axis, layout, shape) ? shape.GetDim(GetAxisIdx(axis, layout)) : kInvalidDimValue;
}

ge::graphStatus QSFAInfoParser::CheckTensorShapes() const
{
    OP_CHECK(opParamInfo_.query.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "query", "The shape of query is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.key.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "key", "The shape of key is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.value.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "value", "The shape of value is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(
        opParamInfo_.sparseIndices.shape == nullptr,
        OpLogeForInvalidArgumentWithReason(opName_, "sparse_indices", "The shape of sparse_indices is nullptr"),
        return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.selectionBlockStatus.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "selection_kv_block_status",
                                                         "The shape is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.fullKvCache.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "full_kv_cache", "The shape is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.fullBlockTable.shape == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "full_kv_block_table", "The shape is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(
        opParamInfo_.attenOut.shape == nullptr,
        OpLogeForInvalidArgumentWithReason(opName_, "attention_out", "The shape of attention_out is nullptr"),
        return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::CheckTensorDescriptions() const
{
    OP_CHECK(opParamInfo_.query.desc == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "query", "The desc of query is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.key.desc == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "key", "The desc of key is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.value.desc == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "value", "The desc of value is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(
        opParamInfo_.sparseIndices.desc == nullptr,
        OpLogeForInvalidArgumentWithReason(opName_, "sparse_indices", "The desc of sparse_indices is nullptr"),
        return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.selectionBlockStatus.desc == nullptr || opParamInfo_.fullKvCache.desc == nullptr ||
                    opParamInfo_.fullBlockTable.desc == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "selection inputs", "A required desc is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(
        opParamInfo_.attenOut.desc == nullptr,
        OpLogeForInvalidArgumentWithReason(opName_, "attention_out", "The desc of attention_out is nullptr"),
        return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::CheckRequiredInOutExistence() const
{
    ge::graphStatus status = CheckTensorShapes();
    if (status != ge::GRAPH_SUCCESS) {
        return status;
    }

    status = CheckTensorDescriptions();
    if (status != ge::GRAPH_SUCCESS) {
        return status;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::CheckRequiredAttrExistence() const
{
    OP_CHECK(opParamInfo_.layoutQuery == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "layout_query", "Layout_query is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.layoutKV == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "layout_kv", "Layout_kv is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.sparseBlockSize == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "sparse_block_size", "Sparse_block_size is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.scaleValue == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "scale_value", "Scale_value is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(!std::isfinite(*opParamInfo_.scaleValue) || *opParamInfo_.scaleValue <= 0.0F,
                OpLogeForInvalidArgumentWithReason(opName_, "scale_value",
                                                         "Scale_value must be finite and greater than 0"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.sparseMode == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "sparse_mode", "Sparse_mode is nullptr"),
                return ge::GRAPH_FAILED);
    OP_CHECK(opParamInfo_.selectionTopkBlockSize == nullptr,
                OpLogeForInvalidArgumentWithReason(opName_, "selection_topk_block_size", "attr is nullptr"),
                return ge::GRAPH_FAILED);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::CheckRequiredParaExistence() const
{
    if (CheckRequiredInOutExistence() != ge::GRAPH_SUCCESS || CheckRequiredAttrExistence() != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetActualSeqLenQSize(uint32_t &size)
{
    return GetActualSeqLenSize(size, opParamInfo_.actualSeqLengthsQ.tensor, opParamInfo_.actualSeqLengthsQ.shape,
                               "actual_seq_lengths_query", opName_);
}

ge::graphStatus QSFAInfoParser::GetOpName()
{
    if (context_->GetNodeName() == nullptr) {
        OPS_LOG_E("GatherSelectionSparseFlashAttention", "opName got from TilingContext is nullptr");
        return ge::GRAPH_FAILED;
    }
    opName_ = context_->GetNodeName();
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetNpuInfo()
{
    platformInfo_ = context_->GetPlatformInfo();
    OP_CHECK(platformInfo_ == nullptr, OPS_REPORT_VECTOR_INNER_ERR(opName_, "GetPlatformInfo is nullptr."),
                return ge::GRAPH_FAILED);

    auto qsfaAscendcPlat = platform_ascendc::PlatformAscendC(platformInfo_);
    uint32_t qsfaAivNum = qsfaAscendcPlat.GetCoreNumAiv();
    uint32_t qsfaAicNum = qsfaAscendcPlat.GetCoreNumAic();
    OP_CHECK(qsfaAicNum == 0 || qsfaAivNum == 0, OPS_REPORT_VECTOR_INNER_ERR(opName_, "num of core obtained is 0."),
                return GRAPH_FAILED);

    // Older CANN Toolkit used by recipes does not provide GetCurNpuArch().
    // Map via GetSocVersion(); this operator is A3-only (DAV_2201).
    const auto socVersion = qsfaAscendcPlat.GetSocVersion();
    npuArch_ = NpuArch::DAV_2201;
    isA5_ = false;
    if (socVersion != platform_ascendc::SocVersion::ASCEND910B &&
        socVersion != platform_ascendc::SocVersion::ASCEND910) {
        OPS_REPORT_VECTOR_INNER_ERR(opName_,
                                    "SocVersion[%d] is not support for GatherSelectionSparseFlashAttention "
                                    "(need ASCEND910B / ascend910_93).",
                                    static_cast<int32_t>(socVersion));
        return GRAPH_FAILED;
    }

    qsfaAscendcPlat.GetCoreMemSize(platform_ascendc::CoreMemType::L2, l2CacheSize_);

    return ge::GRAPH_SUCCESS;
}

void QSFAInfoParser::GetOptionalInputParaInfo()
{
    opParamInfo_.blockTable.tensor = context_->GetOptionalInputTensor(BLOCK_TABLE_INPUT_INDEX);
    opParamInfo_.blockTable.shape = context_->GetInputShape(BLOCK_TABLE_INPUT_INDEX);
    opParamInfo_.actualSeqLengthsQ.tensor = context_->GetOptionalInputTensor(ACT_SEQ_LEN_Q_INPUT_INDEX);
    opParamInfo_.actualSeqLengthsQ.desc = context_->GetOptionalInputDesc(ACT_SEQ_LEN_Q_INPUT_INDEX);
    opParamInfo_.actualSeqLengthsQ.shape = context_->GetInputShape(ACT_SEQ_LEN_Q_INPUT_INDEX);
    opParamInfo_.actualSeqLengths.tensor = context_->GetOptionalInputTensor(ACT_SEQ_LEN_KV_INPUT_INDEX);
    opParamInfo_.actualSeqLengths.desc = context_->GetOptionalInputDesc(ACT_SEQ_LEN_KV_INPUT_INDEX);
    opParamInfo_.actualSeqLengths.shape = context_->GetInputShape(ACT_SEQ_LEN_KV_INPUT_INDEX);
    opParamInfo_.keyDequantScale.tensor = context_->GetOptionalInputTensor(KEY_DEQUANT_SCALE_INPUT_INDEX);
    opParamInfo_.valueDequantScale.tensor = context_->GetOptionalInputTensor(VALUE_DEQUANT_SCALE_INPUT_INDEX);
    opParamInfo_.sinks.tensor = context_->GetOptionalInputTensor(SINKS_INPUT_INDEX);
    opParamInfo_.sinks.desc = context_->GetOptionalInputDesc(SINKS_INPUT_INDEX);
}

void QSFAInfoParser::GetInputParaInfo()
{
    opParamInfo_.query.desc = context_->GetInputDesc(QUERY_INPUT_INDEX);
    opParamInfo_.query.shape = context_->GetInputShape(QUERY_INPUT_INDEX);
    opParamInfo_.key.desc = context_->GetInputDesc(KEY_INPUT_INDEX);
    opParamInfo_.key.shape = context_->GetInputShape(KEY_INPUT_INDEX);
    opParamInfo_.value.desc = context_->GetInputDesc(VALUE_INPUT_INDEX);
    opParamInfo_.value.shape = context_->GetInputShape(VALUE_INPUT_INDEX);
    opParamInfo_.sparseIndices.desc = context_->GetInputDesc(SPARSE_INDICES_INPUT_INDEX);
    opParamInfo_.sparseIndices.shape = context_->GetInputShape(SPARSE_INDICES_INPUT_INDEX);
    opParamInfo_.selectionBlockStatus.desc = context_->GetInputDesc(SELECTION_BLOCK_STATUS_INPUT_INDEX);
    opParamInfo_.selectionBlockStatus.shape = context_->GetInputShape(SELECTION_BLOCK_STATUS_INPUT_INDEX);
    opParamInfo_.fullKvCache.desc = context_->GetInputDesc(FULL_KV_CACHE_INPUT_INDEX);
    opParamInfo_.fullKvCache.shape = context_->GetInputShape(FULL_KV_CACHE_INPUT_INDEX);
    opParamInfo_.fullBlockTable.desc = context_->GetInputDesc(FULL_BLOCK_TABLE_INPUT_INDEX);
    opParamInfo_.fullBlockTable.shape = context_->GetInputShape(FULL_BLOCK_TABLE_INPUT_INDEX);
    GetOptionalInputParaInfo();
}

void QSFAInfoParser::GetOutputParaInfo()
{
    opParamInfo_.attenOut.desc = context_->GetOutputDesc(OUTPUT_INDEX);
    opParamInfo_.attenOut.shape = context_->GetOutputShape(OUTPUT_INDEX);
}

ge::graphStatus QSFAInfoParser::GetAttrParaInfo()
{
    auto attrs = context_->GetAttrs();
    OP_CHECK(attrs == nullptr, OPS_REPORT_VECTOR_INNER_ERR(context_->GetNodeName(), "attrs got from GE is nullptr"),
                return ge::GRAPH_FAILED);

    opParamInfo_.layoutQuery = attrs->GetStr(LAYOUT_QUERY_ATTR_INDEX);
    opParamInfo_.layoutKV = attrs->GetStr(LAYOUT_KV_ATTR_INDEX);
    opParamInfo_.sparseBlockSize = attrs->GetAttrPointer<int64_t>(SPARSE_BLOCK_SIZE_ATTR_INDEX);
    opParamInfo_.scaleValue = attrs->GetAttrPointer<float>(SCALE_VALUE_ATTR_INDEX);
    opParamInfo_.sparseMode = attrs->GetAttrPointer<int64_t>(SPARSE_MODE_ATTR_INDEX);
    opParamInfo_.keyQuantMode = attrs->GetAttrPointer<int64_t>(KEY_QUANT_MODE_ATTR_INDEX);
    opParamInfo_.valueQuantMode = attrs->GetAttrPointer<int64_t>(VALUE_QUANT_MODE_ATTR_INDEX);
    opParamInfo_.attentionMode = attrs->GetAttrPointer<int64_t>(ATTENTION_MODE_ATTR_INDEX);
    opParamInfo_.preTokens = attrs->GetAttrPointer<int64_t>(PRE_TOKENS_ATTR_INDEX);
    opParamInfo_.nextTokens = attrs->GetAttrPointer<int64_t>(NEXT_TOKENS_ATTR_INDEX);
    opParamInfo_.quantScaleRepoMode = attrs->GetAttrPointer<int64_t>(QUANT_SCALE_REPO_MODE_ATTR_INDEX);
    opParamInfo_.tileSize = attrs->GetAttrPointer<int64_t>(TILE_SIZE_ATTR_INDEX);
    opParamInfo_.ropeHeadDim = attrs->GetAttrPointer<int64_t>(ROPE_HEAD_DIM_ATTR_INDEX);
    opParamInfo_.selectionTopkBlockSize = attrs->GetAttrPointer<int64_t>(SELECTION_TOPK_BLOCK_SIZE_ATTR_INDEX);

    // Older TilingContext has no GetDynamicInputStride(). GSFA is A3-only and
    // GenerateInfo forces keyStride0=0 on non-DAV_3510, so leaving defaults is correct.
    keyStride0_ = 0;
    keyStride1_ = 0;

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetOpParaInfo()
{
    GetInputParaInfo();
    GetOutputParaInfo();
    if (ge::GRAPH_SUCCESS != GetAttrParaInfo()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetInOutDataType()
{
    inputQType_ = opParamInfo_.query.desc->GetDataType();
    inputKvType_ = opParamInfo_.key.desc->GetDataType();
    outputType_ = opParamInfo_.attenOut.desc->GetDataType();
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetBatchSize()
{
    // 获取B基准值
    // 1、非TND时, 以query的batch_size维度为基准;
    // 2、TND时, actual_seq_lens_q必须传入, 以actual_seq_lens_q数组的长度为B轴大小
    if (qLayout_ == QSFALayout::TND) {
        return GetActualSeqLenQSize(bSize_);
    } else { // BSND
        bSize_ = GetAxisNum(queryShape_, QSFAAxis::B, qLayout_);
        return ge::GRAPH_SUCCESS;
    }
}

ge::graphStatus QSFAInfoParser::GetQTSize()
{
    // 获取query的T基准值
    // 1、非TND时, 以query的batch_size维度为基准;
    // 2、TND时, actual_seq_lens_q必须传入, 以actual_seq_lens_q数组的长度为B轴大小
    qTSize_ = (qLayout_ == QSFALayout::TND) ? GetAxisNum(queryShape_, QSFAAxis::T, qLayout_) : 0;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetKVTSize()
{
    // 获取query的T基准值
    // 1、非TND时, 以key的batch_size维度为基准;
    // 2、TND时, actual_seq_lens_q必须传入, 以actual_seq_lens_q数组的长度为B轴大小
    kvTSize_ = (kvLayout_ == QSFALayout::TND) ? GetAxisNum(keyShape_, QSFAAxis::T, kvLayout_) : 0;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetQHeadDim()
{
    // 获取qHeadDim基准值
    // 以query的D维度为基准
    qHeadDim_ = GetAxisNum(queryShape_, QSFAAxis::D, qLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetKHeadDim()
{
    // 获取kHeadDim基准值
    // 以key的D维度为基准
    kHeadDim_ = GetAxisNum(keyShape_, QSFAAxis::D, kvLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetS1Size()
{
    // 获取S1基准值
    // 1、非TND时, 以query的S维度为基准;
    // 2、TND时, actual_seq_lens_q必须传入, 以actual_seq_lens_q数组中的最大值为基准
    if (qLayout_ == QSFALayout::TND) {
        s1Size_ = GetAxisNum(queryShape_, QSFAAxis::T, qLayout_);
        return ge::GRAPH_SUCCESS;
    } else { // BSND
        s1Size_ = GetAxisNum(queryShape_, QSFAAxis::S, qLayout_);
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetKvStorageMode()
{
    if (kvLayout_ == QSFALayout::PA_BSND) {
        kvStorageMode_ = KvStorageMode::PAGE_ATTENTION;
    } else {
        kvStorageMode_ = KvStorageMode::BATCH_CONTINUOUS;
    }
    // kv存储模式基准值
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetKvLayout()
{
    const map<string, QSFALayout> layoutKVMap = {
        {"BSND", QSFALayout::BSND}, {"PA_BSND", QSFALayout::PA_BSND}, {"TND", QSFALayout::TND}};

    std::string layout(opParamInfo_.layoutKV);
    auto it = layoutKVMap.find(layout);
    if (it != layoutKVMap.end()) {
        kvLayout_ = it->second;
    } else {
        OpLogeForInvalidValue(opName_, "layout_kv", layout.c_str(), "BSND, PA_BSND or TND");
        return ge::GRAPH_FAILED;
    }
    if (kvLayout_ != QSFALayout::PA_BSND && qLayout_ != kvLayout_) {
        OpLogeForInvalidValuesWithReason(
            opName_, "layout_kv and layout_query",
            QSFALayoutToSerialString(kvLayout_) + " and " + QSFALayoutToSerialString(qLayout_),
            "When layout_kv is not PA_BSND, layout_kv and layout_query must be same");
        return ge::GRAPH_FAILED;
    }
    uint32_t keyDimNum = opParamInfo_.key.shape->GetStorageShape().GetDimNum();
    if (kvLayout_ == QSFALayout::PA_BSND && keyDimNum != 4U) {
        OpLogeForInvalidShapedimWithReason(opName_, "key", std::to_string(keyDimNum).c_str(),
                                           "When layout_kv is PA_BSND, the dim num of key must be 4");
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetS2SizeForBatchContinuous()
{
    if (kvLayout_ == QSFALayout::BSND) { // BSND
        s2Size_ = GetAxisNum(keyShape_, QSFAAxis::S, kvLayout_);
    } else if (kvLayout_ == QSFALayout::TND) { // TND
        s2Size_ = GetAxisNum(keyShape_, QSFAAxis::T, kvLayout_);
    }

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetMaxBlockNumPerBatch()
{
    if (opParamInfo_.blockTable.tensor == nullptr) {
        OpLogeForInvalidArgumentWithReason(
            opName_, "block_table",
            "The layout_kv is " + QSFALayoutToSerialString(kvLayout_) + ", block_table must be provided");
        return ge::GRAPH_FAILED;
    }
    uint32_t qsfaDimNum = opParamInfo_.blockTable.tensor->GetStorageShape().GetDimNum();
    if (qsfaDimNum != DIM_NUM_TWO) {
        OpLogeForInvalidShapedimWithReason(opName_, "block_table", std::to_string(qsfaDimNum),
                                           "The shape dim of block_table must be " + std::to_string(DIM_NUM_TWO));
        return ge::GRAPH_FAILED;
    }
    if (opParamInfo_.blockTable.tensor->GetStorageShape().GetDim(1) <= 0) {
        OpLogeForInvalidShapeWithReason(opName_, "block_table",
                                        ToStringRaw(opParamInfo_.blockTable.tensor->GetStorageShape()).c_str(),
                                        "The second dim of block_table should be greater than 0");
        return ge::GRAPH_FAILED;
    }
    maxBlockNumPerBatch_ = opParamInfo_.blockTable.tensor->GetStorageShape().GetDim(1);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetSparseBlockCount()
{
    sparseBlockCount_ = GetAxisNum(sparseIndicesShape_, QSFAAxis::K, qLayout_);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetBlockSize()
{
    blockSize_ = GetAxisNum(keyShape_, QSFAAxis::Bs, kvLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetS2SizeForPageAttention()
{
    if (GetMaxBlockNumPerBatch() != ge::GRAPH_SUCCESS || GetBlockSize() != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    s2Size_ = maxBlockNumPerBatch_ * blockSize_;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetS2Size()
{
    // 获取S2基准值
    // 1、BATCH_CONTINUOUS时, 从key的S轴获取
    // 2、PAGE_ATTENTION时, S2 = block_table.dim1 * block_size
    if (kvStorageMode_ == KvStorageMode::BATCH_CONTINUOUS) {
        return GetS2SizeForBatchContinuous();
    }
    return GetS2SizeForPageAttention();
}

ge::graphStatus QSFAInfoParser::GetValueHeadDim()
{
    // 获取vHeadDim基准值
    // 以value的D维度为基准
    vHeadDim_ = GetAxisNum(valueShape_, QSFAAxis::D, kvLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetDSizeKV()
{
    dSizeKV_ = GetAxisNum(keyShape_, QSFAAxis::D, kvLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetQueryAndOutLayout()
{
    // 获取query和attentionOut的Layout基准值
    // layoutQuery: {qLayout, outLayout}
    const std::map<std::string, std::pair<QSFALayout, QSFALayout>> qsfaLayoutMap = {
        {"BSND", {QSFALayout::BSND, QSFALayout::BSND}},
        {"TND", {QSFALayout::TND, QSFALayout::TND}},
    };

    std::string qsfaLayout(opParamInfo_.layoutQuery);
    auto qsfaLayoutIt = qsfaLayoutMap.find(qsfaLayout);
    if (qsfaLayoutIt != qsfaLayoutMap.end()) {
        qLayout_ = qsfaLayoutIt->second.first;
        outLayout_ = qsfaLayoutIt->second.second;
    } else {
        OpLogeForInvalidValue(opName_, "layout_query", qsfaLayout.c_str(), "BSND or TND");
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetTopkLayout()
{
    topkLayout_ = qLayout_;
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetN1Size()
{
    n1Size_ = GetAxisNum(queryShape_, QSFAAxis::N, qLayout_);
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetN2Size()
{
    n2Size_ = GetAxisNum(keyShape_, QSFAAxis::N, kvLayout_);
    return ge::GRAPH_SUCCESS;
}

void QSFAInfoParser::SetQSFAShape()
{
    queryShape_ = opParamInfo_.query.shape->GetStorageShape();
    keyShape_ = opParamInfo_.key.shape->GetStorageShape();

    valueShape_ = opParamInfo_.value.shape->GetStorageShape();
    sparseIndicesShape_ = opParamInfo_.sparseIndices.shape->GetStorageShape();
}

ge::graphStatus QSFAInfoParser::GetGSize()
{
    if (n2Size_ != 0) {
        gSize_ = n1Size_ / n2Size_;
    }
    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetActualseqInfo()
{
    maxActualseq_ = static_cast<uint32_t>(s2Size_);
    if (opParamInfo_.actualSeqLengths.tensor != nullptr) {
        actualLenDimsKV_ = opParamInfo_.actualSeqLengths.tensor->GetShapeSize();
    }
    if (opParamInfo_.actualSeqLengthsQ.tensor != nullptr) {
        actualLenDimsQ_ = opParamInfo_.actualSeqLengthsQ.tensor->GetShapeSize();
    }
    return ge::GRAPH_SUCCESS;
}

// 非连续校验：通过shape计算expected stride进行校验
// PA_BSND时，只允许0轴非连续，其余轴必须连续
// 非PA_BSND时，所有轴都必须连续
ge::graphStatus QSFAInfoParser::CheckContiguous() const
{
    if (!isA5_) {
        return ge::GRAPH_SUCCESS;
    }

    bool keyNonContiguous = false;
    if (keyStride0_ != 0 && keyShape_.GetDimNum() > 0) {
        uint64_t totalElements = 0;
        uint64_t shapeSize = 0;

        if (kvLayout_ == QSFALayout::PA_BSND) {
            totalElements = keyStride1_ * static_cast<uint64_t>(keyShape_.GetDim(1));
            shapeSize = static_cast<uint64_t>(keyShape_.GetDim(1)) * static_cast<uint64_t>(keyShape_.GetDim(2U)) *
                        static_cast<uint64_t>(keyShape_.GetDim(3U));
        } else {
            totalElements = keyStride0_ * static_cast<uint64_t>(keyShape_.GetDim(0));
            shapeSize = static_cast<uint64_t>(context_->GetOptionalInputTensor(KEY_INPUT_INDEX)->GetShapeSize());
        }
        keyNonContiguous = (shapeSize != totalElements);
    }

    OP_CHECK(keyNonContiguous,
                OpLogeForInvalidArgumentWithReason(
                    opName_, "key", "Key only supports non-contiguous tensor on the 0-axis in PA scenarios"),
                return ge::GRAPH_FAILED);

    return ge::GRAPH_SUCCESS;
}

ge::graphStatus QSFAInfoParser::GetShapeAndSizeInfo()
{
    SetQSFAShape();
    if (ge::GRAPH_SUCCESS != GetN1Size() || ge::GRAPH_SUCCESS != GetN2Size() || ge::GRAPH_SUCCESS != GetGSize() ||
        ge::GRAPH_SUCCESS != GetBatchSize() || ge::GRAPH_SUCCESS != GetQTSize() || ge::GRAPH_SUCCESS != GetKVTSize() ||
        ge::GRAPH_SUCCESS != GetS1Size() || ge::GRAPH_SUCCESS != GetQHeadDim() || ge::GRAPH_SUCCESS != GetKHeadDim() ||
        ge::GRAPH_SUCCESS != GetS2Size() || ge::GRAPH_SUCCESS != GetValueHeadDim() ||
        ge::GRAPH_SUCCESS != GetDSizeKV() || ge::GRAPH_SUCCESS != GetSparseBlockCount()) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

void QSFAInfoParser::GenerateInfo(QSFATilingInfo &qsfaInfo)
{
    qsfaInfo.opName = opName_;
    qsfaInfo.platformInfo = platformInfo_;
    qsfaInfo.opParamInfo = opParamInfo_;
    qsfaInfo.npuArch = npuArch_;
    qsfaInfo.isA5 = isA5_;

    qsfaInfo.bSize = bSize_;
    qsfaInfo.n1Size = n1Size_;
    qsfaInfo.n2Size = n2Size_;
    qsfaInfo.s1Size = s1Size_;
    qsfaInfo.s2Size = s2Size_;
    qsfaInfo.gSize = gSize_;
    qsfaInfo.qHeadDim = qHeadDim_;
    qsfaInfo.kHeadDim = kHeadDim_;
    qsfaInfo.vHeadDim = vHeadDim_;
    qsfaInfo.qTSize = qTSize_;
    qsfaInfo.kvTSize = kvTSize_;
    qsfaInfo.sparseBlockSize = *opParamInfo_.sparseBlockSize;
    qsfaInfo.sparseBlockCount = sparseBlockCount_;

    qsfaInfo.inputQType = inputQType_;
    qsfaInfo.inputKvType = inputKvType_;
    qsfaInfo.outputType = outputType_;

    qsfaInfo.kvStorageMode = kvStorageMode_;
    qsfaInfo.l2CacheSize = l2CacheSize_;

    qsfaInfo.totalBlockNum = opParamInfo_.key.shape->GetStorageShape().GetDim(0);
    qsfaInfo.scaleValue = *opParamInfo_.scaleValue;
    qsfaInfo.pageAttentionFlag = (kvStorageMode_ == KvStorageMode::PAGE_ATTENTION);
    qsfaInfo.blockSize = blockSize_;
    qsfaInfo.blockTypeSize = sizeof(float);
    qsfaInfo.maxBlockNumPerBatch = maxBlockNumPerBatch_;
    const gert::Shape &statusShape = opParamInfo_.selectionBlockStatus.shape->GetStorageShape();
    const gert::Shape &fullKvShape = opParamInfo_.fullKvCache.shape->GetStorageShape();
    const gert::Shape &fullBlockTableShape = opParamInfo_.fullBlockTable.shape->GetStorageShape();
    qsfaInfo.selectionStatusStride = statusShape.GetDim(statusShape.GetDimNum() - 1);
    qsfaInfo.selectionMaxBlockNum = maxBlockNumPerBatch_;
    qsfaInfo.selectionBlockSize = blockSize_;
    qsfaInfo.selectionPhysicalBlockCount =
        static_cast<uint32_t>(opParamInfo_.key.shape->GetStorageShape().GetDim(0));
    qsfaInfo.fullMaxBlockNum = fullBlockTableShape.GetDim(1);
    qsfaInfo.fullBlockSize = fullKvShape.GetDim(1);
    qsfaInfo.fullPhysicalBlockCount = static_cast<uint32_t>(fullKvShape.GetDim(0));

    if (npuArch_ != NpuArch::DAV_3510) {
        qsfaInfo.keyStride0 = 0; // 910无需使用stride
    } else {
        if (keyStride0_ != 0) {
            qsfaInfo.keyStride0 = keyStride0_;
        } else if (kvLayout_ == QSFALayout::PA_BSND) {
            qsfaInfo.keyStride0 = blockSize_ * dSizeKV_;
        } else {
            qsfaInfo.keyStride0 = 0; // 非PA无需使用stride
        }
    }

    FillTilingInfoAttrsAndLayouts(qsfaInfo);
}

void QSFAInfoParser::FillTilingInfoAttrsAndLayouts(QSFATilingInfo &qsfaInfo)
{
    qsfaInfo.actualLenDimsQ = actualLenDimsQ_;
    qsfaInfo.actualLenDimsKV = actualLenDimsKV_;
    qsfaInfo.maxActualseq = maxActualseq_;

    qsfaInfo.actualQSeqLenFlag = (opParamInfo_.actualSeqLengthsQ.tensor != nullptr);
    qsfaInfo.actualSeqLenFlag = (opParamInfo_.actualSeqLengths.tensor != nullptr);

    qsfaInfo.isSameSeqAllKVTensor = isSameSeqAllKVTensor_;
    qsfaInfo.isSameActualseq = isSameActualseq_;

    qsfaInfo.sparseMode = *opParamInfo_.sparseMode;
    qsfaInfo.attentionMode = *opParamInfo_.attentionMode;
    qsfaInfo.keyQuantMode = *opParamInfo_.keyQuantMode;
    qsfaInfo.valueQuantMode = *opParamInfo_.valueQuantMode;
    qsfaInfo.quantScaleRepoMode = *opParamInfo_.quantScaleRepoMode;
    qsfaInfo.preTokens = *opParamInfo_.preTokens;
    qsfaInfo.nextTokens = *opParamInfo_.nextTokens;
    qsfaInfo.tileSize = *opParamInfo_.tileSize;
    qsfaInfo.ropeHeadDim = *opParamInfo_.ropeHeadDim;

    qsfaInfo.qLayout = qLayout_;
    qsfaInfo.topkLayout = topkLayout_;
    qsfaInfo.kvLayout = kvLayout_;
    qsfaInfo.outLayout = outLayout_;
    qsfaInfo.dSizeVInput = dSizeKV_;
}

ge::graphStatus QSFAInfoParser::Parse(QSFATilingInfo &qsfaInfo)
{
    if (context_ == nullptr) {
        OPS_LOG_E("GatherSelectionSparseFlashAttention", "tiling context is nullptr");
        return ge::GRAPH_FAILED;
    }
    if (ge::GRAPH_SUCCESS != GetOpName() || ge::GRAPH_SUCCESS != GetNpuInfo() || ge::GRAPH_SUCCESS != GetOpParaInfo() ||
        ge::GRAPH_SUCCESS != CheckRequiredParaExistence()) {
        return ge::GRAPH_FAILED;
    }

    if (ge::GRAPH_SUCCESS != GetInOutDataType() || ge::GRAPH_SUCCESS != GetQueryAndOutLayout() ||
        ge::GRAPH_SUCCESS != GetTopkLayout() || ge::GRAPH_SUCCESS != GetKvLayout() ||
        ge::GRAPH_SUCCESS != GetKvStorageMode()) {
        return ge::GRAPH_FAILED;
    }

    if (ge::GRAPH_SUCCESS != GetShapeAndSizeInfo()) {
        return ge::GRAPH_FAILED;
    }

    const gert::Shape &statusShape = opParamInfo_.selectionBlockStatus.shape->GetStorageShape();
    const gert::Shape &fullKvShape = opParamInfo_.fullKvCache.shape->GetStorageShape();
    const gert::Shape &fullBlockTableShape = opParamInfo_.fullBlockTable.shape->GetStorageShape();
    // Layout: keep TND + PA as the supported fused path (arch22 MLA absorb).
    OP_CHECK(qLayout_ != QSFALayout::TND || kvLayout_ != QSFALayout::PA_BSND,
                OPS_LOG_E(opName_, "fused kernel currently supports TND query and PA_BSND KV"),
                return ge::GRAPH_FAILED);
    // Token-level fused MergeKv staging currently assumes block size 1 (topk index == S2 index).
    OP_CHECK(*opParamInfo_.sparseBlockSize != 1 || *opParamInfo_.selectionTopkBlockSize != 1,
             OPS_LOG_E(opName_,
                       "sparse_block_size and selection_topk_block_size must both be 1 for the fused MergeKv path"),
             return ge::GRAPH_FAILED);
    // status last dim is topk+1; leading dims must cover the selection rows (T or B*S).
    OP_CHECK(statusShape.GetDimNum() < DIM_NUM_TWO ||
                    statusShape.GetDim(statusShape.GetDimNum() - 1) != sparseBlockCount_ + 1,
                OPS_LOG_E(opName_, "selection_kv_block_status last dim must be topk+1 (%ld)",
                        static_cast<long>(sparseBlockCount_ + 1)),
                return ge::GRAPH_FAILED);
    const int64_t statusRows = statusShape.GetShapeSize() / (sparseBlockCount_ + 1);
    OP_CHECK(statusRows < static_cast<int64_t>(bSize_),
                OPS_LOG_E(opName_, "selection_kv_block_status rows (%ld) must cover batch/token rows (%u)",
                        static_cast<long>(statusRows), bSize_),
                return ge::GRAPH_FAILED);
    // topk: positive and within QSFA sparse limit (not hard-coded to exactly 2048).
    OP_CHECK(sparseBlockCount_ <= 0 || sparseBlockCount_ > static_cast<int64_t>(SPARSE_LIMIT),
                OPS_LOG_E(opName_, "selection_topk_indices K must be in (0, %u], got %ld", SPARSE_LIMIT,
                        static_cast<long>(sparseBlockCount_)),
                return ge::GRAPH_FAILED);
    OP_CHECK(maxBlockNumPerBatch_ <= 0 ||
                    static_cast<int64_t>(maxBlockNumPerBatch_) * blockSize_ < sparseBlockCount_,
                OPS_LOG_E(opName_, "selection_kv_block_table capacity must cover topk slots"),
                return ge::GRAPH_FAILED);
    OP_CHECK(fullKvShape.GetDimNum() != DIM_NUM_FOUR || fullKvShape.GetDim(1) <= 0 ||
                    fullKvShape.GetDim(1) > std::numeric_limits<uint32_t>::max() ||
                    fullKvShape.GetDim(2) != 1 || fullKvShape.GetDim(3) != dSizeKV_,
                OPS_LOG_E(opName_, "full_kv_cache must be [physical_blocks, positive_block_size, 1, packed_D]"),
                return ge::GRAPH_FAILED);
    const int64_t selectionPhysicalBlockCount = opParamInfo_.key.shape->GetStorageShape().GetDim(0);
    const int64_t fullPhysicalBlockCount = fullKvShape.GetDim(0);
    OP_CHECK(selectionPhysicalBlockCount <= 0 || fullPhysicalBlockCount <= 0 ||
                    selectionPhysicalBlockCount > std::numeric_limits<uint32_t>::max() ||
                    fullPhysicalBlockCount > std::numeric_limits<uint32_t>::max(),
                OPS_LOG_E(opName_, "selection/full KV physical block counts must fit in uint32 and be positive"),
                return ge::GRAPH_FAILED);
    OP_CHECK(fullBlockTableShape.GetDimNum() != DIM_NUM_TWO ||
                    fullBlockTableShape.GetDim(0) != static_cast<int64_t>(bSize_) ||
                    fullBlockTableShape.GetDim(1) <= 0 ||
                    fullBlockTableShape.GetDim(1) > std::numeric_limits<uint32_t>::max(),
                OPS_LOG_E(opName_, "full_kv_block_table must be [T, positive_max_blocks]"),
                return ge::GRAPH_FAILED);

    if (ge::GRAPH_SUCCESS != GetActualseqInfo()) {
        return ge::GRAPH_FAILED;
    }

    if (ge::GRAPH_SUCCESS != CheckContiguous()) {
        return ge::GRAPH_FAILED;
    }

    GenerateInfo(qsfaInfo);
    return ge::GRAPH_SUCCESS;
}

IMPL_OP_OPTILING(GatherSelectionSparseFlashAttention)
    .Tiling(TilingGatherSelectionSparseFlashAttention)
    .TilingParse<GatherSelectionSparseFlashAttentionCompileInfo>(TilingPrepareForGatherSelectionSparseFlashAttention);
} // namespace optiling
