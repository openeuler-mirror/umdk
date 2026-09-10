/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#ifndef RDMA_DL_HCOMM_DEF_H
#define RDMA_DL_HCOMM_DEF_H

#include <cstdint>
#include <cstring>

#include "securec.h"

#include "hcomm_entity_compat.h"
#include "dl_comm_def.h"

namespace shm {

typedef void* ChannelEntityHandle;

enum ProtectionType {
    PROTECTION_TYPE_RESERVED = -1,
    PROTECTION_TYPE_ROCE = 0,
    PROTECTION_TYPE_UB = 1,
};

enum RegedBufferType {
    REGED_BUFFER_TYPE_RESERVED = -1,
    REGED_BUFFER_TYPE_IPC = 0,
    REGED_BUFFER_TYPE_RMA = 1,
};

enum RegedNotifyType {
    REGED_NOTIFY_TYPE_RESERVED = -1,
    REGED_NOTIFY_TYPE_IPC_RT = 0,
    REGED_NOTIFY_TYPE_IPC_MEM = 1,
    REGED_NOTIFY_TYPE_RMA_RT = 2,
    REGED_NOTIFY_TYPE_RMA_MEM = 3,
};

enum SqContextType {
    SQ_CONTEXT_TYPE_RESERVED = -1,
    SQ_CONTEXT_TYPE_UB_JFS = 0,
    SQ_CONTEXT_TYPE_ROCE = 1,
};

enum CqContextType {
    CQ_CONTEXT_TYPE_RESERVED = -1,
    CQ_CONTEXT_TYPE_UB_JFC = 0,
    CQ_CONTEXT_TYPE_ROCE = 1,
};

struct ProtectionInfo {
    ProtectionType type;
    union {
        struct {
            uint32_t lkey;
            uint32_t rkey;
        } roce;
        struct {
            uint32_t tokenId;
            uint32_t tokenValue;
        } ub;
        uint8_t raws[24];
    } memInfo;
};

struct RegedBufferEntity {
    RegedBufferType type;
    union {
        struct {
            uint64_t addr;
            uint64_t size;
        } ipc;
        struct {
            uint64_t addr;
            uint64_t size;
            ProtectionInfo protectionInfo;
        } rma;
        uint8_t raws[56];
    } bufferInfo;
};

struct RegedNotifyEntity {
    RegedNotifyType type;
    union {
        struct {
            uint64_t addr;
            uint32_t size;
            int32_t notifyId;
        } ipcRt;
        struct {
            uint64_t addr;
            uint32_t size;
        } ipcMem;
        struct {
            uint64_t addr;
            uint32_t size;
            int32_t notifyId;
            ProtectionInfo protectionInfo;
        } rmaRt;
        struct {
            uint64_t addr;
            uint32_t size;
            ProtectionInfo protectionInfo;
        } rmaMem;
        uint8_t raws[56];
    } notifyInfo;
};

struct SqContext {
    SqContextType type;
    union {
        struct {
            uint64_t sqVa;
            uint64_t headAddr;
            uint64_t tailAddr;
            uint64_t dbVa;
            uint32_t jfsID;
            uint32_t wqeSize;
            uint32_t sqDepth;
            uint32_t tpID;
            uint8_t remoteEID[16];
        } ubJfs;
        struct {
            uint64_t sqVa;
            uint64_t headAddr;
            uint64_t tailAddr;
            uint64_t dbHwVa;
            uint64_t dbSwVa;
            uint32_t qpn;
            uint32_t wqeSize;
            uint32_t depth;
            uint8_t sl;
            uint8_t mtuShift;
        } roceSq;
        uint8_t raws[120];
    } contextInfo;
};

struct CqContext {
    CqContextType type;
    union {
        struct {
            uint64_t scqVa;
            uint64_t headAddr;
            uint64_t tailAddr;
            uint64_t dbVa;
            uint32_t jfcID;
            uint32_t cqeSize;
            uint32_t cqDepth;
        } ubJfc;
        struct {
            uint64_t cqVa;
            uint64_t headAddr;
            uint64_t tailAddr;
            uint64_t dbHwVa;
            uint64_t dbSwVa;
            uint32_t cqn;
            uint32_t cqeSize;
            uint32_t cqDepth;
        } roceCq;
        uint8_t raws[120];
    } contextInfo;
};

struct ChannelEntity {
    CommAbiHeader abiHeader;
    CommEngine engine;
    CommProtocol protocol;
    uint32_t localNotifyNum;
    uint32_t remoteNotifyNum;
    uint32_t localBufferNum;
    uint32_t remoteBufferNum;
    uint32_t sqNum;
    uint32_t cqNum;
    RegedNotifyEntity* localNotifyAddr;
    RegedNotifyEntity* remoteNotifyAddr;
    RegedBufferEntity* localBufferAddr;
    RegedBufferEntity* remoteBufferAddr;
    SqContext* sqContextAddr;
    CqContext* cqContextAddr;
    uint8_t reserve[160];
};

// ============================================================
// 旧版 CANN (2026-07-07 之前) ROCE 上下文结构体，用于向后兼容
// ============================================================
struct SqContextRoceV1 {
    uint64_t sqVa;
    uint64_t headAddr;
    uint64_t tailAddr;
    uint64_t dbVa;
    uint32_t qpn;
    uint32_t wqeSize;
    uint32_t depth;
    int8_t dbMode;
    uint8_t sl;
};

struct CqContextRoceV1 {
    uint64_t cqVa;
    uint64_t headAddr;
    uint64_t tailAddr;
    uint64_t dbVa;
    uint32_t cqn;
    uint32_t cqeSize;
    uint32_t cqDepth;
    int8_t dbMode;
};

// 检测 SqContext 是否为新版 V2 格式 (2026-07-07 及之后)
// 通过 $ASCEND_HOME_PATH/share/info/hcomm/version.info 中的 timestamp 字段判断
inline bool IsRoceSqV2Format(const SqContext& ctx)
{
    if (ctx.type != SQ_CONTEXT_TYPE_ROCE) {
        return true; // 非 ROCE 类型无需区分
    }
    return IsHcommV2();
}

// 检测 CqContext 是否为新版 V2 格式
inline bool IsRoceCqV2Format(const CqContext& ctx)
{
    if (ctx.type != CQ_CONTEXT_TYPE_ROCE) {
        return true;
    }
    return IsHcommV2();
}

// 从 SqContext 的原始字节中提取旧版 V1 字段 (SqContext::raws 覆盖整个 union)
inline SqContextRoceV1 ExtractSqContextRoceV1(const SqContext& ctx)
{
    SqContextRoceV1 v1{};
    static_assert(sizeof(v1) <= sizeof(ctx.contextInfo.raws), "SqContextRoceV1 too large");
    (void)memcpy_s(&v1, sizeof(v1), ctx.contextInfo.raws, sizeof(v1));
    return v1;
}

// 从 CqContext 的原始字节中提取旧版 V1 字段
inline CqContextRoceV1 ExtractCqContextRoceV1(const CqContext& ctx)
{
    CqContextRoceV1 v1{};
    static_assert(sizeof(v1) <= sizeof(ctx.contextInfo.raws), "CqContextRoceV1 too large");
    (void)memcpy_s(&v1, sizeof(v1), ctx.contextInfo.raws, sizeof(v1));
    return v1;
}
// 用于判断 HcommChannelDesc 是否存在 roceAttr.cqAttrFlags 字段
template <typename T, typename = void>
struct HasCqAttrFlagsField : std::false_type {};

template <typename T>
struct HasCqAttrFlagsField<T, std::void_t<decltype(T::roceAttr.cqAttrFlags)>> : std::true_type {};

constexpr static bool IsHcommSupportCqOverrun() { return HasCqAttrFlagsField<HcommChannelDesc>::value; }

// 辅助函数：设置 HcommChannelDesc 的 cqAttrFlags 的值
// 通过函数模板特化的时机来使得编译时期可以根据 HasCqOverrunField 是否特定字段来设置 cqAttrFlags
template <typename DescT>
inline void SetChannelDescCqAttrFlags(DescT& desc, uint32_t cqAttrFlags)
{
    if constexpr (IsHcommSupportCqOverrun()) {
        desc.roceAttr.cqAttrFlags = cqAttrFlags;
    }
    // 字段不存在时，什么都不做
}

} // namespace shm

#endif // RDMA_DL_HCOMM_DEF_H
