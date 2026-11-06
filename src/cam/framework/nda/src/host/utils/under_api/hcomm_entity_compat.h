/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software; you can redistribute it and/or modify it under the terms of conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

/*
 * Override of the pinned shmem commit's src/host/utils/under_api/hcomm_entity_compat.h.
 * The nda build copies this tree over the pinned shmem sources, so this patched
 * copy takes effect. Drop this override once the shmem pin moves to a commit
 * that handles the CANN 9.2.x hcomm header layout itself.
 *
 * Patch vs. the pinned version: CANN 9.2.x ships the experimental
 * hcomm_res_entity_defs.h under aarch64-linux/pkg_inc, which is also on the
 * compile include path, so the original "entity first" probe wrongly selected
 * the entity layout even though that header does not provide the
 * channel-desc API (HcommChannelDesc / HcommChannelDescInit) this code uses.
 * Prefer the stable hcomm_res.h layout whenever it is visible (res.h pulls in
 * hcomm_channel.h on CANN 9.2.x, and defines the channel API directly on
 * CANN 9.1.x), and keep the entity layout only as a fallback for a future
 * CANN that drops the stable headers.
 */

#ifndef SHMEM_HCOMM_ENTITY_COMPAT_H
#define SHMEM_HCOMM_ENTITY_COMPAT_H

#include <cstring>
#include <netinet/in.h>

#include <cstdint>

#if defined(__has_include)
#if __has_include(<hcomm/hcomm_primitives.h>) && __has_include(<hcomm/hcomm_res.h>)
#include <hcomm/hcomm_res.h>
#define SHMEM_HCOMM_RES_FROM_CANN 1
#elif __has_include(<hcomm/hcomm_res_entity_defs.h>)
#include <hcomm/hcomm_res_entity_defs.h>
#define SHMEM_HCOMM_ENTITY_FROM_CANN 1
#endif
#endif

/*
 * Older CANN packages, for example 8.5.1, do not ship the HCOM resource
 * headers.  HCOM is loaded with dlopen/dlsym, so the host compilation only
 * needs ABI-shaped declarations.  Keep this fallback deliberately local to
 * this compatibility header; it does not provide or emulate any runtime API.
 */
#if !defined(SHMEM_HCOMM_ENTITY_FROM_CANN) && !defined(SHMEM_HCOMM_RES_FROM_CANN)

enum class CommEngine : int32_t {
    RESERVED = -1,
    CPU = 0,
    CPU_TS = 1,
    AICPU = 2,
    AICPU_TS = 3,
    AIV = 4,
    CCU = 5,
};
inline constexpr CommEngine COMM_ENGINE_RESERVED = CommEngine::RESERVED;
inline constexpr CommEngine COMM_ENGINE_CPU = CommEngine::CPU;
inline constexpr CommEngine COMM_ENGINE_CPU_TS = CommEngine::CPU_TS;
inline constexpr CommEngine COMM_ENGINE_AICPU = CommEngine::AICPU;
inline constexpr CommEngine COMM_ENGINE_AICPU_TS = CommEngine::AICPU_TS;
inline constexpr CommEngine COMM_ENGINE_AIV = CommEngine::AIV;
inline constexpr CommEngine COMM_ENGINE_CCU = CommEngine::CCU;

enum class CommProtocol : int32_t {
    RESERVED = -1,
    HCCS = 0,
    ROCE = 1,
    PCIE = 2,
    SIO = 3,
    UBC_CTP = 4,
    UBC_TP = 5,
    UB_MEM = 6,
    UBOE = 7,
    HCCS_ONLY = 8,
};
inline constexpr CommProtocol COMM_PROTOCOL_RESERVED = CommProtocol::RESERVED;
inline constexpr CommProtocol COMM_PROTOCOL_HCCS = CommProtocol::HCCS;
inline constexpr CommProtocol COMM_PROTOCOL_ROCE = CommProtocol::ROCE;
inline constexpr CommProtocol COMM_PROTOCOL_PCIE = CommProtocol::PCIE;
inline constexpr CommProtocol COMM_PROTOCOL_SIO = CommProtocol::SIO;
inline constexpr CommProtocol COMM_PROTOCOL_UBC_CTP = CommProtocol::UBC_CTP;
inline constexpr CommProtocol COMM_PROTOCOL_UB_TP = CommProtocol::UB_TP;
inline constexpr CommProtocol COMM_PROTOCOL_UB_MEM = CommProtocol::UB_MEM;
inline constexpr CommProtocol COMM_PROTOCOL_UBOE = CommProtocol::UBOE;
inline constexpr CommProtocol COMM_PROTOCOL_HCCS_ONLY = CommProtocol::HCCS_ONLY;

enum class CommAddrType : int32_t {
    RESERVED = -1,
    IP_V4 = 0,
    IP_V6 = 1,
    ID = 2,
    EID = 3,
};
inline constexpr CommAddrType COMM_ADDR_TYPE_RESERVED = CommAddrType::RESERVED;
inline constexpr CommAddrType COMM_ADDR_TYPE_IP_V4 = CommAddrType::IP_V4;
inline constexpr CommAddrType COMM_ADDR_TYPE_IP_V6 = CommAddrType::IP_V6;
inline constexpr CommAddrType COMM_ADDR_TYPE_ID = CommAddrType::ID;
inline constexpr CommAddrType COMM_ADDR_TYPE_EID = CommAddrType::EID;

struct CommAddr {
    CommAddrType type;
    union {
        uint8_t raws[36];
        struct in_addr addr;
        struct in6_addr addr6;
        uint32_t id;
        uint8_t eid[16];
    };
};

enum class EndpointLocType : int32_t {
    RESERVED = -1,
    DEVICE = 0,
    HOST = 1,
};
inline constexpr EndpointLocType ENDPOINT_LOC_TYPE_RESERVED = EndpointLocType::RESERVED;
inline constexpr EndpointLocType ENDPOINT_LOC_TYPE_DEVICE = EndpointLocType::DEVICE;
inline constexpr EndpointLocType ENDPOINT_LOC_TYPE_HOST = EndpointLocType::HOST;

struct EndpointLoc {
    EndpointLocType locType;
    union {
        uint8_t raws[60];
        struct {
            uint32_t devPhyId;
            uint32_t superDevId;
            uint32_t serverIdx;
            uint32_t superPodIdx;
        } device;
        struct {
            uint32_t id;
        } host;
    };
};
struct EndpointDesc {
    CommProtocol protocol;
    CommAddr commAddr;
    EndpointLoc loc;
};
using ChannelHandle = uint64_t;
using HcclResult = int32_t;
constexpr HcclResult HCCL_SUCCESS = 0;
constexpr HcclResult HCCL_E_PTR = 2;

inline HcclResult EndpointDescInit(EndpointDesc* endpoint, uint32_t num)
{
    if (endpoint == nullptr) {
        return HCCL_E_PTR;
    }
    for (uint32_t idx = 0; idx < num; ++idx) {
        std::memset(endpoint, 0, sizeof(EndpointDesc));
        endpoint->protocol = COMM_PROTOCOL_RESERVED;
        endpoint->commAddr.type = COMM_ADDR_TYPE_RESERVED;
        endpoint->loc.locType = ENDPOINT_LOC_TYPE_RESERVED;
        ++endpoint;
    }
    return HCCL_SUCCESS;
}

using EndpointHandle = void*;
using HcommMemHandle = void*;
using HcommResult = int32_t;
using HcommSocket = void*;

enum class CommMemType : int32_t {
    INVALID = -1,
    DEVICE = 0,
    HOST = 1,
};
struct CommMem {
    CommMemType type;
    void* addr;
    uint64_t size;
};

struct CommAbiHeader {
    uint32_t version;
    uint32_t magicWord;
    uint32_t size;
    uint32_t reserved;
};

enum class HcommSocketRole : int32_t {
    CLIENT = 0,
    SERVER = 1,
};
inline constexpr HcommSocketRole HCOMM_SOCKET_ROLE_CLIENT = HcommSocketRole::CLIENT;
inline constexpr HcommSocketRole HCOMM_SOCKET_ROLE_SERVER = HcommSocketRole::SERVER;

struct HcommChannelDesc {
    EndpointDesc remoteEndpoint{};
    uint32_t notifyNum{0};
    bool exchangeAllMems{false};
    void** memHandles{nullptr};
    uint32_t memHandleNum{0};
    struct {
        uint32_t qos{0};
    } hccsAttr;
    struct {
        uint32_t queueNum{0};
        uint32_t retryCnt{0};
        uint32_t retryInterval{0};
        uint8_t tc{0};
        uint8_t sl{0};
    } roceAttr;
    HcommSocketRole role{HcommSocketRole::CLIENT};
    HcommSocket socket{nullptr};
    uint16_t port{0};
    uint32_t qos{0};
};

#endif // no CANN HCOM resource headers

#if !defined(SHMEM_HCOMM_ENTITY_FROM_CANN) && !defined(SHMEM_HCOMM_RES_FROM_CANN)

using HcommMem = CommMem;

#endif // fallback HCOM declarations

// Keep the HCOM memory-registration ABI used by SHMEM independent from the
// CANN header spelling. The runtime implementation is loaded by dlsym and
// follows the pointer-form ABI used by CANN 9.0.0 and later.
namespace shm {
using HcommResult = int32_t;
using HcommMemHandle = void*;
enum class CommMemType : int32_t {
    INVALID = -1,
    DEVICE = 0,
    HOST = 1,
};
struct CommMem {
    CommMemType type;
    void* addr;
    uint64_t size;
};

namespace detail {

template <typename Desc>
auto InitializeHcommChannelDesc(Desc* channelDesc, uint32_t num, int)
    -> decltype(HcommChannelDescInit(channelDesc, num))
{
    return HcommChannelDescInit(channelDesc, num);
}

template <typename Desc>
HcommResult InitializeHcommChannelDesc(Desc* channelDesc, uint32_t num, long)
{
    if (channelDesc == nullptr) {
        return 2;
    }
    for (uint32_t i = 0; i < num; ++i) {
        std::memset(channelDesc, 0, sizeof(HcommChannelDesc));
        channelDesc->remoteEndpoint.protocol = COMM_PROTOCOL_RESERVED;
        channelDesc->remoteEndpoint.commAddr.type = COMM_ADDR_TYPE_RESERVED;
        channelDesc->remoteEndpoint.loc.locType = ENDPOINT_LOC_TYPE_RESERVED;
        ++channelDesc;
    }
    return 0;
}

} // namespace detail

// Keep a project-scoped initializer available without colliding with CANN's
// global declaration. Use CANN's initializer whenever the visible headers
// declare it; otherwise use the ABI-shaped fallback implementation.
inline HcommResult ShmemHcommChannelDescInit(HcommChannelDesc* channelDesc, uint32_t num)
{
    return detail::InitializeHcommChannelDesc(channelDesc, num, 0);
}
} // namespace shm

#endif // SHMEM_HCOMM_ENTITY_COMPAT_H
