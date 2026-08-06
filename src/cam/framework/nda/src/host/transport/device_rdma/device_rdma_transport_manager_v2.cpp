/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include "mem_entity_def.h"
#include "shmemi_logger.h"
#include "shmemi_scope_guard.h"
#include "dl_acl_api.h"
#include "dl_hcomm_api.h"
#include "dl_hcomm_def.h"
#include "device_rdma_common.h"
#include "device_rdma_helper.h"
#include "transport/topo/topo_reader.h"
#include "device_rdma_transport_manager_v2.h"

#include <chrono>
#include <cstdlib>
#include <thread>

namespace shm {
namespace transport {
namespace device {

constexpr uint32_t RDMA_PORT_PREFIX = 60032;
constexpr uint32_t MAX_RANKS_PER_NIC = 16;
constexpr uint32_t ATOMIC_MAX_NUM = 128;            // 最大的 atomic 并发数
constexpr uint32_t RDMA_NOTIFY_NUM = 3;             // 通道通知数量
constexpr uint32_t RDMA_QUEUE_NUM = 1;              // 每个通道的 RoCE 队列数
constexpr uint32_t ENDPOINT_DESC_COUNT = 1;         // 端点描述符数量
constexpr uint32_t QP_COUNT = 1;                    // QP 数量
constexpr uint32_t SEND_RECV_QUEUE_COUNT = 2;       // 每个 rank 的 WQ(sq+rq)与 CQ(scq+rcq)数量
constexpr uint32_t ATOMIC_LOCAL_BUFFER_INDEX = 1;   // atomic 内存位于 localBufferAddr 数组的第 2 个槽位
constexpr int32_t ROCE_V1_DB_MODE_HW = 0;          // 旧版格式 dbMode=0 表示硬件 doorbell (HW_DB)
constexpr uint32_t MEMORY_ALIGNMENT = 4096;         // HNS 1825 atomic MR 注册需要 4K 对齐
constexpr uint8_t RDMA_TC_MIN = 0;                  // RoCE TC 最小值
constexpr uint8_t RDMA_TC_MAX = 255;                // RoCE TC 最大值
constexpr uint8_t RDMA_SL_MIN = 0;                  // RoCE SL 最小值
constexpr uint8_t RDMA_SL_MAX = 7;                  // RoCE SL 最大值
// 非阻塞建链状态轮询参数(按通道个数缩放)
constexpr uint32_t CHANNEL_STATUS_POLL_INTERVAL_PER_CH_MS = 10;   // 单通道单次轮询间隔(ms)
constexpr uint32_t CHANNEL_STATUS_POLL_TIMEOUT_PER_CH_MS = 60000; // 单通道建链就绪等待超时(ms) = 1min

RdmaTransportManagerV2::~RdmaTransportManagerV2()
{
    ClearAllRegisterMRs();
    DestroyEndpoint();
}

Result RdmaTransportManagerV2::OpenDevice(const TransportOptions& options)
{
    int32_t userId = -1;
    int32_t logicId = -1;

    SHM_LOG_DEBUG("rank[" << rankId_ << "] begin to open device with " << options);
    auto ret = DlAclApi::AclrtGetDevice(&userId);
    SHM_ASSERT_LOG_AND_RETURN(
        ret == 0 && userId >= 0, "AclrtGetDevice() return=" << ret << ", output deviceId=" << userId,
        ACLSHMEM_INNER_ERROR);

    ret = DlAclApi::RtGetLogicDevIdByUserDevId(userId, &logicId);
    SHM_ASSERT_LOG_AND_RETURN(
        ret == 0 && logicId >= 0, "RtGetLogicDevIdByUserDevId() return=" << ret << ", output deviceId=" << logicId,
        ACLSHMEM_INNER_ERROR);

    int32_t phyId = -1;
    // HCCP/topo use global phyId; pass userId to deprecated API (MR !407), not logicId.
    ret = DlAclApi::AclrtGetPhyDevIdByLogicDevId(userId, &phyId);
    SHM_ASSERT_LOG_AND_RETURN(
        ret == 0 && phyId >= 0,
        "AclrtGetPhyDevIdByLogicDevId() return=" << ret << ", userId=" << userId << ", logicDeviceId=" << logicId
                                                 << ", output phyId=" << phyId,
        ACLSHMEM_INNER_ERROR);
    phyId_ = static_cast<uint32_t>(phyId);

    rankId_ = options.rankId;
    rankCount_ = options.rankCount;
    role_ = options.role;

    if (options.type == IpV4) {
        deviceIp_.type = IpV4;
    } else if (options.type == IpV6) {
        deviceIp_.type = IpV6;
    }

    devicePort_ = RDMA_PORT_PREFIX + (rankId_ % MAX_RANKS_PER_NIC);
    if (!TopoReader::ParseRdmaNetAddr(phyId_, deviceIp_)) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] ParseRdmaNetAddr failed for phyId " << phyId_);
        return ACLSHMEM_INNER_ERROR;
    }
    nicInfo_ = GenerateDeviceNic(deviceIp_, devicePort_);
    SHM_LOG_DEBUG("rank[" << rankId_ << "] nicInfo_=" << nicInfo_);

    ret = CreateEndpoint();
    if (ret != ACLSHMEM_SUCCESS) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] CreateEndpoint failed: " << ret);
        return ret;
    }

    if (!ReserveRdmaInfoSpace()) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] reserve rdma info space failed.");
        return ACLSHMEM_INNER_ERROR;
    }

    SHM_LOG_INFO("rank[" << rankId_ << "] open device with " << options << " success.");
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::BuildEndpointDesc(EndpointDesc& desc)
{
    EndpointDescInit(&desc, ENDPOINT_DESC_COUNT);

    desc.protocol = COMM_PROTOCOL_ROCE;
    if (deviceIp_.type == IpV4) {
        desc.commAddr.type = COMM_ADDR_TYPE_IP_V4;
        desc.commAddr.addr = deviceIp_.ip.ipv4;
    } else if (deviceIp_.type == IpV6) {
        desc.commAddr.type = COMM_ADDR_TYPE_IP_V6;
        desc.commAddr.addr6 = deviceIp_.ip.ipv6;
    } else {
        SHM_LOG_ERROR("rank[" << rankId_ << "] unsupported ip type: " << deviceIp_.type);
        return ACLSHMEM_INVALID_PARAM;
    }

    desc.loc.locType = ENDPOINT_LOC_TYPE_HOST;
    desc.loc.device.devPhyId = phyId_;
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::CreateEndpoint()
{
    if (endpointHandle_ != nullptr) {
        SHM_LOG_INFO("rank[" << rankId_ << "] endpoint already created.");
        return ACLSHMEM_SUCCESS;
    }

    EndpointDesc endpointDesc{};
    auto ret = BuildEndpointDesc(endpointDesc);
    if (ret != ACLSHMEM_SUCCESS) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] build endpoint desc failed: " << ret);
        return ret;
    }

    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] HcommEndpointCreate, protocol=COMM_PROTOCOL_ROCE, locType=ENDPOINT_LOC_TYPE_HOST"
                << ", devPhyId=" << phyId_);
    HcommResult hret = DlHcommApi::HcommEndpointCreate(&endpointDesc, &endpointHandle_);
    if (hret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommEndpointCreate failed: " << hret);
        return ACLSHMEM_INNER_ERROR;
    }

    SHM_LOG_INFO("rank[" << rankId_ << "] HcommEndpointCreate success, endpointHandle=" << endpointHandle_);
    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::DestroyEndpoint()
{
    if (atomicMemHandle_ != nullptr && endpointHandle_ != nullptr) {
        HcommResult hret = DlHcommApi::HcommMemUnreg(endpointHandle_, atomicMemHandle_);
        if (hret != 0) {
            SHM_LOG_WARN("rank[" << rankId_ << "] HcommMemUnreg for atomic memory failed: " << hret);
        }
        atomicMemHandle_ = nullptr;
        atomicLkey_ = 0;
    }

    if (endpointHandle_ != nullptr) {
        HcommResult hret = DlHcommApi::HcommEndpointDestroy(endpointHandle_);
        if (hret != 0) {
            SHM_LOG_WARN("rank[" << rankId_ << "] HcommEndpointDestroy failed: " << hret);
        }
        endpointHandle_ = nullptr;
    }

    if (atomicSharedMemory_ != nullptr) {
        DlAclApi::AclrtFree(atomicSharedMemory_);
        atomicSharedMemory_ = nullptr;
    }

    if (qpInfo_ != nullptr) {
        DlAclApi::AclrtFree(reinterpret_cast<void*>(qpInfo_));
        qpInfo_ = nullptr;
    }
}

Result RdmaTransportManagerV2::CloseDevice()
{
    DlHcommApi::HcommChannelDestroy(reinterpret_cast<const ChannelHandle*>(channelPtrs_.data()), channelPtrs_.size());
    channelPtrs_.clear();

    ClearAllRegisterMRs();
    DestroyEndpoint();
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::RegisterMemoryRegion(const TransportMemoryRegion& mr)
{
    if (endpointHandle_ == nullptr) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] endpoint not created, cannot register MR.");
        return ACLSHMEM_INNER_ERROR;
    }

    CommMem commMem{};
    if ((mr.flags & REG_MR_FLAG_HBM) || IsVirtualAddressNpu(mr.addr)) {
        commMem.type = CommMemType::DEVICE;
    } else {
        commMem.type = CommMemType::HOST;
    }
    commMem.addr = reinterpret_cast<void*>(static_cast<ptrdiff_t>(mr.addr));
    commMem.size = mr.size;

    HcommMemHandle memHandle = nullptr;
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] HcommMemReg, addr=" << mr.addr << ", size=" << mr.size
                << ", type=" << static_cast<int32_t>(commMem.type));
    HcommResult hret = DlHcommApi::HcommMemReg(endpointHandle_, "HcclBuffer", &commMem, &memHandle);
    if (hret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommMemReg failed: " << hret);
        return ACLSHMEM_INNER_ERROR;
    }

    HcommMemRegEntry entry{};
    entry.memHandle = memHandle;
    entry.addr = mr.addr;
    entry.size = mr.size;

    registeredMRs_.emplace(mr.addr, entry);
    SHM_LOG_DEBUG("rank[" << rankId_ << "] HcommMemReg success, addr=" << mr.addr << ", memHandle=" << memHandle);
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::UnregisterMemoryRegion(uint64_t addr)
{
    auto pos = registeredMRs_.find(addr);
    if (pos == registeredMRs_.end()) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] input address not registered!");
        return ACLSHMEM_INVALID_PARAM;
    }

    HcommResult hret = DlHcommApi::HcommMemUnreg(endpointHandle_, pos->second.memHandle);
    if (hret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommMemUnreg failed: " << hret);
        return ACLSHMEM_INNER_ERROR;
    }

    registeredMRs_.erase(pos);
    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::ClearAllRegisterMRs()
{
    for (auto it = registeredMRs_.begin(); it != registeredMRs_.end(); ++it) {
        HcommResult hret = DlHcommApi::HcommMemUnreg(endpointHandle_, it->second.memHandle);
        if (hret != 0) {
            SHM_LOG_WARN("rank[" << rankId_ << "] HcommMemUnreg addr=" << it->first << " failed: " << hret);
        }
    }
    registeredMRs_.clear();
}

Result RdmaTransportManagerV2::Prepare(const HybmTransPrepareOptions& options)
{
    SHM_LOG_DEBUG("rank[" << rankId_ << "] RdmaTransportManagerV2 Prepare with : " << options);

    int ret;
    if ((ret = CheckPrepareOptions(options)) != 0) {
        return ret;
    }

    mf_sockaddr deviceNetwork;
    for (auto it = options.options.begin(); it != options.options.end(); ++it) {
        ret = ParseDeviceNic(it->second.nic, deviceNetwork);
        if (ret != ACLSHMEM_SUCCESS) {
            SHM_LOG_ERROR(
                "rank[" << rankId_ << "] parse networks[" << it->first << "]=" << it->second.nic << " failed: " << ret);
            return ACLSHMEM_INVALID_PARAM;
        }

        rankInfo_.emplace(it->first, ConnectRankInfo{it->second.role, deviceNetwork, it->second.memKeys});
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] rankInfo_.size=" << rankInfo_.size());

    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::Connect()
{
    SHM_LOG_DEBUG("rank[" << rankId_ << "] RdmaTransportManagerV2 Connect");

    if (endpointHandle_ == nullptr) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] endpoint not created, please call Prepare first");
        return ACLSHMEM_INNER_ERROR;
    }

    auto validateRet = ValidateRanksPerNic();
    if (validateRet != ACLSHMEM_SUCCESS) {
        return static_cast<Result>(validateRet);
    }

    uint32_t channelNum = rankCount_ - 1;

    std::vector<HcommChannelDesc> channelDescs(channelNum);
    auto desc_init_ret = ShmemHcommChannelDescInit(channelDescs.data(), channelNum);
    if (desc_init_ret != 0) {
        SHM_LOG_ERROR("HcommChannelDescInit failed, ret = " << desc_init_ret);
        return ACLSHMEM_INNER_ERROR;
    }

    uint8_t roceTc = GetEnvUint8("HCCL_RDMA_TC", DEFAULT_RDMA_TC, RDMA_TC_MIN, RDMA_TC_MAX, true);
    uint8_t roceSl = GetEnvUint8("HCCL_RDMA_SL", DEFAULT_RDMA_SL, RDMA_SL_MIN, RDMA_SL_MAX);

    uint32_t chIdx = 0;
    for (uint32_t remoteRank = 0; remoteRank < rankCount_; ++remoteRank) {
        if (remoteRank == rankId_) {
            continue;
        }

        auto rankIt = rankInfo_.find(remoteRank);
        if (rankIt == rankInfo_.end()) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] rank " << remoteRank << " not found in rankInfo_");
            return ACLSHMEM_INVALID_PARAM;
        }

        channelDescs[chIdx].remoteEndpoint.protocol = COMM_PROTOCOL_ROCE;

        if (rankIt->second.network.type == IpV4) {
            channelDescs[chIdx].remoteEndpoint.commAddr.type = COMM_ADDR_TYPE_IP_V4;
            channelDescs[chIdx].remoteEndpoint.commAddr.addr = rankIt->second.network.ip.ipv4.sin_addr;
        } else {
            channelDescs[chIdx].remoteEndpoint.commAddr.type = COMM_ADDR_TYPE_IP_V6;
            channelDescs[chIdx].remoteEndpoint.commAddr.addr6 = rankIt->second.network.ip.ipv6.sin6_addr;
        }
        channelDescs[chIdx].notifyNum = 3;
        channelDescs[chIdx].exchangeAllMems = true;
        channelDescs[chIdx].roceAttr.queueNum = 1;
        channelDescs[chIdx].roceAttr.tc = roceTc;
        channelDescs[chIdx].roceAttr.sl = roceSl;
        channelDescs[chIdx].roceAttr.retryCnt = DEFAULT_ROCE_RETRY_CNT;
        channelDescs[chIdx].roceAttr.retryInterval = DEFAULT_ROCE_RETRY_INTERVAL;
        channelDescs[chIdx].socket = nullptr;
        bool isServer = (rankId_ < remoteRank);
        channelDescs[chIdx].role = isServer ? HCOMM_SOCKET_ROLE_SERVER : HCOMM_SOCKET_ROLE_CLIENT;
        uint32_t serverRank = isServer ? rankId_ : remoteRank;
        uint32_t clientRank = isServer ? remoteRank : rankId_;
        channelDescs[chIdx].port = static_cast<uint16_t>(
            RDMA_PORT_PREFIX + (serverRank % MAX_RANKS_PER_NIC) * MAX_RANKS_PER_NIC + (clientRank % MAX_RANKS_PER_NIC));
        ++chIdx;
    }

    channelPtrs_.resize(channelNum);

    if (!RegisterAtomicMemory()) {
        return ACLSHMEM_INNER_ERROR;
    }

    auto hcommRet = DlHcommApi::HcommChannelCreate(
        endpointHandle_, COMM_ENGINE_AIV, channelDescs.data(), channelNum,
        reinterpret_cast<ChannelHandle*>(channelPtrs_.data()));
    if (hcommRet != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommChannelCreate failed: " << hcommRet);
        return ACLSHMEM_INNER_ERROR;
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] HcommChannelCreate success, channelNum=" << channelNum);

    auto channelGuard = shm::utils::make_scope_guard(channelPtrs_.data(), [this, channelNum](ChannelHandle*) {
        DlHcommApi::HcommChannelDestroy(reinterpret_cast<const ChannelHandle*>(channelPtrs_.data()), channelNum);
        channelPtrs_.clear();
    });

    const uint32_t pollIntervalMs = channelNum * CHANNEL_STATUS_POLL_INTERVAL_PER_CH_MS;
    const uint32_t pollTimeoutMs = channelNum * CHANNEL_STATUS_POLL_TIMEOUT_PER_CH_MS;
    std::vector<int32_t> statusList(channelNum, HCOMM_CHANNEL_STATUS_CONNECTING);
    bool allReady = false;
    bool connectFailed = false;
    uint32_t elapsedMs = 0;
    while (elapsedMs <= pollTimeoutMs) {
        auto statusRet = DlHcommApi::HcommChannelGetStatus(channelPtrs_.data(), channelNum, statusList.data());
        if (statusRet != 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] HcommChannelGetStatus failed: " << statusRet);
            return ACLSHMEM_INNER_ERROR;
        }

        allReady = true;
        connectFailed = false;
        for (uint32_t i = 0; i < channelNum; ++i) {
            const int32_t status = statusList[i];
            if (status == HCOMM_CHANNEL_STATUS_READY) {
                continue;
            }
            allReady = false;
            if (status == HCOMM_CHANNEL_STATUS_CONNECTING) {
                continue; // 建链中，继续等待
            }
            if (status == HCOMM_CHANNEL_STATUS_FAILED) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] channel[" << i << "] connect failed, status=" << status);
                connectFailed = true;
            } else if (status == HCOMM_CHANNEL_STATUS_TIMEOUT) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] channel[" << i << "] connect timeout, status=" << status);
                connectFailed = true;
            } else {
                SHM_LOG_ERROR("rank[" << rankId_ << "] channel[" << i << "] unknown status=" << status);
                connectFailed = true;
            }
        }
        if (allReady) {
            break;
        }
        if (connectFailed) {
            SHM_LOG_ERROR(
                "rank[" << rankId_ << "] channel connect failed, stop polling, channelNum=" << channelNum
                        << ", elapsedMs=" << elapsedMs);
            return ACLSHMEM_INNER_ERROR;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
        elapsedMs += pollIntervalMs;
    }

    if (!allReady) {
        SHM_LOG_ERROR(
            "rank[" << rankId_ << "] wait channel connect timeout, channelNum=" << channelNum << ", pollIntervalMs="
                    << pollIntervalMs << ", pollTimeoutMs=" << pollTimeoutMs << ", elapsedMs=" << elapsedMs);
        return ACLSHMEM_INNER_ERROR;
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] all channels connected, elapsedMs=" << elapsedMs);

    auto fillRet = FillRdmaInfo();
    if (fillRet != ACLSHMEM_SUCCESS) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] FillRdmaInfo failed: " << fillRet);
        return fillRet;
    }

    channelGuard.release();
    SHM_LOG_INFO("rank[" << rankId_ << "] Connect success, created " << channelNum << " channels");
    return ACLSHMEM_SUCCESS;
}

int RdmaTransportManagerV2::CheckPrepareOptions(const shm::transport::HybmTransPrepareOptions& options)
{
    if (role_ != HYBM_ROLE_PEER) {
        SHM_LOG_INFO("rank[" << rankId_ << "] transport role: " << role_ << " check options passed.");
        return ACLSHMEM_SUCCESS;
    }

    if (options.options.size() > rankCount_) {
        SHM_LOG_ERROR(
            "rank[" << rankId_ << "] options size():" << options.options.size()
                    << " larger than rank count: " << rankCount_);
        return ACLSHMEM_INVALID_PARAM;
    }

    if (options.options.find(rankId_) == options.options.end()) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] options not contains self rankId: " << rankId_);
        return ACLSHMEM_INVALID_PARAM;
    }

    for (auto it = options.options.begin(); it != options.options.end(); ++it) {
        if (it->first >= rankCount_) {
            SHM_LOG_ERROR(
                "rank[" << rankId_ << "] input options of nics contains rankId:" << it->first
                        << ", rank count: " << rankCount_);
            return ACLSHMEM_INVALID_PARAM;
        }
    }

    return ACLSHMEM_SUCCESS;
}

int RdmaTransportManagerV2::ValidateRanksPerNic() const
{
    uint32_t sameIpCount = 1;
    for (const auto& entry : rankInfo_) {
        if (entry.first == rankId_) {
            continue;
        }
        const auto& network = entry.second.network;
        if (network.type != deviceIp_.type) {
            continue;
        }
        bool sameIp = false;
        if (network.type == IpV4) {
            sameIp = (network.ip.ipv4.sin_addr.s_addr == deviceIp_.ip.ipv4.s_addr);
        } else {
            sameIp = (memcmp(&network.ip.ipv6.sin6_addr, &deviceIp_.ip.ipv6, sizeof(deviceIp_.ip.ipv6)) == 0);
        }
        if (sameIp) {
            sameIpCount++;
            if (sameIpCount > MAX_RANKS_PER_NIC) {
                SHM_LOG_ERROR(
                    "rank[" << rankId_ << "] ranks per NIC/IP exceeded: " << sameIpCount << " > " << MAX_RANKS_PER_NIC
                            << ", conflict rank: " << entry.first);
                return ACLSHMEM_INVALID_PARAM;
            }
        }
    }
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] ranks on same NIC/IP: " << sameIpCount << ", max allowed: " << MAX_RANKS_PER_NIC);
    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::CopyAiWQInfo(struct AiQpRMAWQ& dest, const SqContext& src) noexcept
{
    if (IsRoceSqV2Format(src)) {
        // 新版格式 (2026-07-07 及之后 CANN)
        const auto& roceSq = src.contextInfo.roceSq;
        dest.wqn = roceSq.qpn;
        dest.bufAddr = roceSq.sqVa;
        dest.wqeSize = roceSq.wqeSize;
        dest.depth = roceSq.depth;
        dest.headAddr = roceSq.headAddr;
        dest.tailAddr = roceSq.tailAddr;
        dest.sl = roceSq.sl;
        dest.dbAddr = roceSq.dbHwVa;
        dest.dbSwVa = roceSq.dbSwVa;
        dest.mtuShift = roceSq.mtuShift;
        dest.dbMode = DBMode::SW_DB; // 新版默认软件doorbell
        SHM_LOG_DEBUG(
            "rank[" << rankId_ << "] CopyAiWQInfo(V2), wqn=" << dest.wqn << ", bufAddr=0x" << std::hex << dest.bufAddr
                    << std::dec << ", wqeSize=" << dest.wqeSize << ", depth=" << dest.depth << ", headAddr=0x"
                    << std::hex << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex << dest.tailAddr << std::dec
                    << ", sl=" << dest.sl << ", dbAddr=0x" << std::hex << dest.dbAddr << ", dbSwVa=0x" << std::hex
                    << dest.dbSwVa << std::dec << ", mtuShift=" << static_cast<int>(dest.mtuShift));
    } else {
        // 旧版格式 (2026-07-07 之前 CANN) - 回退兼容
        auto v1 = ExtractSqContextRoceV1(src);
        dest.wqn = v1.qpn;
        dest.bufAddr = v1.sqVa;
        dest.wqeSize = v1.wqeSize;
        dest.depth = v1.depth;
        dest.headAddr = v1.headAddr;
        dest.tailAddr = v1.tailAddr;
        dest.sl = v1.sl;
        dest.dbAddr = v1.dbVa;
        dest.dbSwVa = 0;   // 旧版无软doorbell
        dest.mtuShift = 0; // 旧版无此字段，填0
        dest.dbMode = (v1.dbMode == ROCE_V1_DB_MODE_HW) ? DBMode::HW_DB : DBMode::SW_DB;
        SHM_LOG_DEBUG(
            "rank[" << rankId_ << "] CopyAiWQInfo(V1 fallback), wqn=" << dest.wqn << ", bufAddr=0x" << std::hex
                    << dest.bufAddr << std::dec << ", wqeSize=" << dest.wqeSize << ", depth=" << dest.depth
                    << ", headAddr=0x" << std::hex << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex
                    << dest.tailAddr << std::dec << ", sl=" << dest.sl << ", dbAddr=0x" << std::hex << dest.dbAddr
                    << std::dec << ", dbMode=" << static_cast<int>(v1.dbMode));
    }
}

void RdmaTransportManagerV2::CopyAiCQInfo(struct AiQpRMACQ& dest, const CqContext& src) noexcept
{
    if (IsRoceCqV2Format(src)) {
        // 新版格式 (2026-07-07 之后 CANN)
        const auto& roceCq = src.contextInfo.roceCq;
        dest.cqn = roceCq.cqn;
        dest.bufAddr = roceCq.cqVa;
        dest.cqeSize = roceCq.cqeSize;
        dest.depth = roceCq.cqDepth;
        dest.headAddr = roceCq.headAddr;
        dest.tailAddr = roceCq.tailAddr;
        dest.dbAddr = roceCq.dbHwVa;
        dest.dbSwVa = roceCq.dbSwVa;
        dest.dbMode = DBMode::SW_DB; // 新版默认软件doorbell
        SHM_LOG_DEBUG(
            "rank[" << rankId_ << "] CopyAiCQInfo(V2), cqn=" << dest.cqn << ", bufAddr=0x" << std::hex << dest.bufAddr
                    << std::dec << ", cqeSize=" << dest.cqeSize << ", depth=" << dest.depth << ", headAddr=0x"
                    << std::hex << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex << dest.tailAddr << std::dec
                    << ", dbAddr=0x" << std::hex << dest.dbAddr << ", dbSwVa=0x" << std::hex << dest.dbSwVa
                    << std::dec);
    } else {
        // 旧版格式 (2026-07-07 之前 CANN) - 回退兼容
        auto v1 = ExtractCqContextRoceV1(src);
        dest.cqn = v1.cqn;
        dest.bufAddr = v1.cqVa;
        dest.cqeSize = v1.cqeSize;
        dest.depth = v1.cqDepth;
        dest.headAddr = v1.headAddr;
        dest.tailAddr = v1.tailAddr;
        dest.dbAddr = v1.dbVa;
        dest.dbSwVa = 0; // 旧版无软doorbell
        dest.dbMode = (v1.dbMode == ROCE_V1_DB_MODE_HW) ? DBMode::HW_DB : DBMode::SW_DB;
        SHM_LOG_DEBUG(
            "rank[" << rankId_ << "] CopyAiCQInfo(V1 fallback), cqn=" << dest.cqn << ", bufAddr=0x" << std::hex
                    << dest.bufAddr << std::dec << ", cqeSize=" << dest.cqeSize << ", depth=" << dest.depth
                    << ", headAddr=0x" << std::hex << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex
                    << dest.tailAddr << std::dec << ", dbAddr=0x" << std::hex << dest.dbAddr << std::dec
                    << ", dbMode=" << static_cast<int>(v1.dbMode));
    }
}

void RdmaTransportManagerV2::FillQpPreSettingCopyInfo(AiQpRMAQueueInfo*& copyInfo)
{
    copyInfo->count = QP_COUNT;
    copyInfo->sq = (AiQpRMAWQ*)(void*)(copyInfo + 1);
    copyInfo->rq = (AiQpRMAWQ*)(void*)(copyInfo->sq + rankCount_);
    copyInfo->scq = (AiQpRMACQ*)(void*)(copyInfo->rq + rankCount_);
    copyInfo->rcq = (AiQpRMACQ*)(void*)(copyInfo->scq + rankCount_);
    copyInfo->mr = (RdmaMemRegionInfo*)(void*)(copyInfo->rcq + rankCount_);
}

void RdmaTransportManagerV2::FillQpPostSettingCopyInfo(AiQpRMAQueueInfo*& copyInfo)
{
    auto pointer = (ptrdiff_t)(void*)(qpInfo_);
    pointer += sizeof(AiQpRMAQueueInfo);
    copyInfo->sq = (AiQpRMAWQ*)(void*)(pointer);

    pointer += static_cast<ptrdiff_t>(sizeof(AiQpRMAWQ) * rankCount_);
    copyInfo->rq = (AiQpRMAWQ*)(void*)(pointer);

    pointer += static_cast<ptrdiff_t>(sizeof(AiQpRMAWQ) * rankCount_);
    copyInfo->scq = (AiQpRMACQ*)(void*)(pointer);

    pointer += static_cast<ptrdiff_t>(sizeof(AiQpRMACQ) * rankCount_);
    copyInfo->rcq = (AiQpRMACQ*)(void*)(pointer);

    pointer += static_cast<ptrdiff_t>(sizeof(AiQpRMACQ) * rankCount_);
    copyInfo->mr = (RdmaMemRegionInfo*)(void*)pointer;
}

Result RdmaTransportManagerV2::FillRdmaInfo()
{
    std::vector<uint8_t> qpInfoBuffer(qpInfoSize_);
    auto copyInfo = (AiQpRMAQueueInfo*)(void*)qpInfoBuffer.data();

    FillQpPreSettingCopyInfo(copyInfo);

    auto ret = GetRdmaInfoFromChannelEntity(copyInfo, channelPtrs_);
    if (ret != ACLSHMEM_SUCCESS) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] GetRdmaInfoFromChannelEntity failed: " << ret);
        return ret;
    }

    PrintHostInfo(*copyInfo);

    FillQpPostSettingCopyInfo(copyInfo);

    auto aclRet = DlAclApi::AclrtMemcpy(qpInfo_, qpInfoSize_, copyInfo, qpInfoSize_, ACL_MEMCPY_HOST_TO_DEVICE);
    if (aclRet != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] copy qp info to device failed: " << aclRet);
        return ACLSHMEM_INNER_ERROR;
    }
    SHM_LOG_INFO("rank[" << rankId_ << "] copy qp info success");
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::GetRdmaInfoFromChannelEntity(
    AiQpRMAQueueInfo* copyInfo, const std::vector<ChannelHandle>& channelPtrs)
{
    ChannelEntity hostEntity{};
    bool localInfoRead = false;

    for (const auto& channelPtr : channelPtrs) {
        if (channelPtr == 0) {
            continue;
        }
        auto aclRet = DlAclApi::AclrtMemcpy(
            &hostEntity, sizeof(ChannelEntity), reinterpret_cast<void*>(channelPtr), sizeof(ChannelEntity),
            ACL_MEMCPY_DEVICE_TO_HOST);
        if (aclRet != 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] pre-read channel entity failed: " << aclRet);
            continue;
        }
        if (hostEntity.localBufferNum > 0 && hostEntity.localBufferAddr != nullptr) {
            RegedBufferEntity localBuffer{};
            aclRet = DlAclApi::AclrtMemcpy(
                &localBuffer, sizeof(RegedBufferEntity), hostEntity.localBufferAddr, sizeof(RegedBufferEntity),
                ACL_MEMCPY_DEVICE_TO_HOST);
            if (aclRet != 0) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] copy local buffer from device failed: " << aclRet);
            } else {
                copyInfo->mr[rankId_].lkey = localBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
                copyInfo->mr[rankId_].rkey = localBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.rkey;
                localInfoRead = true;
            }
        }
        if (hostEntity.localBufferNum > 1) {
            RegedBufferEntity atomicLocalBuffer{};
            aclRet = DlAclApi::AclrtMemcpy(
                &atomicLocalBuffer, sizeof(RegedBufferEntity),
                reinterpret_cast<RegedBufferEntity*>(hostEntity.localBufferAddr) + ATOMIC_LOCAL_BUFFER_INDEX,
                sizeof(RegedBufferEntity), ACL_MEMCPY_DEVICE_TO_HOST);
            if (aclRet != 0) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] pre-read atomic local buffer failed: " << aclRet);
            } else {
                atomicLkey_ = atomicLocalBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
                SHM_LOG_DEBUG("rank[" << rankId_ << "] atomicLkey=" << atomicLkey_);
            }
        }
        break;
    }

    if (!localInfoRead) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] failed to read local buffer info from any channel entity");
        return ACLSHMEM_INNER_ERROR;
    }

    bool remoteInfoRead = false;
    for (auto it = rankInfo_.begin(); it != rankInfo_.end(); ++it) {
        auto& map = it->second.memoryMap;
        if (map.empty()) {
            continue;
        }
        copyInfo->mr[it->first].size = map.begin()->second.size;
        copyInfo->mr[it->first].addr = map.begin()->second.address;
        if (it->first == rankId_) {
            continue;
        }

        uint32_t channelIdx = it->first;
        if (channelIdx > rankId_) {
            channelIdx--;
        }
        if (channelIdx >= channelPtrs.size()) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] channel index " << channelIdx << " out of range");
            continue;
        }

        ChannelHandle channelPtr = channelPtrs[channelIdx];
        if (channelPtr == 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] channel ptr is null for channel " << channelIdx);
            continue;
        }

        hostEntity = {};
        auto aclRet = DlAclApi::AclrtMemcpy(
            &hostEntity, sizeof(ChannelEntity), reinterpret_cast<void*>(channelPtr), sizeof(ChannelEntity),
            ACL_MEMCPY_DEVICE_TO_HOST);
        if (aclRet != 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] copy channel entity from device failed: " << aclRet);
            continue;
        }

        if (hostEntity.remoteBufferNum > 0 && hostEntity.remoteBufferAddr != nullptr) {
            RegedBufferEntity remoteBuffer{};
            aclRet = DlAclApi::AclrtMemcpy(
                &remoteBuffer, sizeof(RegedBufferEntity), hostEntity.remoteBufferAddr, sizeof(RegedBufferEntity),
                ACL_MEMCPY_DEVICE_TO_HOST);
            if (aclRet != 0) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] copy remote buffer from device failed: " << aclRet);
                continue;
            }
            copyInfo->mr[it->first].lkey = remoteBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
            copyInfo->mr[it->first].rkey = remoteBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.rkey;
            remoteInfoRead = true;
        } else {
            SHM_LOG_ERROR("rank[" << rankId_ << "] remoteBufferNum = 0 || remoteBufferAddr is null");
            continue;
        }

        // 填充sq信息
        if (hostEntity.sqNum > 0 && hostEntity.sqContextAddr != nullptr) {
            std::vector<SqContext> sqContexts(hostEntity.sqNum);
            aclRet = DlAclApi::AclrtMemcpy(
                sqContexts.data(), sizeof(SqContext) * hostEntity.sqNum, hostEntity.sqContextAddr,
                sizeof(SqContext) * hostEntity.sqNum, ACL_MEMCPY_DEVICE_TO_HOST);
            if (aclRet != 0) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] copy sq context from device failed: " << aclRet);
                continue;
            }

            CopyAiWQInfo(copyInfo->sq[it->first], sqContexts[0]);
        } else {
            SHM_LOG_ERROR("rank[" << rankId_ << "] sqNum = 0 || sqContextAddr is null");
        }

        // 填充cq信息
        if (hostEntity.cqNum > 0 && hostEntity.cqContextAddr != nullptr) {
            std::vector<CqContext> cqContexts(hostEntity.cqNum);
            aclRet = DlAclApi::AclrtMemcpy(
                cqContexts.data(), sizeof(CqContext) * hostEntity.cqNum, hostEntity.cqContextAddr,
                sizeof(CqContext) * hostEntity.cqNum, ACL_MEMCPY_DEVICE_TO_HOST);
            if (aclRet != 0) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] copy cq context from device failed: " << aclRet);
                continue;
            }

            CopyAiCQInfo(copyInfo->scq[it->first], cqContexts[0]);
        } else {
            SHM_LOG_ERROR("rank[" << rankId_ << "] cqNum = 0 || cqContextAddr is null");
        }

        // atomicSizePerRank 每个rank的atomic内存大小
        size_t atomicSizePerRank = ATOMIC_MAX_NUM * sizeof(uint64_t);
        copyInfo->sq[it->first].atomicAddr =
            reinterpret_cast<uint64_t>(static_cast<char*>(atomicSharedMemory_) + it->first * atomicSizePerRank);
        copyInfo->sq[it->first].atomicLkey = atomicLkey_;
        copyInfo->rq[it->first].atomicAddr =
            reinterpret_cast<uint64_t>(static_cast<char*>(atomicSharedMemory_) + it->first * atomicSizePerRank);
        copyInfo->rq[it->first].atomicLkey = atomicLkey_;
    }

    if (!remoteInfoRead && rankCount_ > 1) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] failed to read remote buffer info from any channel entity");
        return ACLSHMEM_INNER_ERROR;
    }

    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::PrintHostInfo(AiQpRMAQueueInfo& copyInfo)
{
    SHM_LOG_DEBUG("=======================rank [" << rankId_ << "] host info====================");
    auto tempMemInfo = ((RdmaMemRegionInfo*)copyInfo.mr)[rankId_];
    SHM_LOG_DEBUG("rank[" << rankId_ << "] MemInfo.size: " << tempMemInfo.size);
    SHM_LOG_DEBUG("rank[" << rankId_ << "] MemInfo.addr: " << tempMemInfo.addr);
    SHM_LOG_DEBUG("rank[" << rankId_ << "] MemInfo.lkey: " << tempMemInfo.lkey);
    SHM_LOG_DEBUG("rank[" << rankId_ << "] MemInfo.rkey: " << tempMemInfo.rkey);
}

bool RdmaTransportManagerV2::ReserveRdmaInfoSpace() noexcept
{
    // reserve qp info space
    if (qpInfo_ == nullptr) {
        void* ptr = nullptr;
        auto oneQpSize = SEND_RECV_QUEUE_COUNT * (sizeof(AiQpRMAWQ) + sizeof(AiQpRMACQ)) + sizeof(RdmaMemRegionInfo);
        qpInfoSize_ = sizeof(AiQpRMAQueueInfo) + oneQpSize * rankCount_;
        auto ret = DlAclApi::AclrtMalloc(&ptr, qpInfoSize_, 0);
        if (ret != 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] allocate device size: " << qpInfoSize_ << ", failed: " << ret);
            qpInfo_ = nullptr;
            return false;
        }

        qpInfo_ = (AiQpRMAQueueInfo*)ptr;
    }

    // reserve atomic info space
    if (atomicSharedMemory_ == nullptr) {
        void* ptr = nullptr;
        uint32_t atomicSize = ATOMIC_MAX_NUM * sizeof(uint64_t) * rankCount_;
        // HNS 1825 atomic MR 注册需要 4K 对齐。
        atomicSize = ALIGN_UP(atomicSize, MEMORY_ALIGNMENT);
        auto ret = DlAclApi::AclrtMalloc(&ptr, atomicSize, 0);
        if (ret != 0) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] allocate device atomic size: " << atomicSize << ", failed: " << ret);
            atomicSharedMemory_ = nullptr;
            return false;
        }
        atomicSharedMemory_ = ptr;
    }

    return true;
}

bool RdmaTransportManagerV2::RegisterAtomicMemory() noexcept
{
    if (atomicMemHandle_ != nullptr) {
        return true;
    }

    if (atomicSharedMemory_ == nullptr || endpointHandle_ == nullptr) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] atomic memory or endpoint not ready for registration");
        return false;
    }

    uint32_t atomicSize = ATOMIC_MAX_NUM * sizeof(uint64_t) * rankCount_;
    // HNS 1825 atomic MR 注册需要 4K 对齐。
    atomicSize = ALIGN_UP(atomicSize, MEMORY_ALIGNMENT);

    CommMem commMem{};
    commMem.type = CommMemType::DEVICE;
    commMem.addr = atomicSharedMemory_;
    commMem.size = atomicSize;

    HcommMemHandle memHandle = nullptr;
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] HcommMemReg for atomic memory, addr=" << atomicSharedMemory_
                << ", size=" << atomicSize);
    HcommResult hret = DlHcommApi::HcommMemReg(endpointHandle_, "AtomicBuffer", &commMem, &memHandle);
    if (hret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommMemReg for atomic memory failed: " << hret);
        return false;
    }

    atomicMemHandle_ = memHandle;
    SHM_LOG_DEBUG("rank[" << rankId_ << "] atomic memory registered, memHandle=" << memHandle);

    return true;
}

Result RdmaTransportManagerV2::UpdateRankOptions(const HybmTransPrepareOptions& options)
{
    SHM_LOG_DEBUG("rank[" << rankId_ << "] RdmaTransportManagerV2 Prepare with : " << options);

    mf_sockaddr deviceNetwork;
    std::unordered_map<uint32_t, ConnectRankInfo> ranksInfo;
    for (auto it = options.options.begin(); it != options.options.end(); ++it) {
        auto ret = ParseDeviceNic(it->second.nic, deviceNetwork);
        if (ret != ACLSHMEM_SUCCESS) {
            SHM_LOG_ERROR("rank[" << rankId_ << "] update rank network(" << it->second.nic << ") invalid.");
            return ACLSHMEM_INVALID_PARAM;
        }
        SHM_LOG_INFO("rank[" << rankId_ << "] UpdateRankOptions update rank: " << it->first);
        ranksInfo.emplace(it->first, ConnectRankInfo{it->second.role, deviceNetwork, it->second.memKeys});
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] UpdateRankOptions ranksInfo.size=" << ranksInfo.size());

    rankInfo_ = ranksInfo;

    return ACLSHMEM_SUCCESS;
}

const std::string& RdmaTransportManagerV2::GetNic() const { return nicInfo_; }

const void* RdmaTransportManagerV2::GetQpInfo() const
{
    if (qpInfo_ == nullptr) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] GetQpInfo():qpInfo_ is nullptr.");
        return nullptr;
    }
    return qpInfo_;
}

} // namespace device
} // namespace transport
} // namespace shm
