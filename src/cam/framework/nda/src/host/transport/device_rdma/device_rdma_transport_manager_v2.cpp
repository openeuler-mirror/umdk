/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include <cstdlib>

#include "mem_entity_def.h"
#include "shmemi_logger.h"
#include "dl_acl_api.h"
#include "device_rdma_common.h"
#include "device_rdma_helper.h"
#include "transport/topo/topo_reader.h"
#include "device_rdma_transport_manager_v2.h"

namespace shm {
namespace transport {
namespace device {

constexpr uint32_t RDMA_PORT_PREFIX = 60032;
constexpr uint32_t MAX_RANKS_PER_NIC = 16;
constexpr uint32_t ATOMIC_MAX_NUM = 128;
constexpr uint32_t RDMA_NOTIFY_NUM = 3;
constexpr uint32_t RDMA_QUEUE_NUM = 1;
constexpr uint32_t ENDPOINT_DESC_COUNT = 1;
constexpr uint32_t QP_COUNT = 1;
constexpr uint32_t MEMORY_ALIGNMENT = 512;
constexpr uint8_t RDMA_TC_MIN = 0;
constexpr uint8_t RDMA_TC_MAX = 255;
constexpr uint8_t RDMA_SL_MIN = 0;
constexpr uint8_t RDMA_SL_MAX = 7;

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
    ret = DlAclApi::AclrtGetPhyDevIdByLogicDevId(static_cast<int32_t>(logicId), &phyId);
    SHM_ASSERT_LOG_AND_RETURN(
        ret == 0 && phyId >= 0,
        "AclrtGetPhyDevIdByLogicDevId() return=" << ret << ", input logicId=" << logicId << ", output phyId=" << phyId,
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
    EndpointDescInit(&desc, 1);

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
    HcommResult hret = HcommEndpointCreate(&endpointDesc, &endpointHandle_);
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
        HcommResult hret = HcommMemUnreg(endpointHandle_, atomicMemHandle_);
        if (hret != 0) {
            SHM_LOG_WARN("rank[" << rankId_ << "] HcommMemUnreg for atomic memory failed: " << hret);
        }
        atomicMemHandle_ = nullptr;
        atomicLkey_ = 0;
    }

    if (endpointHandle_ != nullptr) {
        HcommResult hret = HcommEndpointDestroy(endpointHandle_);
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
    HcommChannelDestroy(reinterpret_cast<const ChannelHandle*>(channelPtrs_.data()), channelPtrs_.size());
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
        commMem.type = COMM_MEM_TYPE_DEVICE;
    } else {
        commMem.type = COMM_MEM_TYPE_HOST;
    }
    commMem.addr = reinterpret_cast<void*>(static_cast<ptrdiff_t>(mr.addr));
    commMem.size = mr.size;

    HcommMemHandle memHandle = nullptr;
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] HcommMemReg, addr=" << mr.addr << ", size=" << mr.size << ", type=" << commMem.type);
    HcommResult hret = HcommMemReg(endpointHandle_, "HcclBuffer", &commMem, &memHandle);
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

    HcommResult hret = HcommMemUnreg(endpointHandle_, pos->second.memHandle);
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
        HcommResult hret = HcommMemUnreg(endpointHandle_, it->second.memHandle);
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
    HcommChannelDescInit(channelDescs.data(), channelNum);

    uint8_t roceTc = GetEnvUint8("HCCL_RDMA_TC", DEFAULT_RDMA_TC, 0, 255, true);
    uint8_t roceSl = GetEnvUint8("HCCL_RDMA_SL", DEFAULT_RDMA_SL, 0, 7);

    auto prepareRet = PrepareChannelDescs(channelDescs, roceTc, roceSl);
    if (prepareRet != ACLSHMEM_SUCCESS) {
        return prepareRet;
    }

    return CreateChannelsAndFillInfo(channelDescs, channelNum);
}

Result RdmaTransportManagerV2::PrepareChannelDescs(std::vector<HcommChannelDesc> &channelDescs, uint8_t roceTc,
                                                   uint8_t roceSl)
{
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
        channelDescs[chIdx].notifyNum = RDMA_NOTIFY_NUM;
        channelDescs[chIdx].exchangeAllMems = true;
        channelDescs[chIdx].roceAttr.queueNum = RDMA_QUEUE_NUM;
        channelDescs[chIdx].roceAttr.tc = roceTc;
        channelDescs[chIdx].roceAttr.sl = roceSl;
        channelDescs[chIdx].socket = nullptr;

        bool isServer = (rankId_ < remoteRank);
        channelDescs[chIdx].role = isServer ? HCOMM_SOCKET_ROLE_SERVER : HCOMM_SOCKET_ROLE_CLIENT;
        uint32_t serverRank = isServer ? rankId_ : remoteRank;
        uint32_t clientRank = isServer ? remoteRank : rankId_;
        channelDescs[chIdx].port = static_cast<uint16_t>(
            RDMA_PORT_PREFIX + (serverRank % MAX_RANKS_PER_NIC) * MAX_RANKS_PER_NIC + (clientRank % MAX_RANKS_PER_NIC));
        ++chIdx;
    }
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::CreateChannelsAndFillInfo(std::vector<HcommChannelDesc> &channelDescs,
                                                         uint32_t channelNum)
{
    channelPtrs_.resize(channelNum);

    if (!RegisterAtomicMemory()) {
        return ACLSHMEM_INNER_ERROR;
    }

    auto hcommRet = HcommChannelCreate(
        endpointHandle_, COMM_ENGINE_AIV, channelDescs.data(), channelNum,
        reinterpret_cast<ChannelHandle*>(channelPtrs_.data()));
    if (hcommRet != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] HcommChannelCreate failed: " << hcommRet);
        return ACLSHMEM_INNER_ERROR;
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] HcommChannelCreate success, channelNum=" << channelNum);

    auto fillRet = FillRdmaInfo();
    if (fillRet != ACLSHMEM_SUCCESS) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] FillRdmaInfo failed: " << fillRet);
        return fillRet;
    }

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
            sameIp = (memcmp(&network.ip.ipv6.sin6_addr, &deviceIp_.ip.ipv6,
                             sizeof(deviceIp_.ip.ipv6)) == 0);
        }
        if (sameIp) {
            sameIpCount++;
            if (sameIpCount > MAX_RANKS_PER_NIC) {
                SHM_LOG_ERROR("rank[" << rankId_ << "] ranks per NIC/IP exceeded: " << sameIpCount
                                       << " > " << MAX_RANKS_PER_NIC << ", conflict rank: " << entry.first);
                return ACLSHMEM_INVALID_PARAM;
            }
        }
    }
    SHM_LOG_DEBUG("rank[" << rankId_ << "] ranks on same NIC/IP: " << sameIpCount
                          << ", max allowed: " << MAX_RANKS_PER_NIC);
    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::CopyAiWQInfo(struct AiQpRMAWQ& dest, const SqContext& src) noexcept
{
    const auto& roceSq = src.contextInfo.roceSq;
    dest.wqn = roceSq.qpn;
    dest.bufAddr = roceSq.sqVa;
    dest.wqeSize = roceSq.wqeSize;
    dest.depth = roceSq.depth;
    dest.headAddr = roceSq.headAddr;
    dest.tailAddr = roceSq.tailAddr;
    dest.sl = roceSq.sl;
    dest.dbAddr = roceSq.dbVa;
    dest.dbMode = static_cast<shm::DBMode>(roceSq.dbMode);
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] CopyAiWQInfo, wqn=" << dest.wqn << ", bufAddr=0x" << std::hex << dest.bufAddr
                << std::dec << ", wqeSize=" << dest.wqeSize << ", depth=" << dest.depth << ", headAddr=0x" << std::hex
                << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex << dest.tailAddr << std::dec << ", sl="
                << dest.sl << ", dbAddr=0x" << std::hex << dest.dbAddr << std::dec << ", dbMode=" << int(dest.dbMode));
}

void RdmaTransportManagerV2::CopyAiCQInfo(struct AiQpRMACQ& dest, const CqContext& src) noexcept
{
    const auto& roceCq = src.contextInfo.roceCq;
    dest.cqn = roceCq.cqn;
    dest.bufAddr = roceCq.cqVa;
    dest.cqeSize = roceCq.cqeSize;
    dest.depth = roceCq.cqDepth;
    dest.headAddr = roceCq.headAddr;
    dest.tailAddr = roceCq.tailAddr;
    dest.dbAddr = roceCq.dbVa;
    dest.dbMode = static_cast<shm::DBMode>(roceCq.dbMode);
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] CopyAiCQInfo, cqn=" << dest.cqn << ", bufAddr=0x" << std::hex << dest.bufAddr
                << std::dec << ", cqeSize=" << dest.cqeSize << ", depth=" << dest.depth << ", headAddr=0x" << std::hex
                << dest.headAddr << std::dec << ", tailAddr=0x" << std::hex << dest.tailAddr << std::dec
                << ", dbAddr=0x" << std::hex << dest.dbAddr << std::dec << ", dbMode=" << int(dest.dbMode));
}

void RdmaTransportManagerV2::FillQpPreSettingCopyInfo(AiQpRMAQueueInfo*& copyInfo)
{
    copyInfo->count = 1;
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
    auto ret = ReadLocalBufferInfo(copyInfo, channelPtrs);
    if (ret != ACLSHMEM_SUCCESS) {
        return ret;
    }
    return ReadRemoteBufferInfo(copyInfo, channelPtrs);
}

Result RdmaTransportManagerV2::ReadLocalBufferInfo(AiQpRMAQueueInfo *copyInfo,
                                                   const std::vector<ChannelHandle> &channelPtrs)
{
    ChannelEntity hostEntity{};
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
                continue;
            }
            copyInfo->mr[rankId_].lkey = localBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
            copyInfo->mr[rankId_].rkey = localBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.rkey;
        }
        if (hostEntity.localBufferNum > 1) {
            RegedBufferEntity atomicLocalBuffer{};
            auto ret = DlAclApi::AclrtMemcpy(&atomicLocalBuffer, sizeof(RegedBufferEntity),
                                             reinterpret_cast<RegedBufferEntity *>(hostEntity.localBufferAddr) + 1,
                                             sizeof(RegedBufferEntity), ACL_MEMCPY_DEVICE_TO_HOST);
            if (ret == 0) {
                atomicLkey_ = atomicLocalBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
                SHM_LOG_DEBUG("rank[" << rankId_ << "] atomicLkey=" << atomicLkey_);
            } else {
                SHM_LOG_ERROR("rank[" << rankId_ << "] pre-read atomic local buffer failed: " << ret);
            }
        }
        if (hostEntity.localBufferNum > 0 && hostEntity.localBufferAddr != nullptr) {
            return ACLSHMEM_SUCCESS;
        }
    }
    SHM_LOG_ERROR("rank[" << rankId_ << "] failed to read local buffer info from any channel entity");
    return ACLSHMEM_INNER_ERROR;
}

Result RdmaTransportManagerV2::ReadRemoteBufferInfo(AiQpRMAQueueInfo *copyInfo,
                                                    const std::vector<ChannelHandle> &channelPtrs)
{
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
        if (ReadSingleRemoteRank(copyInfo, channelPtrs, it->first) == ACLSHMEM_SUCCESS) {
            remoteInfoRead = true;
        }
    }
    if (!remoteInfoRead && rankCount_ > 1) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] failed to read remote buffer info from any channel entity");
        return ACLSHMEM_INNER_ERROR;
    }
    return ACLSHMEM_SUCCESS;
}

Result RdmaTransportManagerV2::ReadSingleRemoteRank(AiQpRMAQueueInfo *copyInfo,
                                                    const std::vector<ChannelHandle> &channelPtrs, uint32_t rankId)
{
    uint32_t channelIdx = rankId;
    if (channelIdx > rankId_) {
        channelIdx--;
    }
    if (channelIdx >= channelPtrs.size()) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] channel index " << channelIdx << " out of range");
        return ACLSHMEM_INNER_ERROR;
    }
    ChannelHandle channelPtr = channelPtrs[channelIdx];
    if (channelPtr == 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] channel ptr is null for channel " << channelIdx);
        return ACLSHMEM_INNER_ERROR;
    }
    ChannelEntity hostEntity{};
    auto aclRet = DlAclApi::AclrtMemcpy(&hostEntity, sizeof(ChannelEntity), reinterpret_cast<void *>(channelPtr),
                                        sizeof(ChannelEntity), ACL_MEMCPY_DEVICE_TO_HOST);
    if (aclRet != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] copy channel entity from device failed: " << aclRet);
        return ACLSHMEM_INNER_ERROR;
    }
    if (hostEntity.remoteBufferNum == 0 || hostEntity.remoteBufferAddr == nullptr) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] remoteBufferNum = 0 || remoteBufferAddr is null");
        return ACLSHMEM_INNER_ERROR;
    }
    RegedBufferEntity remoteBuffer{};
    aclRet = DlAclApi::AclrtMemcpy(&remoteBuffer, sizeof(RegedBufferEntity), hostEntity.remoteBufferAddr,
                                   sizeof(RegedBufferEntity), ACL_MEMCPY_DEVICE_TO_HOST);
    if (aclRet != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] copy remote buffer from device failed: " << aclRet);
        return ACLSHMEM_INNER_ERROR;
    }
    copyInfo->mr[rankId].lkey = remoteBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.lkey;
    copyInfo->mr[rankId].rkey = remoteBuffer.bufferInfo.rma.protectionInfo.memInfo.roce.rkey;
    FillSqCqAtomicInfo(copyInfo, hostEntity, rankId);
    return ACLSHMEM_SUCCESS;
}

void RdmaTransportManagerV2::FillSqCqAtomicInfo(AiQpRMAQueueInfo *copyInfo, const ChannelEntity &hostEntity,
                                                uint32_t rankId)
{
    if (hostEntity.sqNum > 0 && hostEntity.sqContextAddr != nullptr) {
        std::vector<SqContext> sqContexts(hostEntity.sqNum);
        auto aclRet =
            DlAclApi::AclrtMemcpy(sqContexts.data(), sizeof(SqContext) * hostEntity.sqNum, hostEntity.sqContextAddr,
                                  sizeof(SqContext) * hostEntity.sqNum, ACL_MEMCPY_DEVICE_TO_HOST);
        if (aclRet == 0) {
            CopyAiWQInfo(copyInfo->sq[rankId], sqContexts[0]);
        } else {
            SHM_LOG_ERROR("rank[" << rankId_ << "] copy sq context from device failed: " << aclRet);
        }
    } else {
        SHM_LOG_ERROR("rank[" << rankId_ << "] sqNum = 0 || sqContextAddr is null");
    }
    if (hostEntity.cqNum > 0 && hostEntity.cqContextAddr != nullptr) {
        std::vector<CqContext> cqContexts(hostEntity.cqNum);
        auto aclRet =
            DlAclApi::AclrtMemcpy(cqContexts.data(), sizeof(CqContext) * hostEntity.cqNum, hostEntity.cqContextAddr,
                                  sizeof(CqContext) * hostEntity.cqNum, ACL_MEMCPY_DEVICE_TO_HOST);
        if (aclRet == 0) {
            CopyAiCQInfo(copyInfo->scq[rankId], cqContexts[0]);
        } else {
            SHM_LOG_ERROR("rank[" << rankId_ << "] copy cq context from device failed: " << aclRet);
        }
    } else {
        SHM_LOG_ERROR("rank[" << rankId_ << "] cqNum = 0 || cqContextAddr is null");
    }
    size_t atomicSizePerRank = ATOMIC_MAX_NUM * sizeof(uint64_t);
    copyInfo->sq[rankId].atomicAddr =
        reinterpret_cast<uint64_t>(static_cast<char *>(atomicSharedMemory_) + rankId * atomicSizePerRank);
    copyInfo->sq[rankId].atomicLkey = atomicLkey_;
    copyInfo->rq[rankId].atomicAddr =
        reinterpret_cast<uint64_t>(static_cast<char *>(atomicSharedMemory_) + rankId * atomicSizePerRank);
    copyInfo->rq[rankId].atomicLkey = atomicLkey_;
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
    if (qpInfo_ != nullptr) {
        return true;
    }

    void* ptr = nullptr;
    auto oneQpSize = 2U * (sizeof(AiQpRMAWQ) + sizeof(AiQpRMACQ)) + sizeof(RdmaMemRegionInfo);
    qpInfoSize_ = sizeof(AiQpRMAQueueInfo) + oneQpSize * rankCount_;
    auto ret = DlAclApi::AclrtMalloc(&ptr, qpInfoSize_, 0);
    if (ret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] allocate device size: " << qpInfoSize_ << ", failed: " << ret);
        return false;
    }

    qpInfo_ = (AiQpRMAQueueInfo*)ptr;

    // reserve atomic info space
    if (atomicSharedMemory_ != nullptr) {
        return true;
    }

    uint32_t atomicSize = ATOMIC_MAX_NUM * sizeof(uint64_t) * rankCount_; // 128 是最大的 atomic 并发数
    atomicSize = ALIGN_UP(atomicSize, MEMORY_ALIGNMENT);
    ret = DlAclApi::AclrtMalloc(&atomicSharedMemory_, atomicSize, 0);
    if (ret != 0) {
        SHM_LOG_ERROR("rank[" << rankId_ << "] allocate device atomic size: " << atomicSize << ", failed: " << ret);
        return false;
    }
    atomicLkey_ = 0;
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
    atomicSize = ALIGN_UP(atomicSize, MEMORY_ALIGNMENT);

    CommMem commMem{};
    commMem.type = COMM_MEM_TYPE_DEVICE;
    commMem.addr = atomicSharedMemory_;
    commMem.size = atomicSize;

    HcommMemHandle memHandle = nullptr;
    SHM_LOG_DEBUG(
        "rank[" << rankId_ << "] HcommMemReg for atomic memory, addr=" << atomicSharedMemory_
                << ", size=" << atomicSize);
    HcommResult hret = HcommMemReg(endpointHandle_, "AtomicBuffer", &commMem, &memHandle);
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
