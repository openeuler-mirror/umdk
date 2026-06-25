/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#ifndef MF_HYBRID_DEVICE_RDMA_TRANSPORT_MANAGER_V2_H
#define MF_HYBRID_DEVICE_RDMA_TRANSPORT_MANAGER_V2_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <map>
#include <memory>

#include "mem_entity_def.h"
#include "transport_manager.h"
#include "device_rdma_common.h"
#include "dl_hcomm_def.h"

namespace shm {
namespace transport {
namespace device {

struct HcommMemRegEntry {
    HcommMemHandle memHandle{nullptr};
    uint64_t addr{0};
    uint64_t size{0};
};

class RdmaTransportManagerV2 : public TransportManager {
public:
    ~RdmaTransportManagerV2() override;
    Result OpenDevice(const TransportOptions& options) override;
    Result CloseDevice() override;
    Result RegisterMemoryRegion(const TransportMemoryRegion& mr) override;
    Result UnregisterMemoryRegion(uint64_t addr) override;
    Result QueryMemoryKey(uint64_t /*addr*/, TransportMemoryKey& /*key*/) override { return ACLSHMEM_SUCCESS; }
    Result ParseMemoryKey(const TransportMemoryKey& /*key*/, uint64_t& /*addr*/, uint64_t& /*size*/) override
    {
        return ACLSHMEM_SUCCESS;
    }
    Result Prepare(const HybmTransPrepareOptions& options) override;
    Result Connect() override;
    Result AsyncConnect() override { return ACLSHMEM_SUCCESS; }
    Result WaitForConnected(int64_t /*timeoutNs*/) override { return ACLSHMEM_SUCCESS; }
    Result UpdateRankOptions(const HybmTransPrepareOptions& options) override;
    const std::string& GetNic() const override;
    const void* GetQpInfo() const override;

private:
    Result CreateEndpoint();
    void DestroyEndpoint();
    Result BuildEndpointDesc(EndpointDesc& desc);
    void ClearAllRegisterMRs();
    int CheckPrepareOptions(const HybmTransPrepareOptions& options);
    int ValidateRanksPerNic() const;
    void PrintHostInfo(AiQpRMAQueueInfo& copyInfo);
    Result FillRdmaInfo();
    void CopyAiWQInfo(struct AiQpRMAWQ& dest, const SqContext& src) noexcept;
    void CopyAiCQInfo(struct AiQpRMACQ& dest, const CqContext& src) noexcept;
    bool ReserveRdmaInfoSpace() noexcept;
    bool RegisterAtomicMemory() noexcept;
    void FillQpPreSettingCopyInfo(AiQpRMAQueueInfo*& copyInfo);
    void FillQpPostSettingCopyInfo(AiQpRMAQueueInfo*& copyInfo);
    Result GetRdmaInfoFromChannelEntity(AiQpRMAQueueInfo* copyInfo, const std::vector<ChannelHandle>& channelPtrs);
    Result ReadLocalBufferInfo(AiQpRMAQueueInfo *copyInfo, const std::vector<ChannelHandle> &channelPtrs);
    Result ReadRemoteBufferInfo(AiQpRMAQueueInfo *copyInfo, const std::vector<ChannelHandle> &channelPtrs);
    Result ReadSingleRemoteRank(AiQpRMAQueueInfo *copyInfo, const std::vector<ChannelHandle> &channelPtrs,
                                uint32_t rankId);
    void FillSqCqAtomicInfo(AiQpRMAQueueInfo *copyInfo, const ChannelEntity &hostEntity, uint32_t rankId);
    Result PrepareChannelDescs(std::vector<HcommChannelDesc> &channelDescs, uint8_t roceTc, uint8_t roceSl);
    Result CreateChannelsAndFillInfo(std::vector<HcommChannelDesc> &channelDescs, uint32_t channelNum);

private:
    uint32_t rankId_{0};
    uint32_t rankCount_{1};
    uint32_t phyId_{0};
    hybm_role_type role_{HYBM_ROLE_PEER};
    net_addr_t deviceIp_{};
    uint16_t devicePort_{0};
    std::string nicInfo_;
    AiQpRMAQueueInfo* qpInfo_{nullptr};
    uint64_t qpInfoSize_{0};
    EndpointHandle endpointHandle_{nullptr};
    std::map<uint64_t, HcommMemRegEntry, std::greater<uint64_t>> registeredMRs_;
    std::vector<ChannelHandle> channelPtrs_;
    std::unordered_map<uint32_t, ConnectRankInfo> rankInfo_;
    void* atomicSharedMemory_{nullptr};
    HcommMemHandle atomicMemHandle_{nullptr};
    uint32_t atomicLkey_{0};
};
} // namespace device
} // namespace transport
} // namespace shm

#endif // MF_HYBRID_DEVICE_RDMA_TRANSPORT_MANAGER_V2_H
