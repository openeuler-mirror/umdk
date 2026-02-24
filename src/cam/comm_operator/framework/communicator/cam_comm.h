/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: CAM communicator header file
 * Author: LI Yuxing
 * Create: 2025-05-28
 * Note:
 * History: 2025-05-28 create cam_comm header file
 */
#ifndef CAM_COMM_H
#define CAM_COMM_H

#include <vector>
#include <string>
#include <unordered_map>

#include <hccl/hccl.h>
#include "cam_types.h"
#include "cam_api.h"
#include "comm_args_host.h"

namespace Cam {
constexpr int IPC_NAME_SIZE = 65;
constexpr int MAGIC_MAX = (1 << 30) - 1;

enum class ChipName {
    CHIP_310P3 = 0,
    CHIP_910B1,
    CHIP_910B2,
    CHIP_910B3,
    CHIP_910B4,
    CHIP_910B41,
    CHIP_910B2C,
    CHIP_910_9391,
    CHIP_910_9381,
    CHIP_910_9392,
    CHIP_910_9382,
    CHIP_910_9372,
    CHIP_910_9361,
    CHIP_910A5,
    RESERVED,
};

enum class PhysicalLink {
    HCCS = 0,
    PCIE = 1,
    RESERVED,
};

// 包含 物理链路、芯片名称 信息。
struct PhysicalInfo {
    ChipName chipName = ChipName::RESERVED;
    PhysicalLink physicalLink = PhysicalLink::RESERVED;
    uint32_t coreNum = 0;
};

struct CommExchangeIds {
    int devId;
    uint32_t pid;
    int64_t sdid;
};

class CamSocketExchange;
class CamComm {
public:
    CamComm(int rank, int rankSize, int devId = -1, const std::vector<int> &devList = {}, 
        std::string serverIpPort = "");
    ~CamComm();
    CamComm(const CamComm &) = delete;
    CamComm &operator=(const CamComm &) = delete;
    int Init();
    int GetRankSize() const;
    int64_t GetMagic() const { return this->magic_; };
    int64_t GetAndIncreaseMagic();
    GM_ADDR GetCommArgsPtr();

private:
    int SetIpcPidSdid(CommExchangeIds *exchangeIds, std::string name) const;
    int OpenIpcMem(const std::vector<char> &names);    
    int GetMyExchangeIds(CommExchangeIds &ids, std::string &name);
    int IdsExchangeAndProcess(CommExchangeIds *ids);
    int EnablePeerAccess();
    int InitCommMem(CommExchangeIds *exchangeIds, std::string &name);
    int InitCommon();
    void CloseIpcMem();
    void FreePeerMem(GM_ADDR &mem) const;
    int InitMem();
    int GetName(std::string &name, std::vector<char> &names) const;
    int SyncCommArgs();

private:
    int rank_ = 0;  // global rank id
    int rankSize_ = 0;  // global rank size
    int commSize_ = 0;  // local CamComm size
    int localRank_ = -1;
    int localRankSize_ = -1;
    int devId_ = 0;
    std::string serverIpPort_ = "";
    int64_t magic_ = 1;
    bool inited_ = false;
    bool ipcMemInited_ = false;
    int64_t batchSize_ = 0;
    int64_t hiddenSize_ = 0;
    int64_t topk_ = 0;
    int64_t sharedExpertRankNum_ = 0;
    int64_t memLen_ = 0;
    std::string uid_ = {};
    std::vector<int> devList_ = {};
    std::vector<int> rankList_ = {};
    
    // shared ping pong buff, 这个地址就是一开始申请在HBM上的，所以host上可以取到，但不能直接修改。
    GM_ADDR peerMem_[CAM_MAX_RANK_SIZE] = {};
    PhysicalInfo physicalInfo_ = {};
    CommArgs commArgs_ = {};    // host侧
    GM_ADDR commArgsPtr_ = nullptr; // device侧
    CamSocketExchange *socketExchange_ = nullptr;
    uint32_t pids[CAM_MAX_RANK_SIZE] = {0};
};
}   // Cam

#endif
