/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: CAM communicator implementation file
 * Author: LI Yuxing
 * Create: 2025-05-30
 * Note:
 * History: 2025-05-30 create cam_comm implemenation file
 */
#include <cam_comm.h>

#include <chrono>
#include <vector>
#include <mutex>
#include <map>
#include <set>
#include <thread>
#include <sstream>
#include <iomanip>

#include <hccl/hccl.h>
#include "cam_log.h"
#include "cam_env.h"

#include "runtime/kernel.h"
#include "runtime/mem.h"
#include "runtime/dev.h"
#include "../tools/socket/cam_socket_exchange.h"

using namespace std;
using namespace chrono;

namespace Cam {
    constexpr int AI_CORE_NUM_24 = 24;
    constexpr int AI_CORE_NUM_20 = 20;
    constexpr int AI_CORE_NUM_2 = 2;
    constexpr int DEFAULT_CAM_BUFF_SIZE = 204;
    constexpr int MAX_CAM_BUFF_SIZE = 2000;

enum TopologyType : int {
    TOPOLOGY_HCCS = 0,
    TOPOLOGY_PIX,
    TOPOLOGY_PIB,
    TOPOLOGY_PHB,
    TOPOLOGY_SYS,
    TOPOLOGY_SIO,
    TOPOLOGY_HCCS_SW
 };
constexpr int HCCL_IPC_PID_ARRAY_SIZE = 1;  // 固定每次只传一个PID数据
constexpr int CAM_INIT_TIMEOUT = 600;
constexpr int CAM_SDID_INFO_TYPE = 26;

static map<string, GM_ADDR [CAM_MAX_RANK_SIZE]> g_localPeerMemMap;
static map<string, int[CAM_MAX_RANK_SIZE]> g_devList;
static std::mutex g_mtx;

static const std::unordered_map<std::string, ChipName> GetChipMap()
{
    static const std::unordered_map<std::string, ChipName> chipMap{{"Ascend310P", ChipName::CHIP_310P3},
        {"Ascend910B1", ChipName::CHIP_910B1},
        {"Ascend910B2", ChipName::CHIP_910B2},
        {"Ascend910B2C", ChipName::CHIP_910B2C},
        {"Ascend910B3", ChipName::CHIP_910B3},
        {"Ascend910B4", ChipName::CHIP_910B4},
        {"Ascend910B4-1", ChipName::CHIP_910B41},
        {"Ascend910_9391", ChipName::CHIP_910_9391},
        {"Ascend910_9381", ChipName::CHIP_910_9381},
        {"Ascend910_9392", ChipName::CHIP_910_9392},
        {"Ascend910_9382", ChipName::CHIP_910_9382},
        {"Ascend910_9372", ChipName::CHIP_910_9372},
        {"Ascend910_9361", ChipName::CHIP_910_9361}};
    return chipMap;
}

/**
 * @brief 用于获取芯片名称
 */
static ChipName GetChipName()
{
    // 在分配内存时用到
    static ChipName curChipName = ChipName::RESERVED;
    if (curChipName != ChipName::RESERVED) {
        return curChipName;
    }
    constexpr int socVerLength = 100;  // asd没有相应的宏的常量，这里和asd测试代码中的长度保持一致
    char ver[socVerLength];
    auto ret = rtGetSocVersion(ver, socVerLength);
    if (ret != RT_ERROR_NONE) {
        CAM_LOG(ERROR) << "rtGetSocVersion failed, not sure whether the function is normal, please use it with caution";
        return ChipName::RESERVED;
    }
    string chipName(ver);
    CAM_LOG(DEBUG) << "rtGetSocVersion -- The result after converting ver to string is:" << chipName;
    const std::unordered_map<std::string, ChipName> chipMap = GetChipMap();
    auto it = chipMap.find(chipName);
    if (it != chipMap.end()) {
        curChipName = it->second;
    } else {
        CAM_LOG(WARN) << "There is no commitment to the supported chip types yet," <<
            "and it is not certain whether the functions will work properly.";
    }
    return curChipName;
}

static uint32_t GetCoreNum(ChipName chipName)
{
    switch (chipName) {
        case ChipName::CHIP_910B1:
        case ChipName::CHIP_910B2:
        case ChipName::CHIP_910_9391:
        case ChipName::CHIP_910_9381:
        case ChipName::CHIP_910_9392:
        case ChipName::CHIP_910_9382:
        case ChipName::CHIP_910B2C:
            return AI_CORE_NUM_24;
        case ChipName::CHIP_910B3:
        case ChipName::CHIP_910B4:
        case ChipName::CHIP_910B41:
        case ChipName::CHIP_910_9372:
        case ChipName::CHIP_910_9361:
        case ChipName::CHIP_910A5:
            return AI_CORE_NUM_20;
        case ChipName::CHIP_310P3:
            return AI_CORE_NUM_2;
        default:
            CAM_LOG(ERROR) << "Unknown chip name";
            return 0;
    }
}

// 如果是互联的链路，返回false;  对910B2C那些不互联的链路，返回true
static bool SkipUnusedChannel910B2C(int curRank, int peerRank, ChipName chipName)
{
    if (chipName == ChipName::CHIP_910B2C) {
        constexpr int rankSizePerNode = 8;
        // 双节点16P中不用的链路:不在同一个节点 且rank在节点内序号不同； 在调用时将跳过
        if ((curRank / rankSizePerNode != peerRank / rankSizePerNode)
            && (std::abs(curRank - peerRank) != rankSizePerNode)) {
                return true;
        }
    }
    return false;
}

static uint64_t GetCamMaxWindowSize()
{
    const char* CAM_BUFFSIZE = "CAM_BUFFSIZE";
    auto defaultWindowSize = DEFAULT_CAM_BUFF_SIZE;
    if (getenv(CAM_BUFFSIZE) == nullptr) {
        CAM_LOG(DEBUG) << "Env CAM_BUFFSIZE don't set";
    } else {
        try {
            std::string envStr(getenv(CAM_BUFFSIZE));
            defaultWindowSize = std::stoi(envStr);
            if (defaultWindowSize > MAX_CAM_BUFF_SIZE) {
                CAM_LOG(ERROR) << "CAM_BUFFSIZE" << defaultWindowSize << ", is larger than MAX_CAM_BUFF_SIZE %d"
                    << MAX_CAM_BUFF_SIZE;
            }
        } catch (...) {
                CAM_LOG(ERROR) << "Unknown Exception encountered when parse env CAN_BUFFSIZE";
        }
    }
    const uint64_t maxWindowSize = static_cast<uint64_t>(defaultWindowSize) * 1024UL * 1024UL;
    CAM_LOG(INFO) << "Get CamMaxWindowSize is " << maxWindowSize;
    return maxWindowSize;
}

int CamComm::SyncCommArgs()
{
    commArgs_.rank = rank_;
    commArgs_.localRank = localRank_;
    commArgs_.rankSize = rankSize_;
    commArgs_.localRankSize = localRankSize_;
    for (int i = 0; i < rankSize_; ++i) {
        commArgs_.peerMems[i] = peerMem_[i];     // 这里不会越界，之前有逻辑校验过越界了
    }
    commArgs_.batchSize = batchSize_;
    commArgs_.hiddenSize = hiddenSize_;
    commArgs_.topk = topk_;
    commArgs_.sharedExpertRankNum = sharedExpertRankNum_;
    commArgs_.memLen = memLen_;
    int ret = 0;
    ret = aclrtMalloc(reinterpret_cast<void **>(&commArgsPtr_), sizeof(commArgs_), ACL_MEM_MALLOC_HUGE_FIRST);
    if (ret != ACL_SUCCESS) {
        CAM_LOG(ERROR) << "aclrtMalloc err" << __LINE__ << " " << ret;
        return CAM_ERROR_INTERNAL;
    }
    ret = aclrtMemcpy(commArgsPtr_, sizeof(commArgs_), &commArgs_, sizeof(commArgs_), ACL_MEMCPY_HOST_TO_DEVICE);
    if (ret != ACL_SUCCESS) {
        CAM_LOG(ERROR) << "aclrtMemcpy err " << __LINE__ << " " << ret;
        return CAM_ERROR_INTERNAL;
    }
    return CAM_SUCCESS;
}

int CamComm::InitCommon()
{
    // enable peer device
    if (EnablePeerAccess() != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "EnablePeerAccess failed!";
        return CAM_ERROR_INTERNAL;
    }

    return CAM_SUCCESS;
}

void CamComm::CloseIpcMem()
{
    for (int i = 0; i < rankSize_; ++i) {
        if (i == rank_ || peerMem_[i] == nullptr) {
            continue;
        }
        int ret = rtIpcCloseMemory(static_cast<void *>(peerMem_[i]));
        if (ret != RT_ERROR_NONE) {
            CAM_LOG(WARN) << "Close ipc[" << i << "] memory failed! ret: " << ret;
        }
        peerMem_[i] = nullptr;
    }
}

void CamComm::FreePeerMem(GM_ADDR &mem) const
{
    if (mem != nullptr) {
        aclError aclRet = aclrtFree(mem);
        if (aclRet != ACL_SUCCESS) {
            CAM_LOG(ERROR) << "Free share memory failed! ret: " << aclRet;
        }
    }
    mem = nullptr;
}

int CamComm::Init()
{
    if (inited_) {
        return CAM_SUCCESS;
    }
    if (rank_ < 0 || rank_ >= rankSize_ || rankSize_ <= 0 || rankSize_ > CAM_MAX_RANK_SIZE) {
        CAM_LOG(ERROR) << "The rank is invalid! rank: " << rank_ << "rankSize:" << rankSize_;
        return CAM_ERROR_PARA_CHECK_FAIL;
    }

    socketExchange_ = new (nothrow) CamSocketExchange(rank_, rankSize_, rankList_, serverIpPort_);

    if (socketExchange_ == nullptr) {
        CAM_LOG(ERROR) << "CamSocketExchange create failed. rank : " << rank_ << "rankSize:" << rankSize_;
        return CAM_ERROR_INTERNAL;
    }
    CommExchangeIds exchangeIds[CAM_MAX_RANK_SIZE] = {0};
    string memName;

    int ret = GetMyExchangeIds(exchangeIds[rank_], memName);
    if (ret != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "get my exchange ids and name failed! ret: " << ret;
        return ret;
    }

    ret = IdsExchangeAndProcess(&(exchangeIds[0]));
    if (ret != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "ids exchange and process failed! ret: " << ret;
        return ret;
    }

    if (InitCommon() != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "init common failed!";
        return CAM_ERROR_INTERNAL;
    }

    CAM_LOG(DEBUG) << "Prepare to InitCommMem localRankSize_ -> " << localRankSize_ << ", localRank -> " << localRank_;
    if (InitCommMem(&(exchangeIds[0]),memName) != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "InitCommMem failed!";
        return CAM_ERROR_INTERNAL;
    }
    CAM_LOG(DEBUG) << "InitCommMem " << rank_ << "/" << rankSize_ << ", localRank_ : " << localRank_ <<
        ", localRankSize_ : " << localRankSize_ << "success";
    
    // set comm args in device
    SyncCommArgs();
    CAM_LOG(INFO) << "CamCommInit" << rank_  << "/" << rankSize_ << " success and extraFlag:" << commArgs_.extraFlag <<
        " commArgs_. localRank : " << commArgs_.localRank << "commArgs_.localRankSize : " << commArgs_.localRankSize;
    inited_ = true;
    delete socketExchange_;  // socketExchange_不会为空
    socketExchange_ = nullptr;
    return CAM_SUCCESS;
}

/**
 *  @brief 函数内部会有检测，是否需要进行 alcrtDeviceEnablePeerAccess， 如果芯片为310P且是HCCS链路， 则不调用此函数
 */
int CamComm::EnablePeerAccess()
{
    for (auto &dev : devList_) {
        if (devId_ == dev) {
            continue;
        }
        // 处理910B2C 16卡通信的特例
        if (SkipUnusedChannel910B2C(dev, devId_, GetChipName())) {
            continue;
        }

        int64_t value = 0;
        if (rtGetPairDevicesInfo(devId_, dev, 0, &value) != RT_ERROR_NONE) {
            CAM_LOG(WARN) << devId_ << " & " << dev << "pair devices info failed to get";
        } else {
            CAM_LOG(DEBUG) << devId_ << " <-----> " << dev << ", halGetPairDevicesInfo: *value = " << value;
        }

        // 如果310P未来通信域要支持两卡四芯的话，这里需要做更改。并且现在默认服务器上机器只有一个链路种类。
        if (value == TOPOLOGY_HCCS || value == TOPOLOGY_SIO || value == TOPOLOGY_HCCS_SW ||
            GetChipName() == ChipName::CHIP_910B2C) {
                physicalInfo_.physicalLink = PhysicalLink::HCCS;
        } else if (physicalInfo_.physicalLink == PhysicalLink::RESERVED) {
            physicalInfo_.physicalLink = PhysicalLink::PCIE;
            if (rankSize_ > PING_PONG_SIZE) {
                CAM_LOG(ERROR) << "do not support pcie > 2 rank! rankSize_ = " << rankSize_;
                return CAM_ERROR_INTERNAL;
            }
        }

        physicalInfo_.coreNum = GetCoreNum(physicalInfo_.chipName);

        // value里的0实际上对应驱动枚举类的 TOPOLOGY_HCCS
        if (physicalInfo_.chipName == ChipName::CHIP_310P3 && value == 0) {
            CAM_LOG(WARN) << "warn aclrtDeviceEnablePeerAccess is skipped! peerDeviceId = " << dev;
            continue;
        }

        aclError ret = aclrtDeviceEnablePeerAccess(dev, 0);
        if (ret != ACL_SUCCESS) {
            CAM_LOG(ERROR) << "err aclrtDeviceEnablePeerAccess failed peerDeviceId = " << dev << ",rank= " << rank_
                           << ", value = " << value << ", flags = " << 0 << "," << __LINE__ << ":" << ret;
            return CAM_ERROR_INTERNAL;
        }
    }
    CAM_LOG(DEBUG) << "EnablePeerAccess succeed" << rank_;
    return CAM_SUCCESS;
}

int CamComm::InitMem()
{
    // 申请并初始化IpcBuff
    CAM_LOG(DEBUG) << "maxBuffSize " << memLen_;
    void *peerMem = nullptr;
    aclError ret = aclrtMalloc(&peerMem,
        memLen_,
        (GetChipName() == ChipName::CHIP_310P3) ? ACL_MEM_MALLOC_HUGE_FIRST_P2P : ACL_MEM_MALLOC_HUGE_FIRST);
    if (ret != ACL_SUCCESS) {
        CAM_LOG(ERROR) << "allocate device mem error " << __FILE__ << ":" <<__LINE__ << " " << ret;
        return CAM_ERROR_INTERNAL;
    }
    peerMem_[rank_] = static_cast<GM_ADDR>(peerMem);
    CAM_LOG(DEBUG) << "peerMem[rank" << rank_ <<"], allocate finished.";
    aclrtMemset(peerMem_[rank_], memLen_, 0 ,memLen_);
    return CAM_SUCCESS;
}

int CamComm::GetMyExchangeIds(CommExchangeIds &ids, string &name)
{
    if (rank_ >= rankSize_) {
        CAM_LOG(ERROR) << "CamComm::GetMyExchangeIds err rank_ >= rankSize_ " << rank_ << ">=" << rankSize_;
        return CAM_ERROR_INTERNAL;
    }
    // 在此处先填chipname信息
    physicalInfo_.chipName = GetChipName();

    // 获取当前的devId
    // 这里这个nodeNum可以理解为Y轴长度，手动控制的话将这个拦截修改即可。
    int nodeNum = socketExchange_->GetNodeNum();
    if (nodeNum <= 0 || nodeNum > rankSize_) {
        CAM_LOG(ERROR) << "error! node num : " << nodeNum << "rank size:" << rankSize_;
        return CAM_ERROR_INTERNAL;
    }
    localRankSize_ = rankSize_/nodeNum;
    localRank_ = rank_ % localRankSize_;
    CAM_LOG_DEBUG << "GetDev : localRankSize_ :" << localRankSize_ << "localRank_: " << localRank_
                    <<" rank :" << rank_ <<"  rankSize :" << rankSize_;
    devList_.resize(rankSize_);
    // get current id
    aclError aclRet = aclrtGetDevice(&(ids.devId));
    if (aclRet != ACL_SUCCESS) {
        CAM_LOG(ERROR) << "aclrtGetDevice error! ret: " << aclRet;
        return CAM_ERROR_INTERNAL;
    }
    devId_ = ids.devId;
    devList_[rank_] = ids.devId;
    
    // 获取当前pid
    if (rtDeviceGetBareTgid(&(ids.pid)) != RT_ERROR_NONE) { // 获取docker外的进程id， bare指docker外
        CAM_LOG(ERROR) << "DeviceGetBareTgid err" << __LINE__;
        return CAM_ERROR_INTERNAL;
    }
    pids[rank_] = ids.pid;

    // 获取当前sdid
    if ((physicalInfo_.chipName >= ChipName::CHIP_910_9391) && (physicalInfo_.chipName < ChipName::RESERVED)) {
        const int rtModuleTypeSystem = 0;
        const int infoTypeSdid = CAM_SDID_INFO_TYPE;
        if (rtGetDeviceInfo(devList_[rank_], rtModuleTypeSystem, infoTypeSdid, &(ids.sdid)) != RT_ERROR_NONE) {
            CAM_LOG(ERROR) << "DeviceGetDeviceInfo err " << __LINE__;
            return CAM_ERROR_INTERNAL;
        }
        CAM_LOG(DEBUG) << "rank" << rank_ << " dev id: " << devList_[rank_]
                       << " rtGetDeviceInfo sdid: " << ids.sdid;
    }

    // 获取本地mem name
    int ret = InitMem();
    if (ret != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "InitMem error! ret: " << ret;
        return ret;
    }
    char nameModified[IPC_NAME_SIZE] = {};
    if (rtIpcSetMemoryName(peerMem_[rank_], memLen_, nameModified, IPC_NAME_SIZE) != RT_ERROR_NONE) {
        return CAM_ERROR_INTERNAL;
    }
    name = nameModified;
    CAM_LOG(DEBUG) << "memory name of rank " << rank_ << " is " << nameModified;

    return CAM_SUCCESS;
}

int CamComm::IdsExchangeAndProcess(CommExchangeIds *ids)
{
    // 信息交换
    int ret = socketExchange_->AllGather(&(ids[rank_]), 1, ids);
    if (ret != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "CamSocketExchange AllGather error! ret:  " << ret;
        return CAM_ERROR_INTERNAL;
    }

    // 处理并打印交换的信息
    std::string devIdStr = "";
    for (int i = 0; i < rankSize_; ++i) {
        if (i != rank_) {
            // 为类私有变量赋值，用于后续使用
            devList_[i] = ids[i].devId;
            pids[i] = ids[i].pid;
        }

        CAM_LOG(DEBUG) << "rank : " << rank_ << ", otherRank : " << i << " pid[" << i << "]:" << pids[i];
        CAM_LOG(DEBUG) << "rank : " << i << " sdid: " << ids[i].sdid;
        devIdStr += (i==0 ? "" : ", ");
        devIdStr += to_string(devList_[i]);
    }
    CAM_LOG(DEBUG) << "rank : " << rank_ << "devId: " << devId_ << ", otherDevList" << devIdStr;
    CAM_LOG(INFO) << "AllGather: Get other rank ids success";
    return CAM_SUCCESS;
}

int CamComm::GetName(std::string &name, std::vector<char> &names) const
{
    int ret = socketExchange_->AllGather<char>(name.c_str(), IPC_NAME_SIZE, names.data());
    if (ret != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "CamSocketExchange AllGather error! ret:  " << ret;
        return CAM_ERROR_INTERNAL;
    }
    for (int i = 0 ; i < rankSize_; ++i) {
        CAM_LOG(DEBUG) << "rank : " << i << "mem name: " << names.data() + i * IPC_NAME_SIZE;
    }
    CAM_LOG(DEBUG) << "AllGather: Get other rank mem name";
    return CAM_SUCCESS;
}

int CamComm::InitCommMem(CommExchangeIds *exchangeIds, std::string &name)
{
    if (SetIpcPidSdid(exchangeIds, name) != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "SetIpcPidSdid failed!";
        return CAM_ERROR_INTERNAL;
    }

    std::vector<char> names(CAM_MAX_RANK_SIZE * IPC_NAME_SIZE);
    if (GetName(name, names) != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "GetName error!";
        return CAM_ERROR_INTERNAL;        
    }

    if (OpenIpcMem(names) != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "rank: " << rank_ << " OpenIpcMem failed!";
        return CAM_ERROR_INTERNAL;        
    }
    return CAM_SUCCESS;
}

int CamComm::OpenIpcMem(const std::vector<char> &names)
{
    static mutex mut;
    lock_guard<mutex> lock(mut);
    for (int i = 0; i < rankSize_; ++i) {
        if (i == rank_) {
            continue;
        }
        // 处理910B2C 16卡通信的特例
        if (SkipUnusedChannel910B2C(rank_, i, GetChipName())) {
            continue;
        }
        const char* name = names.data() + i * IPC_NAME_SIZE;
        void *peerMem = nullptr;
        int ret = rtIpcOpenMemory(&peerMem, name);
        peerMem_[i] = static_cast<GM_ADDR>(peerMem);
        if (ret != RT_ERROR_NONE) {
            CloseIpcMem();
            CAM_LOG(ERROR) << "rank" << rank_ << " localRank : " << localRank_ << " peerMem: " << i
                           << " IpcOpenMemory err " << ret;
            return CAM_ERROR_INTERNAL;
        }
    }
    ipcMemInited_ = true;
    return CAM_SUCCESS;
}

int CamComm::SetIpcPidSdid(CommExchangeIds *exchangeIds, string name) const
{
    for (int i = 0; i < rankSize_; ++i) {
        if (i == rank_) {
            continue;
        }

        if (physicalInfo_.chipName < ChipName::CHIP_910_9391) {
            // 910B
            int32_t pidInt32 = static_cast<int32_t>(exchangeIds[i].pid);
            int rtRet = rtSetIpcMemPid(name.c_str(), &pidInt32, HCCL_IPC_PID_ARRAY_SIZE);
            if (rtRet != RT_ERROR_NONE) {
                CAM_LOG(ERROR) << "err " << rtRet;
                return CAM_ERROR_INTERNAL;
            }
        } else {
            // 910A3
            int32_t pidInt32 = static_cast<int32_t>(exchangeIds[i].pid);
            int rtRet = rtSetIpcMemorySuperPodPid(name.c_str(), exchangeIds[i].sdid, &pidInt32,
                HCCL_IPC_PID_ARRAY_SIZE);
            if (rtRet != RT_ERROR_NONE) {
                CAM_LOG(ERROR) << "err " << rtRet << ", rank " << i << ", name " << name << ", sdid "
                            << exchangeIds[i].sdid << ", pid " << pidInt32;
                return CAM_ERROR_INTERNAL;
            }
        }
    }
    return CAM_SUCCESS;
}

CamComm::~CamComm()
{
    CAM_LOG(WARN) << "Camcomm start destructor.";
    {
        lock_guard<mutex> lock(g_mtx);
        if (g_localPeerMemMap.find(uid_) != g_localPeerMemMap.end()) {
            g_localPeerMemMap.erase(uid_);
        }
    }
    if (ipcMemInited_) {
        CloseIpcMem();
        ipcMemInited_ = false;
    }
    if (socketExchange_) {
        delete socketExchange_;
        socketExchange_ = nullptr;
    }
    FreePeerMem(peerMem_[rank_]);
    FreePeerMem(commArgsPtr_);
}

CamComm::CamComm(int rank, int rankSize, int devId, const vector<int> &devList, std::string serverIpPort)
    : rank_(rank), rankSize_(rankSize), devId_(devId), devList_(devList), serverIpPort_(serverIpPort),
    memLen_(GetCamMaxWindowSize())
{
}

int CamComm::GetRankSize() const
{
    return rankSize_;
}

GM_ADDR CamComm::GetCommArgsPtr()
{
    return commArgsPtr_;
}

int64_t CamComm::GetAndIncreaseMagic()
{
    if (this->magic_ > MAGIC_MAX) {
        this->magic_ = 1;
    }
    return this->magic_++;
}

}   // Cam 