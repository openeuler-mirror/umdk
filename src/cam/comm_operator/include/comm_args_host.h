#ifndef CAM_COMM_ARGS_H
#define CAM_COMM_ARGS_H
#include <cstdint>

using GM_ADDR = uint8_t *;
namespace Cam {

constexpr int CAM_MAX_RANK_SIZE = 384;
constexpr int CAM_MED_RANK_SIZE = 32;

constexpr int RANK_SIZE_TWO = 2;
constexpr int64_t IPC_BUFF_MAX_SIZE = 100 * 1024 * 1024;
constexpr int64_t IPC_DATA_OFFSET = 2 * 1024 * 1024;
constexpr int64_t SYNC_FLAG_BIT_NUM = 10;
constexpr int64_t MEM_DMA_UNIT_INT_NUM = 4;
constexpr int64_t EVENT_ID_MASK = 0xFFFFFFFF;
constexpr int64_t PING_PONG_SIZE = 2;
constexpr int64_t UB_SINGLE_DMA_SIZE_MAX = 190 * 1024;
constexpr int64_t SMALL_DATA_SIZE = 1 * 1024 * 1024;
constexpr int64_t UB_SINGLE_PING_PONG_ADD_SIZE_MAX = UB_SINGLE_DMA_SIZE_MAX / 2;
constexpr int UB_ALIGN_SIZE = 32;

constexpr uint8_t COMM_NUM = 2;
constexpr uint8_t COMM_EP_IDX = 0;
constexpr uint8_t COMM_TP_IDX = 1;

// 2step算法中，2个aiv真正用作数据预处理
constexpr int64_t PRE_CORE_REAL_NUM = 2;

constexpr int64_t AIV_PER_AICORE = 2;

constexpr int DFX_COUNT = 50;

constexpr int64_t HALF_NUM = 2;

constexpr int64_t THREE_NUM = 3;

constexpr int64_t FOUR_NUM = 4;

constexpr int64_t VADD_MAX_REPEAT = 255;
constexpr int64_t VADD_UNIT_BYTE = 256;

// vadd单位粒度是256B，vadd最大repeat次数为255，两个相乘的结果
constexpr int64_t MAX_VADD_SIZE = VADD_MAX_REPEAT * VADD_UNIT_BYTE;
constexpr int64_t BLOCK_UNIT_BYTE = 32;
constexpr int64_t VADD_UNIT_TO_BLOCK_UNIT_RATIO = VADD_UNIT_BYTE / BLOCK_UNIT_BYTE;

enum Op : int { COPYONLY = -1, ADD = 0, MUL = 1, MAX = 2, MIN = 3};

struct ExtraFlag {
    static constexpr uint32_t RDMA = 1;
    static constexpr uint32_t TOPO_910B2C = 1 << 1;
    static constexpr uint32_t TOPO_910_93 = 1 << 2;
    static constexpr uint32_t DETERMINISTIC = 1 << 3;
    static constexpr uint32_t QUANT_FP16 = 1 << 4;
    static constexpr uint32_t QUANT_FP32 = 1 << 5;
    static constexpr uint32_t TOPO_910A5 = 1 << 6;
    static constexpr uint32_t QUANT_DELAY = 1 << 7;
    static constexpr uint32_t QUANT_CURRENT = 1 << 8;
    static constexpr uint32_t TOPO_PCIE = 1 << 9;
    static constexpr uint32_t ATOMIC_ENABLE = 1 << 15;
};

struct CommArgs {
    int rank = 0;
    int localRank = -1;
    int rankSize = 0;
    int localRankSize = -1;
    uint32_t extraFlag = 0;
    int testFlag = 0;
    GM_ADDR peerMems[CAM_MAX_RANK_SIZE] = {};
    int64_t sendCountMatrix[CAM_MAX_RANK_SIZE * CAM_MAX_RANK_SIZE] = {};
    int64_t sendCounts[CAM_MAX_RANK_SIZE] = {};
    int64_t sdispls[CAM_MAX_RANK_SIZE] = {};
    int64_t recvCounts[CAM_MAX_RANK_SIZE] = {};
    int64_t rdispls[CAM_MAX_RANK_SIZE] = {};
    int64_t batchSize;
    int64_t hiddenSize;
    int64_t topk;
    int64_t sharedExpertRankNum;
    int64_t expertNumPerRank;
    int64_t dfx[DFX_COUNT] = {};
    int64_t memLen;
};
}
#endif