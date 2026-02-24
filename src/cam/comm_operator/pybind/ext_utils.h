#ifndef COMMON_OPS_EXT_UTILS_H_
#define COMMON_OPS_EXT_UTILS_H_

#include "cam_comm.h"

constexpr int MAX_COMMS = 64;
constexpr int COMM_PARAM_CNT = 3;
constexpr int FLOAT_16_SIZE = 2;

extern CamCommPtr g_comms[MAX_COMMS];

bool cam_comm_init(const int64_t comm_id, const int64_t rank, const int64_t group_size,
    std::string serverIpPort);

at::Tensor cam_get_comm(const int64_t comm_id, const int64_t rank, const int64_t group_size,
    std::string serverIpPort);

at::Tensor cam_free_comm(const int64_t comm_id);

int32_t cam_get_rank_size(const int64_t comm_id);

int64_t cam_get_and_increase_magic(const int64_t comm_id);

int64_t cam_get_magic(const int64_t comm_id);

#endif