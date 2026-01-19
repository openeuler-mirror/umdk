#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include <hccl/hccl.h>
#include "cam_api.h"
#include "cam_comm.h"
#include <iostream>
#include "ext_utils.h"

using namespace at;
using namespace std;

CamCommPtr g_comms[MAX_COMMS] = { 0 };
constexpr int PARAM_ARGS_CNT = 1;

at::Tensor cam_get_comm(const int64_t comm_id, const int64_t rank, const int64_t group_size,
    std::string serverIpPort)
{
    cam_comm_init(comm_id, rank, group_size, serverIpPort);
    Cam::CamComm *cam_comm(static_cast<Cam::CamComm *>(g_comms[comm_id]));
    auto comm_size = sizeof(Cam::CommArgs);

    auto options = torch::TensorOptions().dtype(torch::kFloat16);
    return torch::from_blob(cam_comm->GetCommArgsPtr(), {comm_size/FLOAT_16_SIZE}, options);
}

bool cam_comm_init(const int64_t comm_id, const int64_t rank, const int64_t group_size,
    std::string serverIpPort)
{
    if (comm_id > MAX_COMMS || comm_id < 0) {
        printf("Comm Id Invalid : %d \n", comm_id);
        return false;
    }
    if (g_comms[comm_id] != nullptr) {
        printf("CamComm %d has been created. rank : %d \n", comm_id, rank);
        return true;
    }

    int ret = CamCreateComm(group_size, rank, serverIpPort.data(), serverIpPort.size(), &g_comms[comm_id]);
    if (ret != Cam::CAM_SUCCESS) {
        printf("CamComm create failed. rank : %d \n", rank);
        return false;
    }
    return true;
}

int32_t cam_get_rank_size(const int64_t comm_id)
{
    Cam::CamComm *cam_comm(static_cast<Cam::CamComm *>(g_comms[comm_id]));
    if (cam_comm == nullptr) {
        printf("ERROR!!! COMM is not INIT!!!");
        return 0;
    }
    int rankSize = cam_comm->GetRankSize();
    return rankSize;
}

int64_t cam_get_and_increase_magic(const int64_t comm_id)
{
    Cam::CamComm *cam_comm(static_cast<Cam::CamComm *>(g_comms[comm_id]));
    if (cam_comm == nullptr) {
        printf("ERROR!!! COMM is not INIT!!!");
        return 0;
    }
    int magic = cam_comm->GetAndIncreaseMagic();
    return magic;
}

int64_t cam_get_magic(const int64_t comm_id)
{
    Cam::CamComm *cam_comm(static_cast<Cam::CamComm *>(g_comms[comm_id]));
    if (cam_comm == nullptr) {
        printf("ERROR!!! COMM is not INIT!!!");
        return 0;
    }
    int magic = cam_comm->GetMagic();
    return magic;
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("cam_get_comm", &cam_get_comm);
    m.impl("cam_free_comm", &cam_free_comm);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("cam_get_comm", &cam_get_comm);
    m.impl("cam_free_comm", &cam_free_comm);
}

// 为Meta设备注册前反向实现
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("cam_get_comm", &cam_get_comm);
    m.impl("cam_free_comm", &cam_free_comm);
}

at::Tensor cam_free_comm(const int64_t comm_id)
{
    int ret = CamDestroyComm(g_comms[comm_id]);
    if (ret != Cam::CAM_SUCCESS) {
        printf("ERROR!!! COMM is not freed!!!");
    }
    g_comms[comm_id] = nullptr;

    return at::Tensor();
}

