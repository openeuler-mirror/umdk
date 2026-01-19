#include "cam_api.h"
#include "cam_types.h"
#include "cam_log.h"
#include "cam_comm.h"

#ifdef __cplusplus
extern "C" {
#endif
namespace {
constexpr int FLOAT_16_SIZE = 2;
}

int32_t CamCreateComm(uint32_t nRanks, uint32_t rank, char *serverIpPort, uint32_t serverIpPortLen, CamCommPtr *comm)
{
    if (comm == nullptr) {
        CAM_LOG(ERROR) << "comm is nullptr!";
        return Cam::CAM_ERROR_PARA_CHECK_FAIL;
    }
    std::string serverIpPortPara;
    if (serverIpPortLen == 0) {
        serverIpPortPara = "";
    } else {
        serverIpPortPara = std::string(serverIpPort, serverIpPortLen);
    }
    Cam::CamComm *commPtr = new (std::nothrow) Cam::CamComm(rank, nRanks, -1, {}, serverIpPortPara);
    if (commPtr == nullptr) {
        CAM_LOG(ERROR) << "Cam comm create failed. rank : " << rank << ", rankSize : " << nRanks;
        return Cam::CAM_ERROR_INTERNAL;
    }
    int32_t ret = commPtr->Init();
    if (ret != Cam::CAM_SUCCESS) {
        delete commPtr;
        return ret;
    }
    *comm = commPtr;
    return Cam::CAM_SUCCESS;
}

int32_t CamGetCommArgs(CamCommPtr comm, aclTensor **commArgs)
{
    if (comm == nullptr) {
        CAM_LOG(ERROR) << "comm is nullptr!";
        return Cam::CAM_ERROR_PARA_CHECK_FAIL;
    }
    Cam::CamComm *commPtr = static_cast<Cam::CamComm *>(comm);
    int64_t count = (static_cast<int64_t>(sizeof(Cam::CommArgs)) + FLOAT_16_SIZE - 1) / FLOAT_16_SIZE;
    std::vector<int64_t> shape{count};
    std::vector<int64_t> strides{1};
    GM_ADDR commArgsPtr = commPtr->GetCommArgsPtr();
    *commArgs = aclCreateTensor(shape.data(), shape.size(), aclDataType::ACL_FLOAT16, strides.data(), 0,
        aclFormat::ACL_FORMAT_ND, shape.data(), shape.size(), commArgsPtr);
    return Cam::CAM_SUCCESS;
}

int64_t CamGetAndIncreaseMagic(CamCommPtr comm)
{
    if (comm == nullptr) {
        CAM_LOG(ERROR) << "comm is nullptr!";
        return Cam::CAM_ERROR_PARA_CHECK_FAIL;
    }
    Cam::CamComm *commPtr = static_cast<Cam::CamComm *>(comm);
    return commPtr->GetAndIncreaseMagic();
}

int32_t CamDestroyComm(CamCommPtr comm)
{
    if (comm == nullptr) {
        CAM_LOG(ERROR) << "comm is nullptr!";
        return Cam::CAM_ERROR_PARA_CHECK_FAIL;
    }
    Cam::CamComm *commPtr = static_cast<Cam::CamComm *>(comm);
    delete commPtr;
    return Cam::CAM_SUCCESS;
}

#ifdef __cplusplus
}
#endif