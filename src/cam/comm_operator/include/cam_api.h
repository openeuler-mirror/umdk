#ifndef CAM_API_H_
#define CAM_API_H_

#include <hccl/hccl_types.h>
#include <acl/acl.h>
#include <aclnn/acl_meta.h>
#include "cam_types.h"

#ifdef __cplusplus
extern "C" {
#endif 

extern int32_t CamCreateComm(
    uint32_t nRanks, uint32_t rank, char *serverIpPort, uint32_t serverIpPortLen, CamCommPtr *comm);

extern int32_t CamGetCommArgs(CamCommPtr comm, aclTensor **commArgs);

extern int64_t CamGetAndIncreaseMagic(CamCommPtr comm);

extern int32_t CamDestroyComm(CamCommPtr comm);

#ifdef __cplusplus
}
#endif
#endif