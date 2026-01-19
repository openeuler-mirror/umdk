#ifndef CAM_TYPES_H_
#define CAM_TYPES_H_

#include <stdint.h>
#include <hccl/hccl_types.h>
#include <map>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *CamCommPtr;

namespace Cam {
constexpr int CAM_SUCCESS = 0;
constexpr int CAM_ERROR_NOT_INITIALIZED = -1;
constexpr int CAM_ERROR_MKIRT = -2;
constexpr int CAM_ERROR_PARA_CHECK_FAIL = -3;
constexpr int CAM_ERROR_INTERNAL = -4;
constexpr int CAM_ERROR_TIMEOUT = -5;
constexpr int CAM_ERROR_NOT_FOUND = -7;
constexpr int OUT_OF_DEVICE_MEMORY = -8;
constexpr int64_t CAM_INVALID_VALUE = -1;

constexpr int CAM_BUFF_BYTES = 204 * 1024 * 1024;
}

#ifdef __cplusplus
}
#endif
#endif