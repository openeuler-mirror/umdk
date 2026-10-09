/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Stub for acl.h used in snc_ping unit tests
 */
#ifndef ACL_ACL_H_
#define ACL_ACL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int aclError;
#define ACL_SUCCESS 0

aclError aclrtSetDevice(int32_t deviceId);

#ifdef __cplusplus
}
#endif

#endif
