# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

file(GLOB URPC_C_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/framework/urpc_framework_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/framework/urpc_framework_errno.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/framework/urpc_framework_types.h"
)

file(GLOB UMQ_C_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/umq/umq_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/umq/umq_errno.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/umq/umq_pro_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/umq/umq_pro_types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/umq/umq_types.h"
)

install(DIRECTORY DESTINATION /usr/include/ub/umdk/urpc/)
install(FILES ${URPC_C_API_FILE} DESTINATION /usr/include/ub/umdk/urpc/)
install(FILES ${UMQ_C_API_FILE} DESTINATION /usr/include/ub/umdk/urpc/umq)
