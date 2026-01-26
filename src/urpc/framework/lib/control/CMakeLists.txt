# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} URPC_LIB_DIR_SRCS)

include(${CMAKE_CURRENT_LIST_DIR}/allocator/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/dfx/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/ip/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/unix_server/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/crypto/CMakeLists.txt)