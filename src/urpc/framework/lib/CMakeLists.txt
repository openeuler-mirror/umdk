# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include(${CMAKE_CURRENT_LIST_DIR}/control/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/datapath/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/manager/CMakeLists.txt)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} URPC_LIB_DIR_SRCS)
