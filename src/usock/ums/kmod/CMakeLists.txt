#
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

find_package(KernelHeaders REQUIRED)
if("${BUILD_EXTRA_UBCORE_SYMBOLS}" STREQUAL "enable")
    find_package(UBcore REQUIRED)
endif()

#Get config_SMC
execute_process(COMMAND bash -c
"cat /boot/config-${KERNEL_RELEASE} | grep 'CONFIG_SMC=m' | awk -F'=' '{print $2}' "
    OUTPUT_VARIABLE CONFIG_SMC
    OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "CONFIG_SMC=${CONFIG_SMC}")
message(STATUS "begin building UMS!")
add_subdirectory(ums)
