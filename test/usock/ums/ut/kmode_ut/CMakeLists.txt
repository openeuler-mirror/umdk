#
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

aux_source_directory(. SRC_LIST)

set(DRIVER_FILE ums_test.ko)

set(UMS_MOD_SYMVERS "${MOD_SYMVERS} ${CMAKE_BINARY_DIR}/ums/kmod/ums/Module.symvers")
message(STATUS "UMS_MOD_SYMVERS = ${UMS_MOD_SYMVERS}")

set(KBUILD_CMD $(MAKE) -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}
    KBUILD_MODPOST_WARN=1 KBUILD_EXTRA_SYMBOLS=${UMS_MOD_SYMVERS})

# Generate the Kbuild file through cmake.
FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := ums_test.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums_test-objs := ums_api_test.o ums_token_kmod_test.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/utils\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/sockops\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/dev\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/cm\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/io\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/dim\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_SOURCE_DIR}/../../../src/usock/ums/kmod/ums/dfx\n")

if(BUILD_WITH_UT)
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -DUMS_UT_TEST\n")
endif()

get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

add_custom_command(OUTPUT ${DRIVER_FILE}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ums ${SRC_LIST}
    VERBATIM
)

add_custom_target(ums_test ALL DEPENDS ${DRIVER_FILE})
set_property(TARGET ums_test PROPERTY C_STANDARD 99)