#
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

include_directories(${KERNELHEADERS_INCLUDE_DIRS})

aux_source_directory(. SRC_LIST)

set(DRIVER_FILE ums.ko)

# Generate the Kbuild file through cmake.
FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := ums.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs := cm/ums_clc.o cm/ums_nl.o cm/ums_core.o cm/ums_llc.o cm/ums_process_link.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += dev/ums_pnet.o dev/ums_ubcore.o dev/ums_wr.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += dfx/ums_dfx.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += utils/ums_common.o utils/ums_ns.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += io/ums_cdc.o io/ums_rx.o io/ums_tx.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += sockops/ums_accept.o sockops/ums_bind.o \
sockops/ums_close.o sockops/ums_connect.o sockops/ums_listen.o sockops/ums_release.o sockops/ums_sockops.o\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += ums_mod.o\n")

if (${KERNEL_RELEASE} STRLESS "5")
    FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -DKERNEL_VERSION_4\n")
else()
    FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ums-objs += dim/ums_dim.o\n")
endif()

if(BUILD_WITH_UT)
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -DUMS_UT_TEST\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -fdump-rtl-expand\n")
endif()

FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/utils\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/sockops\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/dev\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/cm\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/io\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/dim\n")
FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -I${CMAKE_CURRENT_SOURCE_DIR}/dfx\n")

if ("${CONFIG_SMC}" STREQUAL "m")
    FILE(APPEND ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "ccflags-y += -DCONFIG_SMC\n")
endif()

if("${BUILD_EXTRA_UBCORE_SYMBOLS}" STREQUAL "enable")
    set(KBUILD_CMD $(MAKE) -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}
        KBUILD_MODPOST_WARN=1 KBUILD_EXTRA_SYMBOLS=${EXTRA_UBCORE_MOD_SYMVERS})
else()
    set(KBUILD_CMD $(MAKE) -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}
        KBUILD_MODPOST_WARN=1)
endif()

get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

add_custom_command(OUTPUT ${DRIVER_FILE}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${SRC_LIST} Kbuild
    VERBATIM
)

add_custom_target(ums ALL DEPENDS ${DRIVER_FILE})
set_property(TARGET ums PROPERTY C_STANDARD 99)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${DRIVER_FILE} DESTINATION /lib/modules/${KERNEL_RELEASE}/extra/ums/)

add_subdirectory(config)
