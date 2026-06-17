#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#

find_path(UBCORE_DIR REQUIRED
    NAMES ubcore.ko
    PATHS /lib/modules/${CMAKE_HOST_SYSTEM_VERSION}/
    PATH_SUFFIXES
        extra/urma/ubcore
        weak-updates/urma/ubcore
)

find_file(EXTRA_UBCORE_MOD_SYMVERS REQUIRED
    NAMES Module.symvers
    PATHS /usr/include/ub/urma
)