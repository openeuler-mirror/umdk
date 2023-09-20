# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# Description: config and define for cmake
# Author: pandongyang
# Create: 2020-02-20
# Note:
# History: 2020-02-20 pandongyang clipping config for cmake


find_package(PkgConfig)
pkg_check_modules(PC_GLIB QUIET glib-2.0)

find_path(UB_GLIB_INCLUDE_DIR
    NAMES glib.h
    HINTS ${PC_GLIB_INCLUDEDIR}
          ${PC_GLIB_INCLUDE_DIRS}
    PATH_SUFFIXES glib-2.0
)

find_path(UB_GLIB_CONFIG_INCLUDE_DIR
    NAMES glibconfig.h
    HINTS ${PC_LIBRARY_DIRS} ${PC_GLIB_INCLUDE_DIRS} ${PC_GLIB_INCLUDEDIR} ${_GLIB_LIBRARY_DIR} ${PC_LIBDIR}
    PATH_SUFFIXES glib-2.0/include
)

set(GLIB_INCLUDE_DIRS ${UB_GLIB_INCLUDE_DIR} ${UB_GLIB_CONFIG_INCLUDE_DIR})