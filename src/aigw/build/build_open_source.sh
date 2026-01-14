#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set -e

# build opensource
function build_open_source () {
  echo "building opensource"
  if [ ! -d "${ROOT_DIR}" ];then
    echo "${ROOT_DIR} not found!"
    exit 1
  fi

  OPENSOURCE_OUTPUT_DIR="${ROOT_DIR}/output/opensource"
  mkdir -p "${OPENSOURCE_OUTPUT_DIR}"

  echo "compile lightgbm"
  cd "${OPENSOURCE_OUTPUT_DIR}"

  local cmake_command=cmake
  if [[ "${WITH_DEBUG}" == "ON" ]]; then
    cmake_command+=( ${ROOT_DIR}/open_source -WITH_DEBUG=ON -USE_DEBUG=ON)
  else
    cmake_command+=( ${ROOT_DIR}/open_source)
  fi

  cmake_command+=(-DBUILD_STATIC_LIB=ON -DBUILD_CLI=OFF -DUSE_OPENMP=OFF)
  cmake_command+=(-DCMAKE_INSTALL_PREFIX=${ROOT_DIR}/output/opensource)

  # checking ccache
  if command -v ccache &> /dev/null; then
      echo "ccache detected, enable compilation cache"
      cmake_command+=(-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
  else
      echo "ccache not found, proceeding without cache"
  fi
  
  echo "Run " "${cmake_command[@]}"
  if ! "${cmake_command[@]}"
  then
    print_error "Failed to configure the cmake"
    exit 1
  fi

  # Actually, the last CPU number is the total number of CPUs minus one
  cpucount=$(awk '/^processor/{print $NF}' /proc/cpuinfo | tail -n1)
  make -j$cpucount VERBOSE=1
  ret=$?
  if [ $ret -ne 0 ];then
    echo "Building lightgbm failed with err ${ret}."
    exit 1
  fi

  echo "finished to build lightgbm"
}