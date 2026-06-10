#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
set -e

# build demo
function build_example () {
  echo "building AIGW example"
  if [ ! -d "${ROOT_DIR}" ];then
    echo "${ROOT_DIR} not found!"
    exit 1
  fi

  # build cgo example
  cd "${ROOT_DIR}/example/" || exit 1

  rm -rf build && mkdir build
  cd build
  echo "set CMake..."
  cmake ..
  echo "make start..."
  make -j$(nproc)
  mkdir -p /tmp/aigw/example/ && cp -f "${ROOT_DIR}/example/ttft_pretrain.txt" /tmp/aigw/example/
}