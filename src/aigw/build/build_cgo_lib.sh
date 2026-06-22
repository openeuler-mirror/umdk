#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
set -e

# build cgo
function build_cgo_lib () {
  echo "building AIGW dynamic library"
  if [ ! -d "${ROOT_DIR}" ];then
    echo "${ROOT_DIR} not found!"
    exit 1
  fi

  cd "${ROOT_DIR}" || exit 1
  AIGW_CGO_INCLUDE_FILE="${ROOT_DIR}/include/aigw.h"
  AIGW_CGO_FILE="${ROOT_DIR}/src/libaigw.go"
  AIGW_CGO_OUTPUT_LIB="${ROOT_DIR}/output/aigw/libaigw.so"

  mkdir -p "${AIGW_OUTPUT_DIR}"
  go build -buildmode=c-shared --ldflags '-extldflags "-Wl,-z,now"' -o "$AIGW_CGO_OUTPUT_LIB" "$AIGW_CGO_FILE"

  AIGW_OUTPUT_DIR="${ROOT_DIR}/output/aigw"
  if [ ! -d "${AIGW_OUTPUT_DIR}" ];then
    echo "${AIGW_OUTPUT_DIR} not found!"
    exit 1
  fi
  cd "${AIGW_OUTPUT_DIR}" || exit 1
  rm -f libaigw.h
  cp "${AIGW_CGO_INCLUDE_FILE}" "${AIGW_OUTPUT_DIR}"

  if [ -f "libaigw.so" ] && [ -f "aigw.h" ]; then
    echo "Compilation libaigw.so successful!"
    echo "Generated files:"
    echo " - libaigw.so (shared library)"

    # Display basic information
    echo -e "Library file information:"
    file "libaigw.so"
  else
    echo "Compilation failed!"
    exit 1
  fi
  echo "finished to build AIGW libaigw.so"
}