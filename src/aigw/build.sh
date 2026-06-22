#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set -e

source build/build_options.sh
source build/pull_opensource.sh
source build/build_init.sh
source build/build_go_project.sh
source build/build_open_source.sh
source build/build_rust.sh
source build/run_ut.sh
source build/build_rpm.sh
source build/run_at.sh
source build/build_cgo_lib.sh
source build/build_example.sh

function clean() {
  echo "Cleaning up the build environment..."

  rm -rf output/*

  echo "Cleanup completed."
}

function main() {
  process_options "$@"

  if [[ "${WITH_CLEAN}" == "ON" ]]; then
    clean
    return 0
  fi

  echo "Start to build AIGW."
  init

  pull_opensource
  if [[ "${WITH_RPM}" == "ON" ]];then
    build_rpm
    if [ "$?" != "0" ]; then
      echo "build rpm failed"
      return 1
    fi
    return 0
  fi
  build_open_source
  if [[ "${WITH_TEST_FILE}" == "OFF" ]];then
    find "$ROOT_DIR" -iname  *_test.go -delete
    go mod tidy
  fi
  build_rust_components

  build_go_project
  build_cgo_lib
  build_example
  echo "Building AIGW finished."

  if [ "${WITH_UT}" == "ON" ]; then
    run_ut
  fi
    if [ "${WITH_AT}" == "ON" ]; then
      run_at
    fi
}

main "$@"
