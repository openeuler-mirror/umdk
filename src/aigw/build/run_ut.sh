#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# executing UT for AIGW
set -e

function run_ut() {
  echo ""
  echo "running UT of AIGW"
  LOG_DIR="/var/log/aigw"
  if [ ! -d "$LOG_DIR" ];then
    mkdir -p "$LOG_DIR"
  fi

  cd "${ROOT_DIR}"

  if [[ "${WITH_COVERAGE}" == "ON" ]];then
    go test -gcflags="all=-N -l" -coverprofile="${ROOT_DIR}/output/coverage.out" -covermode=atomic ./...
    go tool cover -html="${ROOT_DIR}/output/coverage.out" -o="${ROOT_DIR}/output/coverage.html"
  else
    go test -gcflags="all=-N -l" ./...
  fi


  echo "finished to run UT of AIGW"
}
