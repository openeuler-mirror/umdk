#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set -e

# build go
function build_go_project () {
  echo "building AIGW go components"
  if [ ! -d "${ROOT_DIR}" ];then
    echo "${ROOT_DIR} not found!"
    exit 1
  fi

  cd "${ROOT_DIR}" || exit 1
  go mod tidy

  AIGW_DIR="${ROOT_DIR}/cmd/aigw"
  AIGW_OUTPUT_DIR="${ROOT_DIR}/output/aigw"
  mkdir -p ${AIGW_OUTPUT_DIR}

  cd ${AIGW_DIR} || exit 1
  go build -buildmode=pie -ldflags '-linkmode=external -buildid=IdAIGW -tmpdir=/tmp -extldflags "-Wl,-z,now"' \
     -o ${AIGW_OUTPUT_DIR}/aigw
  ret=$?
  if [ $ret -ne 0 ];then
    echo "Building AIGW failed with err ${ret}."
    exit 1
  fi

  if [ "${WITH_TSAN}" == "ON" ]; then
      go build -race -ldflags '-linkmode=external -buildid=IdAIGW -tmpdir=/tmp -extldflags "-Wl,-z,now"' \
         -o ${AIGW_OUTPUT_DIR}/aigw-tsan
      ret=$?
      if [ $ret -ne 0 ];then
        echo "Building AIGW-tsan failed with err ${ret}."
        exit 1
      fi
  fi

  if [[ "${WITH_UT}" == "OFF" && "${WITH_COVERAGE}" == "ON" ]];then
      go build -cover -covermode=atomic -ldflags '-linkmode=external -buildid=IdAIGW -tmpdir=/tmp -extldflags "-Wl,-z,now"' \
         -o ${AIGW_OUTPUT_DIR}/aigw-coverage
      ret=$?
      if [ $ret -ne 0 ];then
        echo "Building AIGW-coverage failed with err ${ret}."
        exit 1
      fi
  fi

  echo "finished to build AIGW go component"
}