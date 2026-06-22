#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# executing UT for AIGW
set -e

function run_at() {
  echo ""
  echo "running AT of AIGW"
  LOG_DIR="/var/log/aigw"
  if [ ! -d "$LOG_DIR" ];then
    mkdir -p "$LOG_DIR"
  fi

  cd "${ROOT_DIR}"
  mkdir -p "/etc/aigw/at/"
  cp -f "${ROOT_DIR}/test/at/aigw.json"  "/etc/aigw/at"
  cp -rf "${ROOT_DIR}/test/tokenizer"  "/etc/aigw/at"

  pkill -9 "aigw" 2>/dev/null || true
  sleep 1

  ./output/aigw/aigw --config=/etc/aigw/at/aigw.json &

  echo "waiting for aigw to start..."
  local waited=0
  while [ $waited -lt 30 ]; do
    if curl -s http://127.0.0.1:8888/aigw/v1/health > /dev/null 2>&1; then
      echo "aigw is ready"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [ $waited -ge 30 ]; then
    echo "[ERROR] aigw failed to start within 30s"
    pkill -9 "aigw" 2>/dev/null || true
    return 1
  fi

  python "${ROOT_DIR}/test/at/case1.py"
  local rc=$?

  echo "finished to run AT of AIGW"
  pkill -9 "aigw" 2>/dev/null || true
  return $rc
}
