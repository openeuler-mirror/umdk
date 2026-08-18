#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
#
# 构建 DT 运行环境：liburma + urma-udma provider（按 build.md）+ liburma_sim.so，
# 并把 provider 安装到 sim 重定向目录（/usr/lib64/urma）。
# 构建完成后，直接 `bash test/urma/dt/scripts/run_dt_one.sh <case>` 即可运行，无需设置环境变量。
#
# 用法：
#   bash test/urma/dt/scripts/build_dt_env.sh          # 增量构建（已存在则跳过）
#   bash test/urma/dt/scripts/build_dt_env.sh --rebuild  # 强制重新构建
#
# 环境变量（均可覆盖默认值）：
#   URMA_DT_CMAKE_ARGS     传给 liburma cmake 的额外参数
#   URMA_DT_INSTALL_DIR     provider 安装目录。默认 /usr/lib64/urma（sim 的重定向目标）

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
UMDK_ROOT=$(cd "$DT_ROOT/../../.." && pwd)

SRC_DIR=$UMDK_ROOT/src
SRC_BUILD=${URMA_DT_SRC_BUILD:-$UMDK_ROOT/build/dt/src_noasan}
SIMULATOR_DIR=$DT_ROOT/simulator
SIM_BUILD=${SIM_BUILD:-$UMDK_ROOT/build/dt/simulator}
INSTALL_DIR=${URMA_DT_INSTALL_DIR:-/usr/lib64/urma}

REBUILD=0
if [ "${1:-}" = "--rebuild" ]; then
    REBUILD=1
fi

nproc_cores=$(nproc)

echo "[DT] repo root: $UMDK_ROOT"
echo "[DT] src build: $SRC_BUILD"
echo "[DT] sim build: $SIM_BUILD"
echo "[DT] provider install dir: $INSTALL_DIR"

# ========== 步骤 1/3：liburma + urma-udma provider（按 jd/build.md） ==========
if [ ! -f "$SRC_BUILD/urma/lib/urma/core/liburma.so" ] || \
   [ ! -f "$SRC_BUILD/urma/hw/udma/liburma-udma.so" ] || \
   [ "$REBUILD" = "1" ] || \
   [ -n "$(find "$SRC_DIR" -type f -newer "$SRC_BUILD/urma/hw/udma/liburma-udma.so" -print -quit 2>/dev/null)" ]; then
    echo "[DT] [1/3] build liburma + urma-udma provider ..."
    mkdir -p "$SRC_BUILD"
    (cd "$SRC_BUILD" && \
     cmake "$SRC_DIR" -DBUILD_URMA=enable -DBUILD_ALL=disable -DBUILD_UDMA=enable \
           ${URMA_DT_CMAKE_ARGS:-} && \
     cmake --build . -j"$nproc_cores")
else
    echo "[DT] [1/3] liburma build exists, skip (--rebuild to force)"
fi

if [ ! -f "$SRC_BUILD/urma/lib/urma/core/liburma.so" ]; then
    echo "[DT] missing liburma.so, build failed?" >&2
    exit 1
fi
if [ ! -f "$SRC_BUILD/urma/hw/udma/liburma-udma.so" ]; then
    echo "[DT] missing liburma-udma.so, udma provider build failed?" >&2
    exit 1
fi

# ========== 步骤 2/3：liburma_sim.so（DT 所属仓库的 simulator 源码） ==========
if [ ! -d "$SIMULATOR_DIR" ]; then
    echo "[DT] simulator source missing at $SIMULATOR_DIR" >&2
    exit 1
fi
# 源清单完整校验（仿真器按 PR A..H 顺序合入；缺文件时明确报错而非
# CMake 期 "Cannot find source file"）
for _f in urma_sim_intercept.c urma_sim_cmd.c urma_sim_config.c urma_sim_res.c \
          urma_sim_exec.c urma_sim_ummu.c urma_sim_ipc.c \
          urma_sim_intercept.h urma_sim_res.h urma_sim_exec.h \
          urma_sim.version urma_sim_config.json; do
    if [ ! -f "$SIMULATOR_DIR/$_f" ]; then
        echo "[DT] simulator file missing: $SIMULATOR_DIR/$_f (需先合入前置 PR)" >&2
        exit 1
    fi
done
if [ ! -f "$SIM_BUILD/liburma_sim.so" ] || [ "$REBUILD" = "1" ] || \
   [ "$SIM_BUILD/liburma_sim.so" -ot "$SRC_BUILD/urma/hw/udma/liburma-udma.so" ] || \
   [ "$SIM_BUILD/liburma_sim.so" -ot "$SRC_BUILD/urma/lib/urma/core/liburma.so" ] || \
   [ "$SIM_BUILD/liburma_sim.so" -ot "$SRC_BUILD/urma/common/liburma_common.so" ] || \
   [ -n "$(find "$SIMULATOR_DIR" -maxdepth 1 -type f -newer "$SIM_BUILD/liburma_sim.so" -print -quit 2>/dev/null)" ]; then
    echo "[DT] [2/3] build liburma_sim.so ..."
    mkdir -p "$SIM_BUILD"
    (cd "$SIM_BUILD" && \
     cmake -DURMA_SRC_DIR="$SRC_DIR/urma" -DURMA_BUILD_DIR="$SRC_BUILD" \
           ${URMA_DT_CMAKE_ARGS:-} "$SIMULATOR_DIR" && \
     cmake --build . -j"$nproc_cores")
else
    echo "[DT] [2/3] liburma_sim.so exists, skip (--rebuild to force)"
fi

# ========== 步骤 3/3：安装 provider 到 sim 重定向目录 ==========
echo "[DT] [3/3] install provider to $INSTALL_DIR ..."
if [ ! -d "$INSTALL_DIR" ] && ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    echo "[DT] cannot create $INSTALL_DIR, need root or set URMA_DT_INSTALL_DIR" >&2
    exit 1
fi
if ! cp "$SRC_BUILD/urma/hw/udma/liburma-udma.so" "$INSTALL_DIR/liburma-udma.so" 2>/dev/null; then
    echo "[DT] cannot write $INSTALL_DIR, need root or set URMA_DT_INSTALL_DIR" >&2
    exit 1
fi

echo
echo "[DT] build env done:"
echo "    liburma:        $SRC_BUILD/urma/lib/urma/core"
echo "    urma_common:    $SRC_BUILD/urma/common"
echo "    provider:       $INSTALL_DIR/liburma-udma.so"
echo "    sim:            $SIM_BUILD/liburma_sim.so"
echo "    sim config:     $SIMULATOR_DIR/urma_sim_config.json"
echo "    run:            bash $SCRIPT_DIR/run_dt_one.sh <case_name>"
