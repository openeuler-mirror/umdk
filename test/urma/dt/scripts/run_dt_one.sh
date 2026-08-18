#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
#
# Build and run one generated DT case under the URMA simulator.
#
# Usage:
#   bash test/urma/dt/scripts/run_dt_one.sh <case_name> [generated_cpp] [extra_runtime_env]
#   bash test/urma/dt/scripts/run_dt_one.sh test_read

set -euo pipefail

usage()
{
    cat <<EOF
Usage:
  bash test/urma/dt/scripts/run_dt_one.sh <case_name> [generated_cpp] [extra_runtime_env]

Examples:
  bash test/urma/dt/scripts/run_dt_one.sh test_read
  bash test/urma/dt/scripts/run_dt_one.sh test_rnr test/urma/dt/cases/test_rnr.cpp URMA_SIM_INJECT_STATUS=4

Before running, build the DT environment once:
  bash test/urma/dt/scripts/build_dt_env.sh
Then run cases with no extra environment variables.

Environment:
  URMA_DT_SIM_MODE       Run mode. Only hw supported (real provider + sim). Default: hw
  URMA_DT_BUILD_ROOT     Build output root. Default: <repo>/build/dt
  URMA_DT_SRC_BUILD      liburma build dir (build_dt_env.sh 产物). Default: build/dt/src_noasan
  URMA_DT_SAVE_LOGS      Save logs to files when set to 1. Default: 0
  URMA_DT_LOG_DIR        Log directory. Usually exported by run_dt.sh
  URMA_DT_PRINT_LOGS     Print case stdout when set to 1. Default: 1
  URMA_DT_LOG_TAIL_LINES Printed stdout tail lines. 0 means full stdout. Default: 0
  URMA_DT_TIMEOUT        Per-case timeout in seconds. Default: 30
  URMA_DT_WORK_ROOT      Per-case work root. Default: /tmp/umdk_dt_work
  URMA_DT_FIXTURE_DIR    Fixture directory. Default: <dt_root>/fixture
  URMA_DT_SIMULATOR_DIR  Simulator source directory. Default: <dt_root>/simulator
  GTEST_DIR              Optional googletest root with googletest/include and build/lib
  GTEST_INC              Optional gtest include directory
  GTEST_LIB              Optional gtest library directory
  UA_CORE                liburma.so directory. Default: <src_build>/urma/lib/urma/core
  UA_COMMON              liburma_common.so directory. Default: <src_build>/urma/common
  SIM_BUILD              Simulator build directory (build_dt_env.sh 产物). Default: build/dt/simulator
  SIM_SO                 Simulator shared library. Default: <sim_build>/liburma_sim.so
  SIM_CFG                Simulator config json. Default: <simulator_dir>/urma_sim_config.json
EOF
}

if [ $# -gt 0 ]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
fi

if [ $# -lt 1 ]; then
    usage >&2
    exit 2
fi

CASE_NAME=$1
CASE_CPP=${2:-}
EXTRA_RUNTIME_ENV=${3:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
UMDK_ROOT=$(cd "$DT_ROOT/../../.." && pwd)

BUILD_ROOT=${URMA_DT_BUILD_ROOT:-$UMDK_ROOT/build/dt}
SRC_BUILD=${URMA_DT_SRC_BUILD:-$BUILD_ROOT/src_noasan}
UA_CORE=${UA_CORE:-$SRC_BUILD/urma/lib/urma/core}
UA_COMMON=${UA_COMMON:-$SRC_BUILD/urma/common}
URMA_INC=${URMA_INC:-$UMDK_ROOT/src/urma/lib/urma/core/include}
URMA_COMMON_INC=${URMA_COMMON_INC:-$UMDK_ROOT/src/urma/common/include}
SIMULATOR_DIR=${URMA_DT_SIMULATOR_DIR:-$DT_ROOT/simulator}
SIM_BUILD=${SIM_BUILD:-$BUILD_ROOT/simulator}
SIM_SO=${SIM_SO:-$SIM_BUILD/liburma_sim.so}
SIM_CFG=${SIM_CFG:-$SIMULATOR_DIR/urma_sim_config.json}
FIXTURE_DIR=${URMA_DT_FIXTURE_DIR:-$DT_ROOT/fixture}

if [ -z "$CASE_CPP" ]; then
    CASE_CPP="$DT_ROOT/cases/${CASE_NAME}.cpp"
fi

BIN_DIR=$BUILD_ROOT/bin
LOG_DIR=${URMA_DT_LOG_DIR:-$BUILD_ROOT/logs}
WORK_PARENT=${URMA_DT_WORK_ROOT:-/tmp/umdk_dt_work}
TIMEOUT_SEC=${URMA_DT_TIMEOUT:-30}
SIM_MODE=${URMA_DT_SIM_MODE:-hw}
LOG_TAIL_LINES=${URMA_DT_LOG_TAIL_LINES:-0}
PRINT_LOGS=${URMA_DT_PRINT_LOGS:-1}
SAVE_LOGS=${URMA_DT_SAVE_LOGS:-0}

# 仅支持 hw 模式：真 udma provider 跑真代码，sim 拦截其与内核的交互（方式 1）。
# provider 模式（sim 当 provider，方式 3）已废弃——post_recv/SEND/wait 语义不完整。
if [ "$SIM_MODE" != "hw" ]; then
    echo "unknown URMA_DT_SIM_MODE=$SIM_MODE, only hw is supported" >&2
    exit 2
fi
SIM_HW=1

mkdir -p "$BIN_DIR" "$LOG_DIR" "$WORK_PARENT"

if [[ "$CASE_CPP" != /* ]]; then
    CASE_CPP="$UMDK_ROOT/$CASE_CPP"
fi

check_file()
{
    if [ ! -f "$1" ]; then
        echo "[DT] missing $2: $1"
        exit 1
    fi
}

check_file "$CASE_CPP" "case source"
check_file "$FIXTURE_DIR/dt_fixture.cpp" "fixture source"
check_file "$SIM_SO" "simulator library (run build_dt_env.sh first)"
check_file "$SIM_CFG" "simulator config"


EXE=$BIN_DIR/${CASE_NAME}_run
COMPILE_LOG=$LOG_DIR/${CASE_NAME}.compile.log
STDOUT_LOG=$LOG_DIR/${CASE_NAME}.stdout
STDERR_LOG=$LOG_DIR/${CASE_NAME}.stderr
XML_LOG=$LOG_DIR/${CASE_NAME}.xml
STATUS_LOG=$LOG_DIR/${CASE_NAME}.status
WORKDIR_LOG=$LOG_DIR/${CASE_NAME}.workdir

rm -f "$EXE" "$COMPILE_LOG" "$STDOUT_LOG" "$STDERR_LOG" "$XML_LOG" "$STATUS_LOG" "$WORKDIR_LOG"

dump_log_tail()
{
    local title=$1
    local path=$2

    if [ ! -s "$path" ]; then
        return
    fi

    echo "[DT] ---- $title: $path ----"
    if [ "$LOG_TAIL_LINES" = "0" ]; then
        cat "$path"
    else
        tail -n "$LOG_TAIL_LINES" "$path"
    fi
}

dump_case_logs()
{
    if [ "$PRINT_LOGS" != "1" ]; then
        return
    fi

    dump_log_tail "stdout" "$STDOUT_LOG"
}

cleanup_case_logs()
{
    if [ "$SAVE_LOGS" = "1" ]; then
        return
    fi

    rm -f "$COMPILE_LOG" "$STDOUT_LOG" "$STDERR_LOG" "$XML_LOG" "$STATUS_LOG" "$WORKDIR_LOG"
}

detect_gtest()
{
    if [ -n "${GTEST_INC:-}" ] && [ -n "${GTEST_LIB:-}" ]; then
        return 0
    fi

    if [ -n "${GTEST_DIR:-}" ]; then
        if [ -d "$GTEST_DIR/googletest/include" ]; then
            GTEST_INC=${GTEST_INC:-$GTEST_DIR/googletest/include}
        else
            GTEST_INC=${GTEST_INC:-$GTEST_DIR/include}
        fi
        GTEST_LIB=${GTEST_LIB:-$GTEST_DIR/build/lib}
    elif [ -f /usr/local/include/gtest/gtest.h ]; then
        GTEST_INC=${GTEST_INC:-/usr/local/include}
        GTEST_LIB=${GTEST_LIB:-/usr/local/lib64}
    elif [ -f /usr/include/gtest/gtest.h ]; then
        GTEST_INC=${GTEST_INC:-/usr/include}
        if [ -f /usr/lib64/libgtest.a ] || [ -f /usr/lib64/libgtest.so ]; then
            GTEST_LIB=${GTEST_LIB:-/usr/lib64}
        else
            GTEST_LIB=${GTEST_LIB:-/usr/lib}
        fi
    else
        echo "[DT] gtest headers not found; set GTEST_DIR, GTEST_INC and GTEST_LIB"
        return 1
    fi

    if [ ! -f "$GTEST_LIB/libgtest.a" ] && [ ! -f "$GTEST_LIB/libgtest.so" ]; then
        echo "[DT] gtest library not found in $GTEST_LIB"
        return 1
    fi

    return 0
}

if ! detect_gtest; then
    exit 1
fi

echo "[DT] compile $CASE_NAME"
if ! env -u LD_PRELOAD -u URMA_SIM_CONFIG -u URMA_SIM_HW -u URMA_SIM_WORKDIR -u URMA_SIM_IPC_DIR \
    g++ -std=c++17 -fpermissive -Wno-error \
        -I"$GTEST_INC" -I"$FIXTURE_DIR" -I"$URMA_INC" -I"$URMA_COMMON_INC" \
        "$FIXTURE_DIR/dt_fixture.cpp" "$CASE_CPP" \
        -L"$SIM_BUILD" -lurma_sim \
        -L"$UA_CORE" -lurma -L"$UA_COMMON" -lurma_common \
        -Wl,-rpath,"$SIM_BUILD" -Wl,-rpath,"$UA_CORE" -Wl,-rpath,"$UA_COMMON" \
        -L"$GTEST_LIB" -lgtest_main -lgtest -lpthread \
        -o "$EXE" >"$COMPILE_LOG" 2>&1; then
    echo "COMPILE_FAIL" > "$STATUS_LOG"
    echo "[DT] $CASE_NAME COMPILE_FAIL, see $COMPILE_LOG"
    dump_log_tail "compile log" "$COMPILE_LOG"
    cleanup_case_logs
    exit 1
fi

RUN_ROOT=$(mktemp -d "$WORK_PARENT/${CASE_NAME}.XXXXXX")
mkdir -p "$RUN_ROOT/ipc"

if [ -n "$EXTRA_RUNTIME_ENV" ]; then
    read -r -a EXTRA_ENV_ARRAY <<< "$EXTRA_RUNTIME_ENV"
else
    EXTRA_ENV_ARRAY=()
fi
for extra_env in "${EXTRA_ENV_ARRAY[@]}"; do
    if [[ "$extra_env" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
        continue
    fi
    echo "[DT] invalid EXTRA_RUNTIME_ENV item, expected NAME=VALUE: $extra_env"
    echo "PARAM_ERR" > "$STATUS_LOG"
    cleanup_case_logs
    exit 1
done

echo "[DT] run $CASE_NAME mode=$SIM_MODE sim_hw=$SIM_HW provider=${URMA_DT_REAL_PROVIDER:-}"
RC=0
env \
    LD_LIBRARY_PATH="$UA_CORE:$UA_COMMON:${LD_LIBRARY_PATH:-}" \
    LD_PRELOAD="$SIM_SO" \
    URMA_SIM_CONFIG="$SIM_CFG" \
    URMA_SIM_HW="$SIM_HW" \
    URMA_SIM_WORKDIR="$RUN_ROOT" \
    URMA_SIM_IPC_DIR="$RUN_ROOT/ipc" \
    URMA_DT_INSTALL_DIR="${URMA_DT_INSTALL_DIR:-/usr/lib64/urma}" \
    "${EXTRA_ENV_ARRAY[@]}" \
    timeout "$TIMEOUT_SEC" "$EXE" --gtest_output=xml:"$XML_LOG" \
    >"$STDOUT_LOG" 2>"$STDERR_LOG" || RC=$?

if [ $RC -eq 0 ]; then
    if grep -qE "\\[dt_setup\\].*(num_devs=0|dev idx|fail)" "$STDERR_LOG"; then
        echo "INFRA_FAIL" > "$STATUS_LOG"
        echo "[DT] $CASE_NAME INFRA_FAIL, dt_setup did not reach a usable device, workdir: $RUN_ROOT"
        dump_case_logs
        echo "$RUN_ROOT" > "$WORKDIR_LOG"
        cleanup_case_logs
        exit 1
    fi
    echo "PASS" > "$STATUS_LOG"
    if [ "${KEEP_DT_WORKDIR:-0}" != "1" ]; then
        rm -rf "$RUN_ROOT"
    else
        echo "$RUN_ROOT" > "$WORKDIR_LOG"
    fi
    dump_case_logs
    echo "[DT] $CASE_NAME PASS"
    cleanup_case_logs
    exit 0
fi

if [ $RC -eq 124 ]; then
    echo "TIMEOUT" > "$STATUS_LOG"
    echo "[DT] $CASE_NAME TIMEOUT, workdir: $RUN_ROOT"
else
    echo "FAIL" > "$STATUS_LOG"
    echo "[DT] $CASE_NAME FAIL rc=$RC, workdir: $RUN_ROOT"
fi
dump_case_logs
echo "$RUN_ROOT" > "$WORKDIR_LOG"
cleanup_case_logs
exit $RC
