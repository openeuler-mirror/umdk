#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
#

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.."; pwd)
TEST_BUILD_DIR="$REPO_ROOT/test/urma/build"
REPORTS_DIR="$REPO_ROOT/test/urma/reports/libfuzzer"
FUZZ_BIN_DIR="$TEST_BUILD_DIR/fuzz/libfuzzer"

function usage()
{
    cat <<EOF
Usage: $0 [--runs N]
EOF
}

RUNS=256
while [ $# -gt 0 ]; do
    case "$1" in
        --runs)
            if [ $# -lt 2 ]; then
                echo "ERROR: --runs requires a value" >&2
                exit 1
            fi
            RUNS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

function make_corpus()
{
    local dir="$1"
    local count="$2"
    local i

    rm -rf "$dir"
    mkdir -p "$dir"
    for ((i = 0; i < count; ++i)); do
        printf '%s\n' "$i" > "$dir/case_$i"
    done
}

cd "$REPO_ROOT"
mkdir -p "$REPORTS_DIR"
cmake --build "$TEST_BUILD_DIR" --target urma_libfuzzer -j

make_corpus "$REPORTS_DIR/urma_api_corpus" 128
make_corpus "$REPORTS_DIR/uvs_api_corpus" 12

LIBASAN=$(gcc -print-file-name=libasan.so 2>/dev/null || true)
if [ -f "$LIBASAN" ]; then
    export LD_PRELOAD="$LIBASAN${LD_PRELOAD:+:$LD_PRELOAD}"
fi

"$FUZZ_BIN_DIR/urma_api_libfuzzer" "$REPORTS_DIR/urma_api_corpus" -runs="$RUNS" -max_len=16 \
    > "$REPORTS_DIR/urma_api_libfuzzer.log" 2>&1
"$FUZZ_BIN_DIR/uvs_api_libfuzzer" "$REPORTS_DIR/uvs_api_corpus" -runs="$RUNS" -max_len=16 \
    > "$REPORTS_DIR/uvs_api_libfuzzer.log" 2>&1
