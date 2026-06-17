#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
#
set -e

SCRIPT_PATH=$(cd "$(dirname "$0")"; pwd)
SRC_PATH=$(cd "$SCRIPT_PATH/../../../src"; pwd)
TEST_PATH=$(cd "$SCRIPT_PATH/.."; pwd)
SRC_BUILD_PATH="$SRC_PATH/build"
REPORTS_PATH="$TEST_PATH/reports"
DEPENDENCIES_PATH="$TEST_PATH/dependencies"

function summarize_phase_coverage()
{
    local phase_info="$1"
    local phase_name="$2"

    echo "===== ${phase_name} coverage summary ====="
    if ! lcov --summary "$phase_info" --branch-coverage --ignore-errors empty; then
        echo "WARN: ${phase_name} has no coverage data, skip phase summary"
    fi
}

function extract_phase_coverage()
{
    local phase_name="$1"
    local phase_info="$REPORTS_PATH/${phase_name}.info"

    shift
    # Phase reports are observation data for follow-up UT work. They must not block a
    # passing GTest run while a module has no captured coverage yet.
    if ! lcov --extract "$REPORTS_PATH/filtered.info" "$@" \
        --output-file "$phase_info" --branch-coverage --ignore-errors unused,unused,empty; then
        echo "WARN: ${phase_name} has no coverage data, skip phase summary"
        return 0
    fi

    summarize_phase_coverage "$phase_info" "$phase_name"
}

function generate_phase_reports()
{
    extract_phase_coverage phase_common \
        '*/src/urma/common/*' \
        '*/urma/common/*'

    extract_phase_coverage phase_urma_core \
        '*/src/urma/lib/urma/core/*' \
        '*/urma/lib/urma/core/*'

    extract_phase_coverage phase_urma_bond \
        '*/src/urma/lib/urma/bond/*' \
        '*/urma/lib/urma/bond/*'

    extract_phase_coverage phase_uvs \
        '*/src/urma/lib/uvs/*' \
        '*/urma/lib/uvs/*'
}

function check_added_line_coverage()
{
    python3 "$SCRIPT_PATH/check_diff_coverage.py" \
        --coverage "$REPORTS_PATH/filtered.info" \
        --threshold 90
}

function start_test()
{
    echo "$SCRIPT_PATH"
    mkdir -p "$SRC_BUILD_PATH"
    cd "$SRC_BUILD_PATH"
    cmake .. -DBUILD_ALL=disable -DBUILD_URMA=enable -DBUILD_UDMA=disable \
        -DGTEST=enable -DCODE_COVERAGE=enable -DASAN=enable
    make -j

    if [ -d "$REPORTS_PATH" ]; then
        rm -r "$REPORTS_PATH"
    fi
    mkdir -p "$REPORTS_PATH"

    if [ -d "$DEPENDENCIES_PATH" ]; then
        rm -r "$DEPENDENCIES_PATH"
    fi
    mkdir -p "$DEPENDENCIES_PATH"
    find . -name '*.so*' -exec cp {} "$DEPENDENCIES_PATH" \;

    cd "$TEST_PATH"
    mkdir -p build
    cd build
    cmake .. -D URMA_SRC_DIR="$SRC_PATH/urma" -D URMA_BUILD_DIR="$SRC_BUILD_PATH"
    make -j
    export LD_LIBRARY_PATH="$DEPENDENCIES_PATH:${LD_LIBRARY_PATH:-}"
    ctest --output-on-failure --output-junit "$REPORTS_PATH/report.xml"

    if command -v lcov >/dev/null 2>&1 && command -v genhtml >/dev/null 2>&1; then
        cd "$SRC_BUILD_PATH"
        lcov --capture --directory . --output-file "$REPORTS_PATH/coverage.info" --branch-coverage
        lcov --remove "$REPORTS_PATH/coverage.info" '*c++/*' '*test/urma/*' '*gtest/*' '*mockcpp/*' \
            --output-file "$REPORTS_PATH/filtered.info" --branch-coverage --ignore-errors unused,unused
        check_added_line_coverage
        generate_phase_reports
        genhtml "$REPORTS_PATH/filtered.info" --output-directory "$REPORTS_PATH/lcov_report" \
            --branch-coverage
    else
        echo "WARN: lcov/genhtml not found, skip coverage html report"
    fi

    echo -e "\033[32mSUCCESS\033[0m"
    date

    exit 0
}

start_test
