#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
#

set -e

if [ -z "${SCRIPT_PATH:-}" ]; then
    SCRIPT_PATH=$(dirname "${BASH_SOURCE[0]}")
    SCRIPT_PATH=$(cd "$SCRIPT_PATH" && pwd)
fi
SRC_PATH=$(cd "$SCRIPT_PATH/../../../src"; pwd)
TEST_PATH=$(cd "$SCRIPT_PATH/.."; pwd)
SRC_BUILD_PATH="$SRC_PATH/build"
TEST_BUILD_PATH="$TEST_PATH/build"
REPORTS_PATH="$TEST_PATH/reports"
DEPENDENCIES_PATH="$TEST_PATH/dependencies"

URMA_UT_ENABLE_COVERAGE=1
URMA_UT_PHASE="all"

# The top-level runner owns phase selection. Per-phase wrapper scripts call a
# narrower parser so that an accidental "--phase" does not silently run another
# target than the script name suggests.
function urma_ut_usage()
{
    cat <<EOF
Usage: $0 [--phase common|core|cmd_tlv|bond|uvs|all] [--no-coverage]
EOF
}

function parse_urma_ut_args()
{
    while [ $# -gt 0 ]; do
        case "$1" in
            --phase)
                if [ $# -lt 2 ]; then
                    echo "ERROR: --phase requires an argument" >&2
                    return 1
                fi
                URMA_UT_PHASE="$2"
                shift 2
                ;;
            --no-coverage)
                URMA_UT_ENABLE_COVERAGE=0
                shift
                ;;
            -h|--help)
                urma_ut_usage
                exit 0
                ;;
            *)
                echo "ERROR: unknown option: $1" >&2
                urma_ut_usage >&2
                return 1
                ;;
        esac
    done
}

function parse_urma_phase_script_args()
{
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-coverage)
                URMA_UT_ENABLE_COVERAGE=0
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--no-coverage]"
                exit 0
                ;;
            *)
                echo "ERROR: unknown option for phase script: $1" >&2
                echo "Usage: $0 [--no-coverage]" >&2
                return 1
                ;;
        esac
    done
}

function validate_urma_ut_phase()
{
    case "$1" in
        all|common|core|cmd_tlv|bond|uvs)
            return 0
            ;;
        *)
            echo "ERROR: invalid phase: $1" >&2
            return 1
            ;;
    esac
}

function phase_target()
{
    case "$1" in
        common) echo "urma_common_ut" ;;
        core) echo "urma_core_ut" ;;
        cmd_tlv) echo "urma_cmd_tlv_ut" ;;
        bond) echo "urma_bond_ut" ;;
        uvs) echo "urma_uvs_ut" ;;
        *) return 1 ;;
    esac
}

function phase_label()
{
    case "$1" in
        common) echo "phase_common" ;;
        core) echo "phase_core" ;;
        cmd_tlv) echo "phase_cmd_tlv" ;;
        bond) echo "phase_bond" ;;
        uvs) echo "phase_uvs" ;;
        *) return 1 ;;
    esac
}

function prepare_urma_source_build()
{
    echo "$SCRIPT_PATH"
    mkdir -p "$SRC_BUILD_PATH"
    cd "$SRC_BUILD_PATH"
    cmake .. -DBUILD_ALL=disable -DBUILD_URMA=enable -DBUILD_UDMA=disable \
        -DGTEST=enable -DCODE_COVERAGE=enable -DASAN=enable
    cmake --build . -j
}

function prepare_urma_reports()
{
    if [ -d "$REPORTS_PATH" ]; then
        rm -r "$REPORTS_PATH"
    fi
    mkdir -p "$REPORTS_PATH"
}

function prepare_urma_dependencies()
{
    if [ -d "$DEPENDENCIES_PATH" ]; then
        rm -r "$DEPENDENCIES_PATH"
    fi
    mkdir -p "$DEPENDENCIES_PATH"
    # Tests link against freshly built local URMA artifacts only. Do not depend
    # on installed provider libraries under /lib64 or on a real device setup.
    find "$SRC_BUILD_PATH" -name '*.so*' -exec cp {} "$DEPENDENCIES_PATH" \;
}

function configure_urma_test_build()
{
    mkdir -p "$TEST_BUILD_PATH"
    cd "$TEST_BUILD_PATH"
    cmake .. -D URMA_SRC_DIR="$SRC_PATH/urma" -D URMA_BUILD_DIR="$SRC_BUILD_PATH"
}

function clean_urma_coverage_data()
{
    find "$SRC_BUILD_PATH" "$TEST_BUILD_PATH" -name '*.gcda' -delete 2>/dev/null || true
}

function build_urma_test_target()
{
    local target="$1"

    cd "$TEST_BUILD_PATH"
    cmake --build . --target "$target" -j
}

function build_all_urma_test_targets()
{
    cd "$TEST_BUILD_PATH"
    cmake --build . -j
}

function run_urma_ctest()
{
    local phase="$1"
    local label
    local junit_report

    cd "$TEST_BUILD_PATH"
    export LD_LIBRARY_PATH="$DEPENDENCIES_PATH:${LD_LIBRARY_PATH:-}"
    if [ "$phase" = "all" ]; then
        ctest --output-on-failure --output-junit "$REPORTS_PATH/report.xml"
        return
    fi

    label=$(phase_label "$phase")
    junit_report="$REPORTS_PATH/report_${phase}.xml"
    ctest -L "$label" --output-on-failure --output-junit "$junit_report"
}

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
    # Phase reports are observation data for follow-up UT work. They must not
    # block a passing GTest run while a module has no captured coverage yet.
    if ! lcov --extract "$REPORTS_PATH/filtered.info" "$@" \
        --output-file "$phase_info" --branch-coverage --ignore-errors unused,unused,empty; then
        echo "WARN: ${phase_name} has no coverage data, skip phase summary"
        return 0
    fi

    summarize_phase_coverage "$phase_info" "$phase_name"
}

function generate_common_phase_report()
{
    extract_phase_coverage phase_common \
        '*/src/urma/common/*' \
        '*/urma/common/*'
}

function generate_core_phase_report()
{
    extract_phase_coverage phase_urma_core \
        '*/src/urma/lib/urma/core/*' \
        '*/urma/lib/urma/core/*'
}

function generate_cmd_tlv_phase_report()
{
    extract_phase_coverage phase_cmd_tlv \
        '*/src/urma/lib/urma/core/urma_cmd_tlv.c' \
        '*/urma/lib/urma/core/urma_cmd_tlv.c'
}

function generate_bond_phase_report()
{
    extract_phase_coverage phase_urma_bond \
        '*/src/urma/lib/urma/bond/*' \
        '*/urma/lib/urma/bond/*'
}

function generate_uvs_phase_report()
{
    extract_phase_coverage phase_uvs \
        '*/src/urma/lib/uvs/*' \
        '*/urma/lib/uvs/*'
}

function generate_non_udma_phase_report()
{
    extract_phase_coverage phase_urma_non_udma \
        '*/src/urma/common/*' \
        '*/urma/common/*' \
        '*/src/urma/lib/urma/core/*' \
        '*/urma/lib/urma/core/*' \
        '*/src/urma/lib/urma/bond/*' \
        '*/urma/lib/urma/bond/*' \
        '*/src/urma/lib/uvs/*' \
        '*/urma/lib/uvs/*'
}

function generate_all_phase_reports()
{
    generate_common_phase_report
    generate_core_phase_report
    generate_cmd_tlv_phase_report
    generate_bond_phase_report
    generate_uvs_phase_report
    generate_non_udma_phase_report
}

function generate_one_phase_report()
{
    case "$1" in
        common) generate_common_phase_report ;;
        core) generate_core_phase_report ;;
        cmd_tlv) generate_cmd_tlv_phase_report ;;
        bond) generate_bond_phase_report ;;
        uvs) generate_uvs_phase_report ;;
        *) return 1 ;;
    esac
}

function check_added_line_coverage()
{
    python3 "$SCRIPT_PATH/check_diff_coverage.py" \
        --coverage "$REPORTS_PATH/filtered.info" \
        --threshold 90
}

function capture_urma_coverage()
{
    local phase="$1"

    if ! command -v lcov >/dev/null 2>&1 || ! command -v genhtml >/dev/null 2>&1; then
        echo "WARN: lcov/genhtml not found, skip coverage html report"
        return 0
    fi

    cd "$SRC_BUILD_PATH"
    lcov --capture --directory . --output-file "$REPORTS_PATH/coverage.info" --branch-coverage \
        --rc geninfo_unexecuted_blocks=1
    lcov --remove "$REPORTS_PATH/coverage.info" '*c++/*' '*test/urma/*' '*gtest/*' '*mockcpp/*' \
        --output-file "$REPORTS_PATH/filtered.info" --branch-coverage --ignore-errors unused,unused

    if [ "$phase" = "all" ]; then
        check_added_line_coverage
        generate_all_phase_reports
    else
        generate_one_phase_report "$phase"
    fi

    genhtml "$REPORTS_PATH/filtered.info" --output-directory "$REPORTS_PATH/lcov_report" \
        --branch-coverage
}

function run_urma_ut_phase()
{
    local phase="$1"
    local target

    validate_urma_ut_phase "$phase"
    if [ "$phase" = "all" ]; then
        echo "ERROR: run_urma_ut_phase requires a concrete phase" >&2
        return 1
    fi

    target=$(phase_target "$phase")
    prepare_urma_source_build
    prepare_urma_reports
    prepare_urma_dependencies
    configure_urma_test_build
    if [ "$URMA_UT_ENABLE_COVERAGE" -eq 1 ]; then
        clean_urma_coverage_data
    fi
    build_urma_test_target "$target"
    run_urma_ctest "$phase"
    if [ "$URMA_UT_ENABLE_COVERAGE" -eq 1 ]; then
        capture_urma_coverage "$phase"
    fi
    echo -e "\033[32mSUCCESS\033[0m"
    date
}

function run_urma_ut_all()
{
    prepare_urma_source_build
    prepare_urma_reports
    prepare_urma_dependencies
    configure_urma_test_build
    if [ "$URMA_UT_ENABLE_COVERAGE" -eq 1 ]; then
        clean_urma_coverage_data
    fi
    build_all_urma_test_targets
    run_urma_ctest all
    if [ "$URMA_UT_ENABLE_COVERAGE" -eq 1 ]; then
        capture_urma_coverage all
    fi
    echo -e "\033[32mSUCCESS\033[0m"
    date
}
