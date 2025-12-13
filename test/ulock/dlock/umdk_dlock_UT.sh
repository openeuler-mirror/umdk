#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

set -euo pipefail
set -e
SCRIPT_PATH=$(cd $(dirname $0);pwd)

SERVER_IP_ADDR=""
EID=""
LOG_LEVEL=4 # LOG_WARNING

OPTIONS=":i:e:g:"

while getopts $OPTIONS opt; do
    case $opt in
        i)
            SERVER_IP_ADDR=$OPTARG
            ;;
        e)
            EID=$OPTARG
            ;;
        g)
            LOG_LEVEL=$OPTARG
            ;;
        :)
            echo "ERROR: option $OPTARG requires a parameter." >&2
            exit 1
            ;;
        \?)
            echo "ERROR: invalid option $OPTARG" >&2
            exit 1
            ;;
    esac
done

# server_ip and eid are required parameters
if [ -z "$SERVER_IP_ADDR" ] || [ -z "$EID" ]; then
    echo "Usage: sh umdk_dlock_UT.sh -i <server_ip> -e <eid> [-g <log_level>]"
    exit 1
fi

echo "Configuration:"
echo "server_ip: $SERVER_IP_ADDR"
echo "eid:       $EID"
echo "log_level: $LOG_LEVEL"

# compile DLock code
cd $SCRIPT_PATH/../../../src
if [ -d ./build ]; then
    rm -r build;
fi

mkdir -p build
cd build
cmake .. -DBUILD_ALL=disable -DBUILD_DLOCK=enable -DASAN=enable -DCODE_COVERAGE=enable
make -j VERBOSE=1
make install

# run UT and generate code coverage report
PROJECT_NAME="dlock_ut_gtest"
PROJECT_DESC="dlock ut project"

echo "Building project: ${PROJECT_NAME} - ${PROJECT_DESC}"
cd $SCRIPT_PATH
if [ -d ./build ]; then
    rm -r build;
fi
mkdir -p build
cd build
cmake .. -DASAN=enable
make -j VERBOSE=1

echo "Running tests..."
REPORT_DIR=$(pwd)/reports
mkdir -p ${REPORT_DIR}
./dlock_ut_gtest --gtest_output="xml:${REPORT_DIR}/report.xml" -i $SERVER_IP_ADDR -e $EID -g $LOG_LEVEL

echo "Generating coverage report..."
cd $SCRIPT_PATH/../../../src/build/ulock/dlock/
lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
lcov --remove coverage.info '*c++/*' '*gtest/*' '*/tests/*' '*mockcpp/*' --output-file filtered.info --rc lcov_branch_coverage=1
genhtml filtered.info --output-directory lcov_report --rc lcov_branch_coverage=1
cp -r lcov_report ${REPORT_DIR}