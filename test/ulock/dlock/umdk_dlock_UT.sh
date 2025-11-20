#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

set -e
SCRIPT_PATH=$(cd $(dirname $0);pwd)

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
./dlock_ut_gtest --gtest_output="xml:${REPORT_DIR}/report.xml"

echo "Generating coverage report..."
cd $SCRIPT_PATH/../../../src/ulock/dlock/build/lib/dlock
lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
lcov --remove coverage.info '*c++/*' '*gtest/*' '*/tests/*' '*mockcpp/*' --output-file filtered.info --rc lcov_branch_coverage=1
genhtml filtered.info --output-directory lcov_report --rc lcov_branch_coverage=1
cp -r lcov_report ${REPORT_DIR}