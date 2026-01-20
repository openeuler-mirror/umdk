#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

set -e
SCRIPT_PATH=$(cd $(dirname $0);pwd)
REPORTS_PATH=$SCRIPT_PATH/reports
DEPENDENCIES_PATH=$SCRIPT_PATH/dependencies

# compile uRPC code
cd $SCRIPT_PATH/../../src
if [ -d ./build ]; then
    rm -r build;
fi

mkdir -p build
cd build
cmake -DBUILD_ALL=disable -DBUILD_URPC=enable -DASAN=enable -DCODE_COVERAGE=enable ..
make -j
make install

# copy .gcno to reports dir
if [ -d $REPORTS_PATH ]; then
    rm -r $REPORTS_PATH;
fi
mkdir -p $REPORTS_PATH
find $(pwd) -name *.gcno | xargs -i cp --parents {} $REPORTS_PATH

# copy .so to dependencies dir to avoid impact others
if [ -d $DEPENDENCIES_PATH ]; then
    rm -r $DEPENDENCIES_PATH;
fi
mkdir -p $DEPENDENCIES_PATH
find ./ -name *.so | xargs -i cp {} $DEPENDENCIES_PATH

cd $SCRIPT_PATH
if [ -d ./build ]; then
    rm -r build;
fi
mkdir -p build
cd build
cmake ..
make -j

echo "Running tests..."
export LD_LIBRARY_PATH="$DEPENDENCIES_PATH:$LD_LIBRARY_PATH"
export GCOV_PREFIX="$REPORTS_PATH"

./core/test_core
./lib/test_lib
./protocol/test_protocol
./util/test_util

echo "Generating coverage reports..."
cd $REPORTS_PATH
lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1
genhtml coverage.info --output-directory lcov_report -rc lcov_branch_coverage=1