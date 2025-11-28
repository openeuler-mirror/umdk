#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

set -e
SCRIPT_PATH=$(cd $(dirname $0);pwd)

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

cd $SCRIPT_PATH
if [ -d ./build ]; then
    rm -r build;
fi
mkdir -p build
cd build
cmake ..
make -j

echo "Running tests..."
./core/test_core
./lib/test_lib
./protocol/test_protocol
./util/test_util