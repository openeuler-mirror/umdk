#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
#

set -e

SCRIPT_PATH=$(dirname "$0")
SCRIPT_PATH=$(cd "$SCRIPT_PATH" && pwd)
source "$SCRIPT_PATH/urma_ut_common.sh"

parse_urma_phase_script_args "$@"
run_urma_ut_phase fuzz
