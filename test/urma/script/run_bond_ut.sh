#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
#
set -e

SCRIPT_PATH=$(cd "$(dirname "$0")"; pwd)
source "$SCRIPT_PATH/urma_ut_common.sh"

parse_urma_phase_script_args "$@"
run_urma_ut_phase bond
