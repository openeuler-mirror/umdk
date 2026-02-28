#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: Markers for UT, skip if ranksize is not equal to expected value
# Create: 2026-1-13
# Note:
# History: 2026-1-13 create marker file
#

import pytest
from . import tool

Author = pytest.mark.author
MPTest = pytest.mark.multi_process_test
SPTest = pytest.mark.single_process_test
A2Test = pytest.mark.a2_test
A3Test = pytest.mark.a3_test

def SKIP_ENV_RANKSIZE_UNEQUAL(expect_ranksize, reason='skip if ranksize is not equal to '):
    skip = False
    if expect_ranksize != tool.get_world_size():
        skip = True
        reason += str(expect_ranksize)
    return pytest.mark.skipif(condition=skip, reason=reason)
