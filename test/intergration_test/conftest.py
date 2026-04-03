# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description:
"""

import os
import random
import sys

def pytest_addoption(parser):
    parser.addoption("--random_seed", action="store", default=None, help="Configure the random library seed")


def pytest_configure(config):
    # Set random seed
    random_seed = config.getoption("--random_seed")
    if random_seed is None:
        random_seed = random.randint(0, 10000)
    random.seed(int(random_seed))
    src_path = os.path.abspath(os.path.dirname(__file__)).split('test_suites')[0]
    framework_path = os.path.join(src_path, "test_framework")
    sys.path.insert(0, framework_path)
    from common.constants import const
    const.CASE_PATH = os.path.abspath(config.invocation_params.args[0])
    const.CASE_DIR = os.path.dirname(const.CASE_PATH)
    const.CASE_NAME = const.CASE_DIR.split('/')[-1]
    sys.path.insert(0, os.path.dirname(const.CASE_DIR))

    const.IP_VERSION = [item for item in const.IP_VERSION if item != '']
    const.URMA_MODE = [item for item in const.URMA_MODE if item != '']

    timeout = int(config.getoption("--timeout"))
    if const.TMOUT != timeout:
        const.TMOUT = timeout
    print(f"pytest {const.CASE_PATH}  --random_seed {random_seed}")

def pytest_collection_modifyitems(items):
    for item in items:
        mark = item.get_closest_marker(name='timeout')
        if mark:
            timeout = mark.args[0]
            from common.constants import const
            if const.TMOUT != timeout:
                const.TMOUT = timeout