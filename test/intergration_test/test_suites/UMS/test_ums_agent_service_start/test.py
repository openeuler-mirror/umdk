# -*- coding: utf-8 -*-

"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: ums example
"""

import logging
import os
import sys

from app.ums.ums_app import prepare_test_case, exec_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()

class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('--------- [ Test setup ] ---------')
        prepare_test_case(self.host_list, local_path)

    def teardown(self):
        log.info('--------- [ Test teardown ] ---------')
        super(Test, self).teardown()

    def test_ums_agent_service_start(self):
        log.info(f'--------- [ Test local_path = {local_path} ] ---------')
        exec_test_case(self.host_list, local_path)
