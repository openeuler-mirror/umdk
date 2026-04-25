# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

from itertools import combinations
import pytest
import logging
from public import UBUSFeature
 
log = logging.getLogger()
 
 
class Test(UBUSFeature):
 
    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')
 
    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    @pytest.mark.timeout(1600)
    def test_urma_qemu_smoke_8host_agg_dev_basic(self):
        p_list = []
        cmd_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
        mode_list = [
            "-p 0 --single_path",
            "-p 1 --single_path",
            "-p 0 --ctp",
            "-p 1 --ctp"
        ]

        # Traverse all hosts, all types, and all modes to perform pairwise traffic generation
        for host1, host2 in combinations(self.host_list, 2):
            for cmd in cmd_list:
                for mode in mode_list:
                    p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2, cmd_syntax=cmd, opt=mode))
