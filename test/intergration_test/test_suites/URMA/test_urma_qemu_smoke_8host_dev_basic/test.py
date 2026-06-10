# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

from itertools import combinations
import logging
import pytest
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
    def test_urma_qemu_smoke_8host_dev_basic(self):
        p_list = []
        cmd_list = ["write_bw", "send_bw", "write_lat", "send_lat"]
        mode_list = [
            "-p 0 --eid_idx 0",
            "-p 1 --eid_idx 0",
            "-p 0 --ctp",
            "-p 1 --ctp",
            "-p 2 --ctp",
            "-p 0 --ctp --tp_aware",
            "-p 1 --ctp --tp_aware",
            "-p 2 --ctp --tp_aware"
        ]

        # Traverse all hosts, all modes, and all types and cover both aware TP to generate pairwise traffic
        for host1, host2 in combinations(self.host_list, 2):
            for cmd in cmd_list:
                for mode in mode_list:
                    if "-p 2" in mode and "send_" not in cmd:
                        continue
                    p_list.append(self.urma_perftest_one_perf_single_dev(host1, host2, cmd_syntax=cmd, opt=mode))
