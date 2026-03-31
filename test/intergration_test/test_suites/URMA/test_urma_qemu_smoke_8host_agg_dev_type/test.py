# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

import random
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

    @pytest.mark.timeout(800)
    def test_urma_qemu_smoke_8host_agg_dev_type(self):
        p_list = []
        cmd_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
        mode_list = ["-p 0", "-p 1"]

        # Randomly generate 20 flows
        for _ in range(20):
            host1, host2 = random.sample(self.host_list, 2)
            p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))
        # traverse all traffic types
        for cmd in cmd_list:
            for mode in mode_list:
                host1, host2 = random.sample(self.host_list, 2)
                p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2, cmd_syntax=cmd, opt=mode))

        # randomly generate 20 flows again
        for _ in range(20):
            host1, host2 = random.sample(self.host_list, 2)
            p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))