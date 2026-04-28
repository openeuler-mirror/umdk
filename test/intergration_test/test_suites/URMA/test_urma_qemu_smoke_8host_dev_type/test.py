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
    def test_urma_qemu_smoke_8host_dev_type(self):
        p_list = []
        cmd_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
        mode_list = ["-p 0 --eid_idx 0", "-p 1  --eid_idx 0", "-p 0 --ctp", "-p 1 --ctp"]
        for cmd in cmd_list:
            for mode in mode_list:
                p_list.append(self.urma_perftest_one_perf_single_dev(self.host1, self.host2, cmd_syntax=cmd, opt=mode))

        p_list.append(self.urma_perftest_one_perf_single_dev
                      (self.host2, self.host1, cmd_syntax="send_bw", opt="-p 2 --ctp "))
        p_list.append(self.urma_perftest_one_perf_single_dev
                      (self.host1, self.host2, cmd_syntax="send_lat", opt="-p 2 --ctp "))

        # Sensing TP primary_eid only supports CTP
        cmd_list2 = ["read_lat", "write_lat", "send_lat"]
        mode_list2 = ["-p 0 --ctp --tp_aware", "-p 1 --ctp --tp_aware"]
        for cmd in cmd_list2:
            for mode in mode_list2:
                p_list.append(self.urma_perftest_one_perf_single_dev(self.host2, self.host1, cmd_syntax=cmd, opt=mode))
        p_list.append(self.urma_perftest_one_perf_single_dev(self.host1, self.host2, cmd_syntax="send_lat", opt="-p 2 --tp_aware --ctp"))

        for _ in range(20):
            if random.randint(0, 1) == 1:
                host1, host2 = random.sample(self.host_list, 2)
                p_list.append(self.urma_perftest_one_perf_single_dev(host1, host2, opt="--ctp "))
            else:
                p_list.append(self.urma_perftest_one_perf_single_dev(self.host1, self.host2, opt="--eid_idx 0 "))