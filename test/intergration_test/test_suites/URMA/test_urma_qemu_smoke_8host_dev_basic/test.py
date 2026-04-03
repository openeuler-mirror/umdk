# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

from itertools import combinations
import random
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
 
    def test_urma_qemu_smoke_8host_dev_basic(self):
        p_list = []
        # Pairwise traffic traversal
        for host1, host2 in combinations(self.host_list, 2):
            opt = "--ctp "
            if random.randint(0, 1) == 1:
                opt += "--tp_aware "
            p_list.append(self.urma_perftest_one_perf_single_dev(host1, host2, opt=opt))

        # Randomly generate 20 flows again
        for _ in range(20):
            opt = "--ctp "
            host1, host2 = random.sample(self.host_list, 2)
            if random.randint(0, 1) == 1:
                opt += "--tp_aware "
            p_list.append(self.urma_perftest_one_perf_single_dev(host1, host2, opt=opt))