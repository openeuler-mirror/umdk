# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

from itertools import combinations
import pytest
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

    @pytest.mark.timeout(800)
    def test_urma_qemu_smoke_8host_agg_dev_basic(self):
        p_list = []
        for host1, host2 in combinations(self.host_list, 2):
            for _ in range(3):
                p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))

        # Randomly generate 20 flows again
        for _ in range(20):
            host1, host2 = random.sample(self.host_list, 2)
            p_list.append(self.urma_perftest_one_perf_ubagg(host1, host2))