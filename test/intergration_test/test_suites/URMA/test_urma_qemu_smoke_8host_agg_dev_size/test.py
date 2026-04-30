# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma example
"""

from itertools import combinations
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

    @pytest.mark.timeout(1600)
    def test_urma_qemu_smoke_8host_agg_dev_size(self):
        p_list = []
        cmd_list = ["send_lat", "read_lat", "write_lat",
                     "send_bw", "read_bw", "write_bw"]
        # Send single mode maximum 64K, current simulation performance is insufficient
        size_ranges = [
            ("1", 1, 1),
            ("1-1K", 1, 1024),
            ("1K", 1024,  1024),
            ("1025", 1025,  1025),
            ("1K-4K", 1025, 4096),
            ("4K", 4096, 4096),
            ("4K-64K", 4097, 65536),
        ]

        # Randomly generate 2 flows for each size
        for _ in range(2):
            host1, host2 = random.sample(self.host_list, 2)
            for cmd in cmd_list:
                for label, min_size, max_size in size_ranges:
                    size = random.randint(min_size, max_size)
                    opt = f" -s {size} -p 1 --single_path"
                    if cmd in ["send_bw", "read_bw", "write_bw"]:
                        if random.randint(0, 1) == 1:
                            opt +=" -B"
                    p_list.append(
                        self.urma_perftest_one_perf_ubagg(
                            host1, host2,
                            timeout=60,
                            cmd_syntax=cmd,
                            opt=opt
                        )
                    )
                  