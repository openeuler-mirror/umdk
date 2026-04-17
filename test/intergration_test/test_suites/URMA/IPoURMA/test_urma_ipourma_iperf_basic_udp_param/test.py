""" test_urma_ipourma_ko_in_iperf

:Preparation

:TestStep
    1、对UDP做参数测试；
    2、覆盖边界值，包含随机数；

:ExpectOutput
    1、能成功iperf；

"""

import logging
import os
import sys
import time
import random
import pytest

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()

@pytest.mark.timeout(36000)
class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_urma_ipourma_iperf_udp_param(self):
        test_configs = {
            "-b": ["1M", "10M", "100M", "1G", "0"] + [f"{random.randint(10, 500)}M" for _ in range(5)],
            "-l": [64, 512, 1024, 1400, 1470] + [random.randint(16, 1450) for _ in range(5)],
            "-w": ["4K", "64K", "128K", "256K"] + [f"{random.choice([32, 64, 128])}K" for _ in range(5)],
            "-P": [2, 4, 8, 16] + [random.randint(2, 10) for _ in range(5)],
            "-O": [0, 1, 2, 3] + [random.randint(0, 5) for _ in range(3)],
            "--fq-rate": ["1M", "10M", "100M"] + [f"{random.randint(1, 100)}M" for _ in range(5)],
            "--cport": [12000, 20000, 30000, 40000] + [random.randint(1024, 60000) for _ in range(5)],
        }

        flag_configs = {
            "-R": [True, False],
            "--zerocopy": [True, False]
        }

        for param, values in test_configs.items():
            for val in values:
                self.run_iperf_test(f"{param} {val}", is_udp=True)

        for flag, states in flag_configs.items():
            for enabled in states:
                if enabled:
                    self.run_iperf_test(flag, is_udp=True)