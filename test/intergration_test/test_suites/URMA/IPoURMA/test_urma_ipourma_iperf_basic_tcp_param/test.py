""" test_urma_ipourma_ko_in_iperf

:Preparation

:TestStep
    1、对TCP的-l，-w，-b，-P参数做参数测试；
    2、覆盖边界值，包含随机数；

:ExpectOutput
    1、能成功iperf；

"""

import logging
import os
import sys
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

    def test_urma_ipourma_iperf_tcp_param(self):
        test_configs = {
            "-l": [1, 64, 512, 1024, 4056, 65535] + [random.randint(16, 8192) for _ in range(5)],
            "-w": ["1K", "4K", "64K", "128K", "256K"] + [f"{random.choice([4,8,16,32,64])}K" for _ in range(5)],
            "-M": [88, 256, 512, 1024, 1440, 4055] + [random.randint(128, 4055) for _ in range(5)],
            "-P": [4, 8, 16, 32, 64] + [random.randint(1, 32) for _ in range(5)],
            "-O": [0, 1, 2, 3] + [random.randint(0, 5) for _ in range(3)],
            "--fq-rate": ["1M", "10M", "100M", "1G"] + [f"{random.randint(1,100)}M" for _ in range(5)],
            "--cport": [12000, 20000, 30000, 40000] + [random.randint(1024, 60000) for _ in range(5)],
        }

        flag_configs = {
            "-N": [True, False],
            "-R": [True, False],
            "--zerocopy": [True, False]
        }

        for param, values in test_configs.items():
            for val in values:
                self.run_iperf_test(f"{param} {val}")

        for flag, states in flag_configs.items():
            for enabled in states:
                cmd_part = flag if enabled else ""
                if flag == "-N": 
                    cmd_part += " -l 1"
                self.run_iperf_test(cmd_part)