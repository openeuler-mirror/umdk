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

@pytest.mark.timeout(600)
class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_urma_ipourma_iperf_basic_udp_param(self):
        test_configs = {
            "-b": ["1M", "100M", "0"],
            "-l": [64, 1400],
            "-P": [1, 4],
            "-O": [0, 2],
        }

        for param, values in test_configs.items():
            for val in values:
                self.run_iperf_test(f"{param} {val}", is_udp=True)
