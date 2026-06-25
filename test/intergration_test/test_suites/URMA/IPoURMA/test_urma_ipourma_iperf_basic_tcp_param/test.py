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

@pytest.mark.timeout(600)
class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_urma_ipourma_iperf_basic_tcp_param(self):
        test_configs = {
            "-l": [1, 64],
            "-w": ["1K", "4K"],
            "-M": [88, 256],
            "-P": [4, 8],
        }

        for param, values in test_configs.items():
            for val in values:
                self.run_iperf_test(f"{param} {val}")
