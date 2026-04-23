# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
* Description: urma basic loopback test refined
"""

import logging
import pytest
from public import UBUSFeature

log = logging.getLogger()

class TestUrmaLoopback(UBUSFeature):

    def setup(self):
        log.info('---------- [ Test environment initialization ] ----------')
        super(TestUrmaLoopback, self).setup()

    def teardown(self):
        log.info('---------- [ Test environment cleanup ] ----------')
        super(TestUrmaLoopback, self).teardown()

    def test_urma_basic_loopback(self):
        """
        Single-machine Loopback Traffic Test
        """
        if len(self.host_list) < 2:
            pytest.skip("Insufficient hosts in host_list, skipping test.")

        host1 = self.host_list[0]
        host2 = self.host_list[1]

        dev_name = host1.test_nic1
        msg_size = 4096
        opt = f"--ctp -d {dev_name} -s {msg_size}"

        ret = self.urma_perftest_one_perf_single_dev(
            server=host1,
            client=host2,
            timeout=60,
            cmd_syntax="send_bw",
            opt=opt
        )

        self.assertEqual(ret, 0, f"Loopback traffic test failed. Please check the status of {dev_name} or the underlying driver.")
        log.info("---------- [ Single-machine loopback traffic test passed ] ----------")
