# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
* Description: urma bonding traffic test - BRPC scenario
"""

import logging
import pytest
from public import UBUSFeature

log = logging.getLogger()

class TestBondingBrpc(UBUSFeature):

    def setup(self):
        log.info('---------- [ Test environment initialization: BRPC ] ----------')
        super(TestBondingBrpc, self).setup()

    def teardown(self):
        log.info('---------- [ Test environment cleanup: BRPC ] ----------')
        super(TestBondingBrpc, self).teardown()

    def test_bonding_brpc(self):
        """
        Bonding Traffic Test: BRPC Scenario (RM + single_path + active_backup)
        """
        if len(self.host_list) < 2:
            pytest.skip("Insufficient hosts in host_list, skipping test.")

        host1 = self.host_list[0]
        host2 = self.host_list[1]

        opt = "-p 0 --ctp --aggr_mode active_backup"

        ret = self.urma_perftest_bonding_scenario(
            server=host1,
            client=host2,
            timeout=120,
            cmd_syntax="send_bw",
            opt=opt
        )

        self.assertEqual(ret, 0, "BRPC scenario traffic test failed. Please check bonding_dev_0 status.")
        log.info("---------- [ BRPC scenario traffic test passed ] ----------")