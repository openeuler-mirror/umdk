# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
* Description: urma bonding traffic test - VM Migration scenario
"""

import logging
import pytest
from public import UBUSFeature

log = logging.getLogger()

class TestBondingVmMigration(UBUSFeature):

    def setup(self):
        log.info('---------- [ Test environment initialization: VM Migration ] ----------')
        super(TestBondingVmMigration, self).setup()

    def teardown(self):
        log.info('---------- [ Test environment cleanup: VM Migration ] ----------')
        super(TestBondingVmMigration, self).teardown()

    def test_bonding_vm_migration(self):
        """
        Bonding Traffic Test: VM Migration Scenario (RM + CTP + balance + simplex)
        """
        if len(self.host_list) < 2:
            pytest.skip("Insufficient hosts in host_list, skipping test.")

        host1 = self.host_list[0]
        host2 = self.host_list[1]

        opt = "-p 0 --ctp --aggr_mode balance -b"

        ret = self.urma_perftest_bonding_scenario(
            server=host1,
            client=host2,
            timeout=120,
            cmd_syntax="write_bw",
            opt=opt
        )

        self.assertEqual(ret, 0, "VM Migration scenario traffic test failed. Please check bonding_dev_0 status.")
        log.info("---------- [ VM Migration scenario traffic test passed ] ----------")