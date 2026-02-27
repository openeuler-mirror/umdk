"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

import logging
import os

from ubus_test.base_test import BaseTest

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

class UBUSFeature(BaseTest):

    def setup(self):
        log.info('---------- [ UBUSFeature setup ] ----------')
        super(UBUSFeature, self).setup()

    def teardown(self):
        log.info('---------- [ UBUSFeature teardown ] ----------')
        super(UBUSFeature, self).teardown()