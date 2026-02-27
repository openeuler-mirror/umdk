"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""
携带ctrl_msg 重复attach detach

:Preparation

:TestStep
1、两边注册ctrl_msg回调， 1channel， 携带ctrl_msg 重复attach refresh detach 100次，并且发送普通no ack场景

:ExpectOutput
1、成功

"""

import logging
import os
import sys
import pytest

from app.urpc.urpc_app import prepare_test_case_urpc_lib, exec_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()


class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')
        prepare_test_case_urpc_lib(self.host_list, local_path)

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    @pytest.mark.timeout(1200)
    def test_urpclib_ctrl_msg_repeate_attach_refresh(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, client_num=1, rand_host=False)