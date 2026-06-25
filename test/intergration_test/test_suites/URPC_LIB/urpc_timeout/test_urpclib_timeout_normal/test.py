"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""
设置IO超时，发送各种rsp/ack场景报文

:Preparation

:TestStep
1、设置io超时，发送各种rps_ack_rsp_noack场景报文
2、在超时前后分别查询rsp/ack消息

:ExpectOutput
1、发送成功
2、超时前能差导rsp/ack消息，超时后能poll到POLL_EVENT_REQ_ERR
"""

import logging
import os
import sys

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

    def test_urpclib_timeout_normal(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)