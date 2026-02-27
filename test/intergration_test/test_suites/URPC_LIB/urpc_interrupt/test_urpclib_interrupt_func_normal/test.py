"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""
设置queue中断模式，获取对应的epoll fd，发送不通场景的报文

:Preparation


:TestStep
1、设置queue中断模式，server/client初始化
2、获取对应的epoll fd，通过epoll_wait等待事件
3、client发送不通场景的报文。检验收发统计信息

:ExpectOutput
1、初始化成功
2、获取成功
3、发送成功，统计信息正确

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

    def test_urpclib_interrupt_func_normal(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)