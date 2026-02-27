"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""

:Preparation

:TestStep
1、启动1个server，启动一个client，server端创建100个queue，client创建16channel，100个queue
2、server启动一个线程poll、return rsp，client启动100个线程让每个channel都发送rpc请求

:ExpectOutput
1、启动成功
2、client发送rpc请求成功，server处理rpc请求成功

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

    def test_urpclib_multi_thread_typical_scene_01(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)