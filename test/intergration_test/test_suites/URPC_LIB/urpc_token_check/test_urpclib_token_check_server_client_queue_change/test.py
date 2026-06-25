"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""
urpc lib token检验测试
server、client端queue变更，server初始3个queue，client初始3个queue，server client再同时增加3个queue

:Preparation
2HOST部署UMDK

:TestStep
1、启动1个server，创建3个queue，启动1个client，创建3个queue，创建3个channel
2、client做attach、mem_seg_remote_access_enable，发送SEND_READ请求
3、server client再同时增加3个queue
4、client做mem_seg_remote_access_enable、refresh、add remote queue和pair操作，发送SEND_READ请求

:ExpectOutput
1、启动成功
2、client做attach、mem_seg_remote_access_enable成功，发送SEND_READ请求成功
3、server client 创建queue成功
4、client做mem_seg_remote_access_enable、refresh、add remote queue和pair操作，发送SEND_READ请求成功，server处理成功

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

    def test_urpclib_token_check_server_client_queue_change(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)