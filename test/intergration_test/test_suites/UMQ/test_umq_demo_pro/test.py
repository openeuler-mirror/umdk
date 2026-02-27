"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: umq example
"""

"""
UMQ demo (数据面pro接口 + 消息是裸数据)
测试覆盖不开 UMQ_FEATURE_ENABLE_TOKEN_POLICY 、开UMQ_FEATURE_ENABLE_TOKEN_POLICY 2种情况

:Preparation
2HOST部署UMDK

:TestStep
1、umq初始化，创建queue，bind建链
2、使用数据面pro接口，发送消息（裸数据）

:ExpectOutput
1、初始化成功，创建queue成功，bind建链成功
2、发送成功，对端解析成功
"""

import logging
import os
import sys

from app.umq.umq_app import prepare_test_case, exec_test_case

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()


class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')
        prepare_test_case(self.host_list, local_path)

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    def test_umq_demo_pro(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False, mode=["UB_PLUS"])