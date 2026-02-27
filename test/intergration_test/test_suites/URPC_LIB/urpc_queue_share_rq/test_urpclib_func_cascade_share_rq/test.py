"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib example
"""

"""
配置share_rq创建queue，校验queue查询信息，并进行收发请求测试，检查queue报文统计

:Preparation
server端正常创建一个queue

:TestStep
1、client正常创建queue0
2、创建queue1、queue2，并配置share_rq=queue0
3、创建queue3、queue4，并配置share_rq=queue1
4、创建queue5、queue6，并配置share_rq=queue4
5、所有queue添加到1个channel中，串行使用queue0/1/2/3/4/5/6发送1000次rpc请求，使用1个queue poll rsp 1000次，均成功
6、client删除queue4，并使用queue5/6发送rpc请求，然后server回复rsp
7、client删除queue0，使用queue1/3/2/5/6发送rpc请求
8、client删除queue1/2/3/5，使用queue6发送rpc请求
9、查询queue6信息，其中rx_depth、rx_buf_size、max_rxsge与queue0一致
10、删除queue6

:ExpectOutput
2、创建queue1、queue2成功，查询queue1、queue2的信息rx_depth、rx_buf_size、max_rxsge与queue0一致
3、创建queue3、queue4成功，查询queue3、queue4的信息rx_depth、rx_buf_size、max_rxsge与queue0一致
4、创建queue5、queue6成功，查询queue5、queue6的信息rx_depth、rx_buf_size、max_rxsge与queue0一致
5、查询各个queue报文统计信息，与各个queue调用call、poll的次数一致
6、queue4删除成功，client使用queue5 poll rsp成功。查询queue5统计信息比queue6接受数量多（与rps数量一致）
7、queue0删除成功，rpc请求成功，指定channel poll rps成功
8、删除queue成功，使用queue6发送请求成功，使用channel poll rsp成功
10、删除queue6成功
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

    def test_urpclib_func_cascade_share_rq(self):
        log.info(f'---------- [ Test local_path = {local_path} ] ----------')
        exec_test_case(self.host_list, local_path, rand_host=False)