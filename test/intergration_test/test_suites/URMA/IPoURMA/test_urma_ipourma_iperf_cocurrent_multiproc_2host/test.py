# -*- coding: utf-8 -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright (C) 2016-2021 Huawei Inc
#
# Author h00467106
# pylint: disable=

"""

:Preparation

:TestStep
使用多host并发，在每个host上启动多个iperf3进程，绑定多个port，打多条流：
    1、多打一场景：多个client同时向一个server设备发流；
    2、一打多场景：一个client向多个server设备发流；
    3、每个host使用多个nic并发打流；
    4、遍历host_list中的所有nic；

:ExpectOutput
    1、符合预期

"""

import logging
import time
import pytest
from public import UBUSFeature

log = logging.getLogger()


class Test(UBUSFeature):
    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    @pytest.mark.timeout(600)
    def test_urma_ipourma_iperf_cocurrent_multiproc_2host(self):
        """多打一场景：多个client同时向一个server发流，client使用多个nic并发打流"""
        # 获取host2和host1的所有test_nic
        host2_nics = list(self.host2.test_nic.values())
        host1_nics = list(self.host1.test_nic.values())
        duration = 30

        log.info(f"host2 test_nics count: {len(host2_nics)}")
        log.info(f"host1 test_nics count: {len(host1_nics)}")
        # 清理旧进程
        self.host2.exec_cmd("pkill -9 iperf3 || true", silence=2)
        self.host1.exec_cmd("pkill -9 iperf3 || true", silence=2)
        # 场景一：多打一 - host1多个nic -> host2一个nic
        log.info("========== Multi-to-One Testing ==========")
        server_nic = host2_nics[0]
        server_ip = server_nic.get('ipv6')
        if not server_ip:
            log.error("No ipv6 address for server nic")
            return
        time.sleep(1)

        client_handles = []

        # 每个nic启动num_procs个进程
        num_procs = 4
        for client_nic in host1_nics:
            client_ip = client_nic.get('ipv6')
            if not client_ip:
                continue

            for i in range(num_procs):
                base_port = self.get_free_port()
                self.host2.exec_cmd(f"iperf3 -s -B {server_ip} -p {base_port}", background=True)
                time.sleep(2)
                cmd = f"iperf3 -c {server_ip} -B {client_ip} -p {base_port} -t {duration}"
                handle = self.host1.exec_cmd(cmd, background=True, timeout=duration + 10)
                client_handles.append(handle)
        time.sleep(duration + 5)
        for i, ret in enumerate(client_handles):
            self.assertEqual(ret.ret, 0, f"Multi-to-One Client {i} failed (Port {base_port+i})")

        # 场景二：一打多 - host2一个nic -> host1多个nic
        log.info("========== One-to-Multi Testing ==========")
        client_nic = host1_nics[0]
        client_ip = client_nic.get('ipv6')
        if not client_ip:
            log.error("No ipv6 address for client nic")
            return

        self.host2.exec_cmd("pkill -9 iperf3 || true", silence=2)
        self.host1.exec_cmd("pkill -9 iperf3 || true", silence=2)
        time.sleep(1)

        client_handles = []

        for server_nic in host2_nics:
            server_ip = server_nic.get('ipv6')
            if not server_ip:
                continue

            for i in range(num_procs):
                base_port = self.get_free_port()
                self.host2.exec_cmd(f"iperf3 -s -B {server_ip} -p {base_port}", background=True)
                time.sleep(2)
                cmd = f"iperf3 -c {server_ip} -B {client_ip} -p {base_port} -t {duration}"
                handle = self.host1.exec_cmd(cmd, background=True, timeout=duration + 10)
                client_handles.append(handle)
        time.sleep(duration + 5)
        for i, ret in enumerate(client_handles):
            self.assertEqual(ret.ret, 0, f"One-to-Multi Client {i} failed (Port {base_port+i})")
