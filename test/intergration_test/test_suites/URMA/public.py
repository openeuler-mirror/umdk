# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma public
"""

import logging
import random

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

    def urma_perftest_one_perf_single_dev(self, server, client, timeout=60, cmd_syntax=None, **kwargs):
        """
        Random traffic if not specified
        :param server: urma_perftest server side
        :param client: urma_perftest client side
        :param cmd_syntax: "write_bw", "send_bw"
        :param mode: "RM", "RC", "UM"
        :param opt: additional parameters configured for both server and client
        :param s_opt: additional parameters configured for the server
        :param c_opt: additional parameters configured for the client
        """
        
        opt = kwargs.get("opt", "")
        expect_failed = kwargs.get("expect_failed", False)
        s_opt = kwargs.get("s_opt", "")
        c_opt = kwargs.get("c_opt", "")
        s_dev_opt = ""
        c_dev_opt = ""
        if cmd_syntax is None:
            cmd_syntax_list = ["write_bw", "send_bw", "write_lat", "send_lat"]
            cmd_syntax = random.choice(cmd_syntax_list) 
 
        opt += f" -n 10" 
        if " -s" not in opt and " --size" not in opt:
            opt += f" -s {random.randint(1, 4096)}"
        if " -I" not in opt and " --inline_size" not in opt:
            opt += f" -I {random.randint(1, 188)}"
        if " -d" not in opt and " --dev_name" not in opt:
            s_dev_opt = f" -d {server.test_nic1}"
            c_dev_opt = f" -d {client.test_nic1}"
        if "-p " not in opt and " --trans_mode" not in opt:
            if cmd_syntax in ["send_bw", "send_lat"]:
                opt += f" -p {random.randint(0, 2)}"
            else:
                opt += f" -p {random.randint(0, 1)}"
        if " -e" not in opt and cmd_syntax not in ["write_bw", "write_lat"]:
            if random.randint(0, 1) == 1:
                opt += f" -e"
        if " -b" not in opt and "-p 1" not in opt:
            if random.randint(0, 1) == 1:
                opt += f" -b"
        if " --jetty_id" not in opt and server.test_nic1_ip != client.test_nic1_ip:
            if random.randint(0, 1) == 1:
                opt += f" --jetty_id {random.randint(3, 1024)}"
            
        if expect_failed:
            opt +=" --enable_err_continue"  
        _cmd = f"urma_perftest {cmd_syntax} {opt} -P {self.get_free_port()}"
        s_cmd = f"{_cmd} {s_dev_opt} {s_opt}"
        c_cmd = f"{_cmd} {c_dev_opt} {c_opt} -S {server.test_nic1_ip}"
        
        p1 = server.exec_cmd(s_cmd, background=True)
        p2 = client.exec_cmd(c_cmd, background=True)
        p1.wait(timeout)
        p2.wait(timeout)
        log.info("Verifying urma_perftest traffic results")
        perf_ret = 0
        if p1.ret != 0 or p2.ret != 0:
                perf_ret = -1
        if not expect_failed:
            self.assertEqual(perf_ret, 0, "ERROR: Traffic performance anomaly detected!")
        return perf_ret

    def urma_perftest_one_perf_ubagg(self, server, client, timeout=60, cmd_syntax=None, **kwargs):
        """
        Random traffic if not specified
        :param server: urma_perftest server side
        :param client: urma_perftest client side
        :param cmd_syntax: "write_bw", "send_bw"
        :param mode: "RM", "RC", "UM"
        :param opt: additional parameters configured for both server and client
        :param s_opt: additional parameters configured for server
        :param c_opt: additional parameters configured for client
        """
        
        opt = kwargs.get("opt", "")
        expect_failed = kwargs.get("expect_failed", False)
        s_opt = kwargs.get("s_opt", "")
        c_opt = kwargs.get("c_opt", "")
        
        if cmd_syntax is None:
            cmd_syntax_list = ["write_bw", "send_bw", "write_lat", "send_lat"]
            cmd_syntax = random.choice(cmd_syntax_list)
 
        opt += f" -n 10 -E 2" 
        if " -s" not in opt and " --size" not in opt:
            opt += f" -s {random.randint(1, 4096)}"
        if " -I" not in opt and " --inline_size" not in opt:
            opt += f" -I {random.randint(1, 188)}"
        if "-p " not in opt and " --trans_mode" not in opt:
            if cmd_syntax in ["send_bw", "send_lat"]:
                opt += f" -p {random.randint(0, 1)}"
            else:
                opt += f" -p {random.randint(0, 1)}"
        if " -b" not in opt and "-p 1" not in opt:
            if random.randint(0, 1) == 1:
                opt += f" -b"
        if " -e" not in opt and cmd_syntax not in ["write_bw", "write_lat"]:
            if random.randint(0, 1) == 1:
                opt += f" -e"
        if " --jetty_id" not in opt and " --single_path" not in opt:
            if random.randint(0, 1) == 1:
                opt += f" --jetty_id {random.randint(3, 998)}"
            
        if expect_failed:
            opt +=" --enable_err_continue"  
        _cmd = f"urma_perftest {cmd_syntax} {opt} -P {self.get_free_port()}"
        s_cmd = f"{_cmd} {s_opt} -d bonding_dev_0"
        c_cmd = f"{_cmd} {c_opt} -d bonding_dev_0 -S {server.test_nic1_ip}"
        
        p1 = server.exec_cmd(s_cmd, background=True)
        p2 = client.exec_cmd(c_cmd, background=True)
        p1.wait(timeout)
        p2.wait(timeout)
        log.info("Verifying urma_perftest traffic results")
        perf_ret = 0
        if p1.ret != 0 or p2.ret != 0:
            perf_ret = -1
        if not expect_failed:
            self.assertEqual(perf_ret, 0, "ERROR: Traffic performance anomaly detected!")
        return perf_ret
