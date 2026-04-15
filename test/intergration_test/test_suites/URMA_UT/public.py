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
        :param cmd_syntax: "read_bw", "write_bw", "send_bw"
        :param mode: "RM", "RC", "UM"
        :param opt: additional parameters configured for both server and client
        :param s_opt: additional parameters configured for the server
        :param c_opt: additional parameters configured for the client
        """
        
        opt = kwargs.get("opt", "")
        expect_failed = kwargs.get("expect_failed", False)
        s_opt = kwargs.get("s_opt", "")
        c_opt = kwargs.get("c_opt", "")
        
        if cmd_syntax is None:
            cmd_syntax_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
            cmd_syntax = random.choice(cmd_syntax_list) 
 
        opt += f" -n 10" 
        if "-s " not in opt and "--size " not in opt:
            opt += f" -s {random.randint(1, 4096)}"
        if "-I " not in opt and "--inline_size " not in opt:
            opt += f" -I {random.randint(1, 188)}"
        if "-d " not in opt and "--dev_name " not in opt:
            if random.randint(0, 1) == 1:
                opt += f" -d udma2"
            else:
                opt += f" -d udma5"
        if "-p " not in opt and "--trans_mode " not in opt:
            if cmd_syntax in ["send_bw", "send_lat"]:
                opt += f" -p {random.randint(0, 2)}"
            else:
                opt += f" -p {random.randint(0, 1)}"
        if "-e " not in opt and cmd_syntax not in ["write_bw", "write_lat"]:
            if random.randint(0, 1) == 1:
                opt += f" -e"
        if "-b " not in opt and "-p 1" not in opt:
            if random.randint(0, 1) == 1:
                opt += f" -b"
        if "--jetty_id " not in opt and server.test_nic1_ip != client.test_nic1_ip:
            if random.randint(0, 1) == 1:
                opt += f" --jetty_id {random.randint(3, 1024)}"
            
        if expect_failed:
            opt +=" --enable_err_continue"  
        _cmd = f"urma_perftest {cmd_syntax} {opt} -P {self.get_free_port()}"
        s_cmd = f"{_cmd} {s_opt}"
        c_cmd = f"{_cmd} {c_opt} -S {server.test_nic1_ip}"
        
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
        :param cmd_syntax: "read_bw", "write_bw", "send_bw"
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
            cmd_syntax_list = ["read_bw", "write_bw", "send_bw", "read_lat", "write_lat", "send_lat"]
            cmd_syntax = random.choice(cmd_syntax_list)
 
        opt += f" -n 10 -E 2" 
        if server.test_nic1_ip == client.test_nic1_ip:
            opt += f" -p 1 --single_path"
        if "-s " not in opt and "--size " not in opt:
            opt += f" -s {random.randint(1, 4096)}"
        if "-I " not in opt and "--inline_size " not in opt:
            opt += f" -I {random.randint(1, 188)}"
        if "-p " not in opt and "--trans_mode " not in opt:
            if cmd_syntax in ["send_bw", "send_lat"]:
                opt += f" -p {random.randint(0, 1)}"
            else:
                opt += f" -p {random.randint(0, 1)}"
        if "-b " not in opt and "-p 1" not in opt:
            if random.randint(0, 1) == 1:
                opt += f" -b"
        if "-e " not in opt and cmd_syntax not in ["write_bw", "write_lat"]:
            if random.randint(0, 1) == 1:
                opt += f" -e"                
        if "--jetty_id " not in opt and "--single_path " not in opt:
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

    def urma_perftest_bonding_scenario(self, server, client, cmd_syntax="send_bw", timeout=60, **kwargs):
        """
        Executes precise, targeted traffic testing specifically for bonding devices.
        :param server: urma_perftest server side
        :param client: urma_perftest client side
        :param cmd_syntax: "read_bw", "write_bw", "send_bw"
        :param timeout: Timeout duration in seconds, defaults to 120s
        """
        opt = kwargs.get("opt", "").strip()
        expect_failed = kwargs.get("expect_failed", False)
        s_opt = kwargs.get("s_opt", "")
        c_opt = kwargs.get("c_opt", "")

        # Provide default values if basic parameters are missing to ensure the test executes successfully
        if "-n " not in opt and "--iters " not in opt:
            opt += " -n 32"          # Default to 32 iterations
        if "-s " not in opt and "--size " not in opt:
            opt += " -s 2048"        # Default message size: 2048
        if "-I " not in opt and "--inline_size " not in opt:
            opt += " -I 128"         # Default inline data size: 128
        if " -E " not in opt and "--err_timeout " not in opt:
            opt += " -E 2"           # Aggregation timeout config typically required in bonding scenarios

        # Support for expected failure scenarios
        if expect_failed:
            opt += " --enable_err_continue"

        # Core modification: Dynamically allocate a free port and enforce the use of bonding_dev_0
        _cmd = f"urma_perftest {cmd_syntax} {opt} -P {self.get_free_port()}"
        s_cmd = f"{_cmd} {s_opt} -d bonding_dev_0"
        c_cmd = f"{_cmd} {c_opt} -d bonding_dev_0 -S {server.test_nic1_ip}"

        # Execute commands asynchronously in the background
        p1 = server.exec_cmd(s_cmd, background=True)
        p2 = client.exec_cmd(c_cmd, background=True)
        p1.wait(timeout)
        p2.wait(timeout)

        log.info("Verifying urma_perftest bonding scenario results")
        perf_ret = 0
        if p1.ret != 0 or p2.ret != 0:
            perf_ret = -1

        # Result verification
        if not expect_failed:
            self.assertEqual(perf_ret, 0, "ERROR: Traffic performance anomaly detected in bonding scenario!")

        return perf_ret
