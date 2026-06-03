""" test_ipourma_ifconfig_updown_in_perf

:Preparation

:TestStep
    1、分别在TCP/UDP iperf时对网卡进行ifconfig up/down操作；
    2、在up后重新打流；
    

:ExpectOutput
    1、无core；
    2、操作不影响网卡的连通性；

"""

import logging
import os
import sys
import time
import pytest
import re
log = logging.getLogger()

local_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(local_path))
from public import UBUSFeature

log = logging.getLogger()


class Test(UBUSFeature):

    def setup(self):
        super(Test, self).setup()
        log.info('---------- [ Test setup ] ----------')

    def teardown(self):
        log.info('---------- [ Test teardown ] ----------')
        super(Test, self).teardown()

    @pytest.mark.timeout(36000)
    def test_urma_ipourma_abnormal_ifconfig_updown_in_perf(self): 
        duration = 10
        server_ip = self.host2.test_nic1_ipv6
        client_ip = self.host1.test_nic1_ipv6

        for host in [self.host2, self.host1]:
            ret = host.exec_cmd("pkill iperf3 || true")
            self.assertEqual(ret.ret, 0, msg=f"Failed to kill iperf3 on {host}")

        ret = self.host2.exec_cmd("ifconfig")
        blocks = re.split(r'\n(?=\S)', ret.stdout)
        output_lines = ret.stdout.splitlines()
        ipourma_devices = [line for line in output_lines if line.strip().startswith("ipourma")]
        dev_count = len(ipourma_devices)

        for i in range(dev_count):
            self.host2.exec_cmd("iperf3 -s", background=True)
            time.sleep(2)

            client_cmd = f"iperf3 -c {server_ip} -B {client_ip} -t {duration}"
            ret = self.host1.exec_cmd(client_cmd, background=True)

            ret = self.host2.exec_cmd(f"ifconfig {self.host2.test_nic1} down")
            self.assertEqual(ret.ret, 0, msg=f"Failed to bring {self.host2.test_nic1} down")
            time.sleep(4)

            ret = self.host2.exec_cmd(f"ifconfig {self.host2.test_nic1} up")
            self.assertEqual(ret.ret, 0, msg=f"Failed to bring {self.host2.test_nic1} up")

            for host in [self.host2, self.host1]:
                ret = host.exec_cmd("pkill iperf3 || true")
                self.assertEqual(ret.ret, 0, msg=f"Failed to kill iperf3 on {host}")
            time.sleep(5)

            self.host2.exec_cmd("iperf3 -s", background=True)
            time.sleep(2)

            client_cmd = f"iperf3 -c {server_ip} -B {client_ip} -t {duration}"
            ret = self.host1.exec_cmd(client_cmd)
            self.assertEqual(ret.ret, 0, msg=f"iperf3 connection failed before down:\n{ret.stdout}")

            for host in [self.host2, self.host1]:
                ret = host.exec_cmd("pkill iperf3 || true")
                self.assertEqual(ret.ret, 0, msg=f"Failed to kill iperf3 on {host}")

