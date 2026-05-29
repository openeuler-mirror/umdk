""" test_urma_iperf_concurrent_streams

:Preparation

:TestStep
        1、验证TCP iperf -P并发场景；

:ExpectOutput
    1、能正常打并发，最大到128条；

"""

import logging
import os
import sys
import time
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

    def test_urma_ipourma_iperf_concurrent_streams(self):    
        total_mbps = 5
        server = self.host3
        client = self.host2
        server_ip = server.test_nic2_ipv6
        client_ip = client.test_nic2_ipv6
        parallel_levels = [1, 4, 8, 16, 32, 64, 128]

        # Step 1: 清理旧进程
        for host in [server, client]:
            host.exec_cmd("pkill iperf3 || true")

        # Step 3: 循环测试不同并发级别
        for p in parallel_levels:
            b_val =  total_mbps / p
            server.exec_cmd("iperf3 -s", background=True)
            time.sleep(2)
            cmd = f"iperf3 -c {server_ip} -B {client_ip} -b {b_val}M -P {p}"
            ret = client.exec_cmd(cmd)

            self.assertEqual(
                ret.ret, 0,
                msg=f"iperf3 -P {p} failed with ret={ret.ret}, output:\n{ret.stdout}"
            )

            self.assertIn(
                "receiver", ret.stdout,
                msg=f"iperf3 did not complete normally at parallel={p}"
            )

            time.sleep(2)

        for host in [server, client]:
            host.exec_cmd("pkill iperf3 || true")