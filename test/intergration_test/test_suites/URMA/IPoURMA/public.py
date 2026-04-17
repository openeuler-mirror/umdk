import logging
import itertools
import time
from app.urma.urma_test import URMAFeature
import re
logging.basicConfig(level=logging.INFO)
log = logging.getLogger()


class UBUSFeature(URMAFeature):

    def setup(self):
        log.info('---------- [ UBUSFeature setup ] ----------')
        super(UBUSFeature, self).setup()

    def teardown(self):
        log.info('---------- [ UBUSFeature teardown ] ----------')
        super(UBUSFeature, self).teardown()


    def insmod_ipourma_and_check_dev_num(self, client, server):
        ret = server.exec_cmd("ifconfig", timeout=5)
        ipourma_srv = re.findall(r'^(ipourma\S+)', ret.stdout, re.MULTILINE)
        ipourma_srv_count = len(ipourma_srv)
        log.info(f"[Server] there is {ipourma_srv_count} ipourma_dev: {ipourma_srv}\n")

        self.assertTrue(
            ipourma_srv_count > 0,
            msg=f"[Server] there is no ipourma_dev! ifconfig show:\n{ret.stdout}"
        )

        ret = server.exec_cmd("urma_admin show -a| awk '{print $2}'", timeout=5)
        udma_srv = sorted(set(
            x.strip() for x in ret.stdout.splitlines()
            if x.strip() and "udma" in x and not x.startswith("ubep_dev")
        ))
        udma_srv_count = len(udma_srv)
        log.info(f"[Server] there is {udma_srv_count} ubep_dev: {udma_srv}")

        self.assertEqual(
            ipourma_srv_count, udma_srv_count,
            msg=(
                f"[Server]: ipourma({ipourma_srv_count}) != udma({udma_srv_count})\n"
                f"ifconfig list: {ipourma_srv}\n"
                f"udma list: {udma_srv}"
            )
        )

        ret= client.exec_cmd("ifconfig", timeout=10)
        ipourma_cli = re.findall(r'^(ipourma\S+)', ret.stdout, re.MULTILINE)
        ipourma_cli_count = len(ipourma_cli)
        log.info(f"[Client] there is {ipourma_cli_count} ipourma dev: {ipourma_cli}")

        self.assertTrue(
            ipourma_cli_count > 0,
            msg=f"[Client] there is no ipourma dev! ifconfig show:\n{ret.stdout}"
        )

        ret = client.exec_cmd("urma_admin show -a| awk '{print $2}'", timeout=10)
        udma_cli = sorted(set(
            x.strip() for x in ret.stdout.splitlines()
            if x.strip() and "udma" in x and not x.startswith("ubep_dev")
        ))
        udma_cli_count = len(udma_cli)
        log.info(f"[Client]there is {udma_cli_count} ubep_dev: {udma_cli}")

        self.assertEqual(
            ipourma_cli_count, udma_cli_count,
            msg=(
                f"[Client]: ipourma({ipourma_cli_count}) != udma({udma_cli_count})\n"
                f"ifconfig list: {ipourma_cli}\n"
                f"udma list: {udma_cli}"
            )
        )

    def run_iperf_test(self, extra_cmd, is_udp=False):
        server_ip = self.host2.test_nic2_ipv6
        client_ip = self.host3.test_nic2_ipv6
        test_type = "UDP" if is_udp else "TCP"

        for host in [self.host2, self.host3]:
            host.exec_cmd("pkill -9 iperf3 || true")
        time.sleep(1)

        srv_cmd = f"iperf3 -s -B {server_ip}" if is_udp else "iperf3 -s"
        self.host2.exec_cmd(srv_cmd, background=True)
        time.sleep(2)

        udp_flag = "-u" if is_udp else ""
        duration = "-t 10" if "-O" in extra_cmd else "-t 5"
        full_cmd = f"iperf3 -c {server_ip} -B {client_ip} {udp_flag} {extra_cmd} {duration}"

        log.info(f"Starting {test_type} stress test: {full_cmd}")
        ret = self.host3.exec_cmd(full_cmd)

        self.assertEqual(ret.ret, 0, 
            f"{test_type} process exited with non-zero code: {ret.ret}. Stderr: {ret.stderr}")
        self.assertIn("sender", ret.stdout, 
            f"{test_type} test incomplete: 'sender' keywords not found in output. Stdout: {ret.stdout}")
        
        self.assertNotIn("error", ret.stdout.lower(), 
            f"Detected error keywords in {test_type} test output!")
        
        self.assertNotIn("timeout", ret.stdout.lower(), 
            f"{test_type} test failed due to connection timeout.")
        
        self.assertNotIn("connection refused", ret.stdout.lower(), 
            f"{test_type} server refused the connection on {server_ip}.")