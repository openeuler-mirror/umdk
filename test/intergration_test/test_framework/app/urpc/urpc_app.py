"""
 * SPDX-License-Identifier: MT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpclib framework
"""

import logging
import os
import random
import platform
import time
import datetime

from common.constants import const

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))


URPC_TRANS_MODE_UB = 1


def exec_shell(host_list, _cmd):
    p_list = []
    for host in host_list:
        p_list.append(host.exec_cmd(_cmd, background=True))

    for p in p_list:
        p.wait()
        if p.ret != 0:
            log.error(f'exec_shell failed! _cmd is {_cmd}')
            raise

def prepare_test_case_urpc_lib(host_list, case_path, debug=False):
    common_path = f'{local_path}/../common'

    case_cpp = os.path.join(case_path, "test_case.cpp")
    public_cpp = os.path.join(case_path, "../public.cpp")
    case_out = os.path.join(case_path, "test_case")
    case_log = os.path.join(case_path, "*.log")
    afi_cmd = ' -g -O0'

    _cmd = f'cd {local_path};' \
        f'g++ ../common/common.c ../common/test_log.c ../common/test_thread_pool.c ' \
        f'urpc_lib_atom.cpp {case_cpp} '
    if os.path.exists(public_cpp):
        _cmd += f"{public_cpp} "
    _cmd += f"{afi_cmd} -o {case_out} "

    lib_list = ['-lglib-2.0', '-lpthread', '-lurpc_framework', f'-I {local_path}', f'-I {case_path}/../',
    f'-I {const.GCC_INCLUDE_PATH_URPC}']

    _cmd += " ".join(lib_list)
    if const.FLAG_LOCK_FREE == 1:
        _cmd += " -DLOCK_FREE"

    _cmd += f" && rm -fr {case_log}"

    p_list = []
    for host in host_list:
        p_list.append(host.exec_cmd(_cmd, background=True))

    for p in p_list:
        p.wait()
        if p.ret != 0:
            log.error("gcc test_case failed!")
            raise

def gen_random_port(host_list, port_num=2):
    tcp_port = 20000
    test_port = 30000
    used_ports = set()
    for host in host_list:
        _cmd = "netstat -ant|grep '^tcp'|awk '{print $4}'|awk -F':' '{print $NF}'|sort | uniq"
        for port in host.exec_cmd(_cmd, silence=True).stdout.split("\r\n"):
            if port.isdigit():
                used_ports.add(int(port))
    for i in range(100):
        tcp_port = random.randint(20000, 30000)
        test_port = tcp_port + 10000
        if tcp_port not in used_ports and test_port not in used_ports:
            break
    return tcp_port, test_port


def get_test_dev(case_name, test_host, host_idx):
    test_dev2 = None

    if case_name.startswith("test_urpclib") and hasattr(test_host[0], "test_nic2"):
        test_dev = test_host[host_idx].test_nic2
    else:
        test_dev = test_host[host_idx].test_nic1
        test_dev2 = test_host[host_idx].test_nic1_dev

    return test_dev, test_dev2

def get_test_eid(case_name, test_host, host_idx):
    test_eid = ""
    if case_name.startswith("test_urpclib") and hasattr(test_host[0], "test_nic2"):
        test_eid = test_host[host_idx].test_nic2_eid
    else:
        test_eid = test_host[host_idx].test_nic1_eid
    return test_eid

def get_ip_addrs_cmd(ip_addrs):
    if ip_addrs:
        ip_num = len(ip_addrs.split(","))
        cmd = f' --ip_num {ip_num} --ip_addrs {ip_addrs}'
        return cmd
    else:
        return ''

def exec_test_case(host_list, path, server_num=1, client_num=1, rand_host=True, **kwargs):
    log.info(f'------------- [ Test path = {path} ] ------------')
    tcp_port, _test_port = gen_random_port(host_list)
    seed = random.randint(0, 10000)
    app_num = server_num + client_num
    check = kwargs.get("check", True)
    debug = kwargs.get("debug", False)
    ip_version = kwargs.get("ip_version", None)
    case_path = kwargs.get("case_path", "''")
    _case_name = path.split('/')[-1]
    timeout = kwargs.get("timeout", 1800)
    test_port = kwargs.get("test_port", _test_port)

    ip_addrs = kwargs.get("ip_addrs", None)
    ip_addrs_cmd = get_ip_addrs_cmd(ip_addrs)

    p_list = []
    test_host = []

    if rand_host is True:
        for i in range(app_num):
            test_host.append(random.choice(host_list))
    else:
        for i in range(server_num):
            test_host.append(host_list[0])
        for i in range(server_num, app_num):
            test_host.append(host_list[1])

    if _case_name.startswith(("test_urpclib", "test_kurpc_")) and ip_version is None:
        _test_ip = f'-i {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip} ' \
            f'-I {test_host[0].test_nic1_ipv6},{test_host[-1].test_nic1_ipv6} '
    
    trans_mode = URPC_TRANS_MODE_UB

    _appid = 1
    test_dev, test_dev2 = get_test_dev(_case_name, test_host, 0)
    test_eid = get_test_eid(_case_name, test_host, 0)
    _cmd = f'{path}/test_case -a {app_num}:{_appid}:{tcp_port} -d {test_dev} -D {test_dev2} -e {test_eid} -p {test_port} -s {seed} {_test_ip}' \
        f' -x {case_path} -m {trans_mode}{ip_addrs_cmd}'
    p_list.append(test_host[0].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))


    for i in range(1, server_num):
        log.info(f'-------------------- start app{i} server ---------------------')
        _appid = i + 1
        test_dev, test_dev2 = get_test_dev(_case_name, test_host, i)
        test_eid = get_test_eid(_case_name, test_host, i)
        _cmd = f'{path}/test_case -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip}' \
            f' -d {test_dev} -D {test_dev2} -e {test_eid} -p {test_port + i} -s {seed} {_test_ip} -x {case_path} ' \
            f' -m {trans_mode}{ip_addrs_cmd}'
        p_list.append(test_host[i].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

    for i in range(server_num, app_num):
        log.info(f'-------------------- start app{i} client ---------------------')
        _appid = i + 1
        test_dev, test_dev2 = get_test_dev(_case_name, test_host, i)
        test_eid = get_test_eid(_case_name, test_host, i)
        _cmd = f'{path}/test_case -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip}' \
            f' -d {test_dev} -D {test_dev2}' \
            f' -e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path} -m {trans_mode}{ip_addrs_cmd}'
        p_list.append(test_host[i].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

    if check is True:
        for i in range(app_num):
            log.info(f'----------------- [ Test p{i + 1}.wait() ] ------------------')
            p_list[i].wait()

        for i in range(app_num):
            log.info(f'----------------- [ Test assert p{i + 1} ] ------------------')
            if p_list[i].ret != 0:
                log.error(f"exec_test_case failed! p_list[{i}].ret={p_list[i].ret}!")
                raise
        
    return p_list