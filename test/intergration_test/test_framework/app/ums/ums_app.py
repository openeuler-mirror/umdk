# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: ums app
"""
import logging
import os
import random

from common.constants import const

logging.basicConfig(levev=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))


def prepare_test_case(host_list, case_path, case_name="test_case"):
    case_cpp = os.path.join(case_path, f"{case_name}.cpp")
    public_cpp = os.path.join(case_path, "../public.cpp")
    case_out = os.path.join(case_path, "case_name")

    _cmd = f'cd {local_path};' \
           f'gcc ums_atom.cpp ../common/common.c ../common/test_log.c  ../common/test_thread_pool.c ' \
           f'{case_cpp} {public_cpp} -g  -O0 ' \
           f'-rdynamic -lstdc++  -w -fPIC  -fpermissive -o {case_path}/test_case'
    lib_list = [' -lglib-2.0', '-lpthread', f'-I {local_path}', '-I /usr/include/umdk/', \
                '-ldl', '-I /usr/include/ub/umdk/ums/']
    _cmd += " ".join(lib_list)
    p_list = []
    for host in host_list:
        p_list.append(host.exec_cmd(_cmd, background=True))
    
    for p in p_list:
        p.wait()
        if p.ret != 0:
            log.error("gcc test_case failed!")
            raise

def check_port_nouse(host_list, port):
    cmd = f'cat /tmp/netstat.txt | grep {port} | wc -l'
    buf1 = host_list[0].exec_cmd(cmd).stdout
    buf2 = host_list[1].exec_cmd(cmd).stdout
    return int(buf1[0]) + int(buf2[0])

def gen_random_port(host_list, port_num=2):
    cmd = f'netstat -an > /tmp/netstat.txt'
    for host in host_list:
        host.exec_cmd(cmd)
    for i in range(100):
        _test_port = random.randint(30000, 40000)
        log.info(f'---------- [ _test_port = {i} {_test_port} ] ----------')
        res = 0
        for j in range(port_num):
            up = _test_port + j
            ret = check_port_nouse(host_list, up)
            res += ret
        if res == 0:
            break
    return _test_port

def get_test_eid(test_host, host_idx):
    test_eid = ""
    test_eid = test_host[host_idx].test_nic1_eid
    return test_eid

def get_test_dev(test_host, host_idx):
    test_dev = test_host[host_idx].test_nic1
    return test_dev

def exec_test_case(host_list, path, server_num=1, client_num=1, **kwargs):
    log.info(f'---------- [Test path = {path} ] ----------')
    _test_port = gen_random_port(host_list)
    check = kwargs.get("check", False)
    app_num = server_num + client_num
    timeout = kwargs.get("timeout", 1800)
    test_port = kwargs.get("test_port", _test_port)
    ip_addrs = kwargs.get("ip_addrs", None)
    case_path = os.path.join(path, "test_case")
    seed = random.randint(0, 10000)

    p_list = []
    test_host = []

    test_host.append(host_list[0])
    test_host.append(host_list[1])
        
    _test_ip = f'-i {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}' \
               f' -I {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}'
    
    log.info(f'--------start app1 server--------')
    test_dev = get_test_dev(test_host, 0)
    test_eid = get_test_eid(test_host, 0)
    _cmd = f'{path}/test_case -a {app_num}:1:{test_port} -d {test_dev} ' \
           f'-e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path}'
    p_list.append(test_host[0].exec_cmd(_cmd, background=True))

    log.info(f'--------start app2 client--------')
    test_dev = get_test_dev(test_host, 1)
    test_eid = get_test_eid(test_host, 1)
    _cmd = f'{path}/test_case -a {app_num}:2:{test_port}:{test_host[0].manage_ip} -d {test_dev} ' \
           f'-e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path}'
    p_list.append(test_host[1].exec_cmd(_cmd, background=True))

    if check is True:
        for i in range(app_num):
            log.info(f'---------- [Test p{i + 1}.wait() ] ----------')
            p_list[i].wait()
        for i in range(app_num):
            log.info(f'---------- [Test assert p{i + 1} ] ----------')
            if p_list[i].ret != 0:
                log.error(f"exec_test_case failed!  p_list[{i}],ret={p_list[i].ret}!")
                raise
        p_list = []
    return p_list