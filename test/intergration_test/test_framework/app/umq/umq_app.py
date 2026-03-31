# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: umq test_framework
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


UMQ_TRANS_MODE_IP = 0
UMQ_TRANS_MODE_UB = 1
UMQ_TRANS_MODE_IB = 2
UMQ_TRANS_MODE_IPC = 3
UMQ_TRANS_MODE_UB_PLUS = 5
UMQ_TRANS_MODE_UBMM_PLUS = 7

def prepare_test_case(host_list, case_path):
    case_cpp = os.path.join(case_path, "test_case.cpp")
    public_cpp = os.path.join(case_path, "../public.cpp")
    case_out = os.path.join(case_path, "test_case")
    case_log = os.path.join(case_path, "*.log")
    _cmd = f'cd {local_path};' \
        f'g++ ../common/common.c ../common/test_log.c ../common/test_thread_pool.c ' \
        f'umq_atom.cpp {case_cpp} -g -O0 -o {case_out} '
    if os.path.exists(public_cpp):
        _cmd += f"{public_cpp} "
    
    lib_list = ['-lglib-2.0', '-lpthread', '-lcrypto', '-lumq', '-lumq_buf',
                f'-I {local_path}', f'-I {case_path}/../',
                f'-I /usr/include/ub/umdk/urpc/umq/']
    _cmd += " ".join(lib_list)
    _cmd += f" && rm -rf {case_log}"

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

    
def get_trans_mode(mode):
    trans_mode = UMQ_TRANS_MODE_IP
    if mode == 'UB':
        trans_mode = UMQ_TRANS_MODE_UB
    if mode == 'IB':
        trans_mode = UMQ_TRANS_MODE_IB
    if mode == 'UB_PLUS':
        trans_mode = UMQ_TRANS_MODE_UB_PLUS
    if mode == 'UBMM_PLUS':
        trans_mode = UMQ_TRANS_MODE_UBMM_PLUS
    if mode == 'UB_IPC':
        trans_mode = UMQ_TRANS_MODE_IPC
    return trans_mode


def get_test_dev(case_name, mode, test_host, host_idx):
    test_dev2 = None

    if hasattr(test_host[0], "test_nic2"):
        test_dev = test_host[host_idx].test_nic2 if mode == 'IB' or mode == 'UB' else test_host[host_idx].test_nic2_dev
    else:
        test_dev = test_host[host_idx].test_nic1 if mode == 'IB' or mode == 'UB' else test_host[host_idx].test_nic1_dev
        test_dev2 = test_host[host_idx].test_nic1_dev if mode == 'IB' or mode == 'UB' else test_host[host_idx].test_nic1
    return test_dev, test_dev2


def get_test_eid(case_name, mode, test_host, host_idx):
    test_eid = ""
    if hasattr(test_host[0], "test_nic2"):
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
    log.info(f'---------- [ Test path = {path}] ----------')
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
    single_host = kwargs.get("single_host", False)
    mode = kwargs.get("mode", [])

    ip_addrs = kwargs.get("ip_addrs", None)
    ip_addrs_cmd = get_ip_addrs_cmd(ip_addrs)

    p_list = []
    
    for _mode in  const.UMQ_MODE:
        if mode != [] and _mode not in mode:
            continue
        test_host = []
        log.info(f'---------- [ mode is {_mode}] ----------')
        dev_type = _mode
        if 'UB' in _mode:
            rand_host = False
            dev_type = 'UB'
        if rand_host is True:
            for i in range(app_num):
                test_host.append(random.choice(host_list))
        else: 
            for i in range(server_num):
                test_host.append(host_list[0])
            for i in range(server_num, app_num):
                if 'IPC' in _mode:
                    test_host.append(host_list[0])
                else:
                    test_host.append(host_list[1])
        
        _test_ip = f'-i {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip} ' \
            f'-I {test_host[0].test_nic1_ipv6},{test_host[-1].test_nic1_ipv6} '

        trans_mode = get_trans_mode(_mode)

        _appid = 1
        test_dev, test_dev2 = get_test_dev(_case_name, dev_type, test_host, 0)
        test_eid = get_test_eid(_case_name, dev_type, test_host, 0)
        _cmd = f'{path}/test_case -a {app_num}:{_appid}:{tcp_port} -d {test_dev} -D {test_dev2}' \
            f' -e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path} -m {trans_mode}{ip_addrs_cmd}'
        p_list.append(test_host[0].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))


        for i in range(1, server_num):
            log.info(f'-------------------- start app{i} server ---------------------')
            _appid = i + 1
            test_dev, test_dev2 = get_test_dev(_case_name, dev_type, test_host, i)
            test_eid = get_test_eid(_case_name, dev_type, test_host, i)
            _cmd = f'{path}/test_case -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip}' \
                f' -d {test_dev} -D {test_dev2} -e {test_eid} -p {test_port + i} -s {seed} {_test_ip}' \
                f'-x {case_path} -m {trans_mode}{ip_addrs_cmd}'
            p_list.append(test_host[i].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

        for i in range(server_num, app_num):
            log.info(f'-------------------- start app{i} client ---------------------')
            _appid = i + 1
            test_dev, test_dev2 = get_test_dev(_case_name, dev_type, test_host, i)
            test_eid = get_test_eid(_case_name, dev_type, test_host, i)
            _cmd = f'{path}/test_case -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip}' \
                f' -d {test_dev} -D {test_dev2} -e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path} ' \
                f'-m {trans_mode}{ip_addrs_cmd}'
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
            p_list = []
        return p_list
            