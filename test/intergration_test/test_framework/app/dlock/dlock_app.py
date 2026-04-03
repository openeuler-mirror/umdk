# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: dlock app
"""
import logging
import os
import random

from common.constants import const

logging.basicConfig(levev=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))

SEPERATE_CONN = 0
UNI_CONN = 1

def prepare_test_case(host_list, case_path):
    common_path = f'{local_path}/../common'

    _cmd = f'cd {local_path};' \
           f'gcc dlock_atom.cpp {case_path}/test_case.cpp ../common/test_log.c ../common/common.c  ../common/test_thread_pool.c {case_path}/../public.cpp -g '\
           f'-rdynamic -lstdc++  -w -O0 -fPIC  -fpermissive -o {case_path}/test_case'
    lib_list = [' -lpthread', '-ldlocks', '-ldlockc', '-ldlockm', '-ldl', f'-I {local_path}', '-I /usr/include/ub/umdk/ulock/dlock/', f'-I {common_path}']
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
        tcp_port = random.randint(30000, 40000)
        log.info(f'---------- [ tcp_port = {i} {tcp_port} ] ----------')
        res = 0
        for j in range(port_num):
            up = tcp_port + j
            ret = check_port_nouse(host_list, up)
            res += ret
        if res == 0:
            break
    for i in range(100):
        udp_port = random.randint(40000, 50000)
        log.info(f'---------- [ udp_port = {i} {tcp_port} ] ----------')
        ret = check_port_nouse(host_list, up)
        if ret == 0:
            break
    return tcp_port, udp_port

def get_test_eid(test_host, host_idx):
    test_eid = ""
    test_eid = test_host[host_idx].test_nic1_eid
    return test_eid

def get_test_dev(test_host, host_idx):
    test_dev = test_host[host_idx].test_nic1
    return test_dev

def exec_test_case(host_list, path, server_num=1, client_num=1, random_host=True, **kwargs):
    log.info(f'---------- [Test path = {path} ] ----------')
    tcp_port, _test_port = gen_random_port(host_list)
    check = kwargs.get("check", True)
    seed = random.randint(0, 10000)
    app_num = server_num + client_num
    case_path = kwargs.get("case_path", "''")
    timeout = kwargs.get("timeout", 1800)
    test_port = kwargs.get("test_port", _test_port)

    p_list = []
    tp_mode_list = [SEPERATE_CONN, UNI_CONN]
    for tp_mode in tp_mode_list:
        if const.BONDING_DEV:
            if tp_mode == SEPERATE_CONN:
                continue
        test_host = []
        log.info(f'-------- tp_mode is {tp_mode} ----------')
        if random_host is True:
            for i in range(app_num):
                test_host.append(random.choice(host_list))
        else:
            for i in range(server_num):
                test_host.append(host_list[0])
            for i in range(server_num):
                test_host.append(host_list[1])
            
        _test_ip = f'-i {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}' \
                   f' -I {test_host[0].test_nic1_ip},{test_host[-1].test_nic1_ip}'
        
        _appid = 1
        test_dev = get_test_dev(test_host, 0)
        test_eid = get_test_eid(test_host, 0)
        _cmd = f'{path}/test_case -a {app_num}:{_appid}:{tcp_port} -d {test_dev} '\
               f'-e {test_eid} -p {test_port} -s {seed} {_test_ip}  -x {case_path} -m {tp_mode}'
        p_list.append(test_host[0].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

        for i in range(1, server_num):
            log.info(f'--------start app{i} server--------')
            _appid = i + 1
            test_dev = get_test_dev(test_host, i)
            test_eid = get_test_eid(test_host, i)
            _cmd = f'{path}/test_case  -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip} ' \
                   f' -d {test_dev} -e {test_eid} -p {test_port + i} -s {seed} {_test_ip}' \
                   f' -x {case_path} -m {tp_mode}'
            p_list.append(test_host[i].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))
        
        for i in range(server_num, app_num):
            log.info(f'--------start app{i} client--------')
            test_dev = get_test_dev(test_host, i)
            test_eid = get_test_eid(test_host, i)
            _cmd = f'{path}/test_case -a {app_num}:{i + 1}:{tcp_port}:{test_host[0].manage_ip} ' \
                   f'-d {test_dev} -e {test_eid} -p {test_port} -s {seed} {_test_ip} -x {case_path} -m {tp_mode}'
            p_list.append(test_host[i].exec_cmd(_cmd, background=True, timeout=timeout, port=test_port))

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