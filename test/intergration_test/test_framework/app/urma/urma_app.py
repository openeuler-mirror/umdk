# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma test_framework
"""

import logging
import os
import random

from common.constants import const

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))

def prepare_test_case_new(host_list, case_path, case_name="test_case"):
    case_c = os.path.join(case_path, f"{case_name}.c")
    public_c = os.path.join(case_path, "../public.c")
    case_out = os.path.join(case_path, case_name)

    if not os.path.exists(public_c):
        public_c = ""
    _cmd = f'cd {local_path};' \
           f'gcc urma_atom.c ../common/common.c ../common/test_log.c ../common/test_thread_pool.c ' \
           f' {case_c} {public_c} -g -O0 ' \
           f'-rdynamic -lstdc++ -w -fPIC -fpermissive -o {case_out} '

    lib_list = ['-lurma', '-lglib-2.0', '-lpthread', f'-I {local_path}', '-I /usr/include/umdk/', \
                '-ldl', '-I /usr/include/ub/umdk/urma/']
    _cmd += " ".join(lib_list)

    ret = host_list[0].exec_cmd(_cmd)
    if ret.ret != 0:
        log.error(f"gcc {case_name} failed!")
        raise
    for i in range(1, len(host_list)):
        if host_list[i].manage_ip != host_list[0].manage_ip:
            host_list[i].exec_cmd(f"mkdir -p {case_path};rm -f {case_out}")
            host_list[0].try_put(case_out, host_list[i], case_out)

def urma_admin_show_res(self):
    res_dict = {}
    _cmd = f"urma_admin show_res -d udma2 -R 12|grep '_cnt\s*:'"
    ret = self.exec_cmd(_cmd).stdout
    for line in ret.replace(' ', '').split('\n'):
        kv = line.split(':')
        try:
            res_dict[kv[0]] = int(kv[1])
        except Exception as reason:
            pass
    return res_dict

def urma_admin_show_res_dev_ctx(self):
    res_list = []
    host_list = self.host_list

    for host in host_list:
        res_list.append(urma_admin_show_res(host))
    return res_list

def compare_res_list(list1, list2):
    # Check for resource leakage before and after test case execution
    for i, (d1, d2) in enumerate(zip(list1, list2)):
        for k, v2 in d2.items():
            if v2 > d1.get(k, 0):
                print(f"ERROR: host{i} {k}: {d1.get(k, 0)} → {v2}")

def _get_host_list_for_type(self, host_list, app_num):
    if host_list:
        return host_list
    # Default to 2 nodes if not specified
    return [self.host1] + [self.host2] * (app_num - 1)

def exec_test_case(self, path, app_num=2, mode=None, tp_kind=None, env=None, host_list=None, run_mode='async'):
    # Set environment variables and default parameters
    mode = mode or const.URMA_MODE
    mode = [m for m in mode if m in const.URMA_MODE]
    kind = tp_kind or const.TP_KIND
    kind = [k for k in kind if k in const.TP_KIND]
    if host_list:
        app_num = len(host_list)

    log.info(f'---------- [ Test path = {path} ] ----------')

    case_path = os.path.join(path, "test_case")
    seed = random.randint(0, 10000)

    # Special environment configuration
    before_list = urma_admin_show_res_dev_ctx(self)
    p_list = []
    tp_mode_dict = {'RM': 0, 'RC': 1, 'UM': 2}
    tp_kind_dict = {'TP': 0, 'CTP': 1}

    host_list = _get_host_list_for_type(self, host_list, app_num=app_num)
    # Get device name list
    dev_list = [
        host_list[i].test_nic[1]['name']
        for i in range(app_num)
    ]

    for k in kind:
        tp_kind = tp_kind_dict[k]
        for m in mode:
            tp_mode = tp_mode_dict[m]

            # Bonding device single path only supports RC+TP. Chip does not support UM type CTP.
            if host_list[0].test_nic[1]['name'] == 'bonding_dev_0':
                if (k == 'TP' and m != 'RC') or (k == 'CTP' and m == 'UM'):
                    continue

            eid = 0 if host_list[0].test_nic[1]['name'] == 'bonding_dev_0' else 7
            tcp_port = self.get_free_port()

            _cmd = f'{case_path} -a {app_num}:1:{tcp_port} -d {dev_list[0]} -s {seed} -m {tp_mode} -x {eid} -k {tp_kind}'
            p_list.append(host_list[0].exec_cmd(_cmd, background=True, env=env))
            for i in range(1, app_num):
                _cmd = f'{case_path} -a {app_num}:{i + 1}:{tcp_port}:{host_list[0].manage_ip} ' \
                       f'-d {dev_list[i]} -s {seed} -m {tp_mode} -x {eid} -k {tp_kind}'
                p_list.append(host_list[i].exec_cmd(_cmd, background=True, env=env))

            # Wait for current combination to finish in sync mode
            if run_mode == 'sync':
                for p in p_list:
                    if not p.process_is_finished:
                        p.wait()
    if run_mode != 'background':
        for p in p_list:
            if p.need_kill:
                p.wait()
        for p in p_list:
            self.assertEqual(p.ret, 0)
        after_list = urma_admin_show_res_dev_ctx(self)
        compare_res_list(before_list, after_list)
    return p_list