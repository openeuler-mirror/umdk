# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma test_framework
"""

import logging
import re
import os
import random
import pathlib
from datetime import datetime
from common.constants import const
from ubus_test.base_test import BaseTest


logging.basicConfig(level=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))


class URMAFeature(BaseTest):
    @classmethod
    def setup_class(cls):
        log.info(f'-----------[ URMAFeature setup_class ] -------------')
        super(URMAFeature, cls).setup_class()

    def setup(self):
        log.info('-----------[ URMAFeature setup ] -------------')

        log.info('-----------[ Collect log setup ] -------------')
        # start collect kernal log and user log
        self.kernal_log_res = []
        self.user_log_res = []
        self.case_log_dir = ""


        for host in self.host_list:
            kres = self.collect_kernal_mode_log(host)
            self.kernal_log_res.append(kres)
            ures = self.collect_user_mode_log(host)
            self.user_log_res.append(ures)
        self.case_log_dir = self.create_case_log_dir()

        return

    def teardown(self):
        log.info('-----------[ URMAFeature teardown ] -------------')

        log.info('-----------[ Collect log teardown ] -------------')
        # close collect kernal log and user log
        self.stop_kernal_mode_log(self.kernal_log_res)
        self.stop_user_mode_log(self.user_log_res)

        for host in self.host_list:
            self.collect_all_case_log(host, self.case_log_dir)



    def collect_kernal_mode_log(self, host):
        log.info(f"host: {host.ssh_ip} start collect kernal log")
        # -W: wait and print only new messages
        cmd = f"dmesg -T -W > {host.ssh_ip}_dmesg.log"
        res = host.exec_cmd(cmd, background=True)
        return res

    def stop_kernal_mode_log(self, res_list):
        # stop collect kernal log
        for kernal_log in res_list:
            log.info(f"host: {kernal_log.host.ssh_ip} stop collect kernal log")       
            kernal_log.kill()

    def collect_user_mode_log(self, host):
        log.info(f"host: {host.ssh_ip} start collect user log")
        cmd = f"tail -f /var/log/messages > {host.ssh_ip}_messages.log"
        res = host.exec_cmd(cmd, background=True)
        return res

    def stop_user_mode_log(self, res_list):
        for user_log in res_list:
            log.info(f"host: {user_log.host.ssh_ip} stop collect user log")
            user_log.kill()

    def create_case_log_dir(self):
        # create case run dir
        if not os.path.exists(const.CASE_LOG_PATH):
            os.makedirs(const.CASE_LOG_PATH)

        current_date = datetime.now().strftime("%Y%m%d")
        log_dir = os.path.join(const.CASE_LOG_PATH, current_date)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        case_path = pathlib.Path(const.CASE_PATH)
        case_path_list = list(case_path.parts)
        index = case_path_list.index('test_suites')

        project_root = case_path_list[index -2]
        user_name = case_path_list[index -3]
        user_log_dir = os.path.join(log_dir, f"{user_name}-{project_root}")
        if not os.path.exists(user_log_dir):
            os.makedirs(user_log_dir)

        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        case_name = case_path_list[-2]
        case_log = f"{current_time}_{case_name}"

        case_log_dir = os.path.join(user_log_dir, case_log)
        if not os.path.exists(case_log_dir):
            os.makedirs(case_log_dir)
        log.info(f"************************ create case log dir: {case_log_dir}")
        return case_log_dir

    def collect_all_case_log(self, host, case_log_dir):
        # collect all logs
        case_path = pathlib.Path(const.CASE_PATH).parent 
        case_log_list = case_path.glob("*.log")
        dmesg_file = f"{host.ssh_ip}_dmesg.log"
        messages_file = f"{host.ssh_ip}_messages.log"
        # 1. collect all log
        if host == self.host1:
            for case_log in case_log_list:
                host.get_file(case_log, host, case_log_dir)
            # 1. collect kernal log
            host.get_file(dmesg_file, host, case_log_dir)
            # 2. collect user log
            host.get_file(messages_file, host, case_log_dir)
        else:
            host.put_file(dmesg_file, self.host1, case_log_dir)
            host.put_file(messages_file, self.host1, case_log_dir)