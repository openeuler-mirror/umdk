# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: base function
"""
import logging
import os
import yaml
from common.constants import const
from common.host import  UBUSHost
from common.utils import BaseObject

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

class BaseTest(BaseObject):
    host_list = []
    test_base_flag = {"check_core" : True}
    core_list_setup = []
    used_ports = None
    free_port = 40000

    @classmethod
    def setup_class(cls):
        """
        公共setup_class函数
        解析host、记录当前core信息
        """
        log.info(f'---------- [ BaseTest setup_class ] ----------')
        cls().parse_host()
        if cls().test_base_flag["check_core"]:
            cls().get_core_list(cls().core_list_setup)

    @classmethod
    def teardown_class(cls):
        """
        公共teardown_class函数
        进程清理、校验core
        """
        log.info(f'---------- [ BaseTest teardown_class ] ----------')
        check_core_ret = 0
        for host in cls().host_list:
            for p in host.process:
                if p.need_kill:
                    p.kill()
        if cls().test_base_flag["check_core"]  and cls().check_core_list() != 0:
            check_core_ret = -1
        for host in cls().host_list:
            host.conn.close()

        cls().assertEqual(check_core_ret, 0, "CHECK CORE FAILED!")

    def setup(self, *args):
        """
        公共setup函数
        """
        log.info(f'---------- [ BaseTest setup ] ----------')

    def teardown(self, *args):
        """
        公共teardown函数
        """
        log.info(f'---------- [ BaseTest teardown ] ----------')

    def parse_host(self):
        """
        公共解析host函数：解析conf_file中的host_info,
        注册self.hostX = UBUSHost(yaml_info['host_info']['hostX'])
        """
        log.info(f'---------- [ BaseTest parse_host ] ----------')
        ip_list = []
        with open(const.CONF_FILE, 'r', encoding="utf-8") as load_f:
            yaml_info = yaml.safe_load(load_f)
        for host_name  in yaml_info['host_info'].keys():
            try:
                host = UBUSHost(host_name, yaml_info['host_info'][host_name])
            except Exception as reason:
                log.info("Failed to connect to the test environment, exiting test case.")
                raise
            self.host_list.append(host)
            exec("self.__class__." + host_name + "=host")
            ip_list.append(f"{host_name}:{host.manage_ip}")
        log.info("host list：%s" % ip_list)

    def get_core_list(self, _core_list):
        for host in self.host_list:
            ret = host.exec_cmd(f"ls {const.CORE_PATH}").stdout
            _core_list.append(ret)

    def rename_core(self, host, core_name):
        new_core_name = core_name
        if const.CASE_NAME:
            core_name_split = core_name.strip("core.test_case")
            new_core_name = const.CASE_NAME + "_" + core_name_split
            self.host_list[host].exec_cmd(f"mv {const.CORE_PATH}{core_name} {const.CORE_PATH}{new_core_name}")
        return new_core_name

    def check_core_list(self):
        _core_list = []
        self.get_core_list(_core_list)
        _new_core_list = []
        for host in range(len(self.host_list)):
            for _core in _core_list[host].split():
                if _core not in self.core_list_setup[host]:
                    core_name = self.rename_core(host, _core)
                    _new_core_list.append(f"{self.host_list[host].manage_ip}_{core_name}")
        if len(_new_core_list) != 0:
            log.error(f"new core list = {_new_core_list}")
            return -1
        return 0

    def get_free_port(self):
        """
        获取一个没使用的端口，并且状态不是TIME_WAIT
        """
        if self.used_ports is None:
            self.used_ports = set()
            host_list = self.host_list
            for host in host_list:
                _cmd = "netstat -antp | awk '/^tcp/ || / TIME_WAIT / {print $4}' | awk -F ':' '{print $NF}' | sort | uniq"
                for port in host.exec_cmd(_cmd, silence=True).stdout.split("\r\n"):
                    if port.isdigit():
                        self.used_ports.add(int(port))
            log.info(f"self.used_ports = {self.used_ports}")

        for port in range(self.free_port, 65535):
            if port not in self.used_ports:
                self.free_port = port + 1
                if self.free_port >= 60000:
                    self.free_port = 40000
                return port