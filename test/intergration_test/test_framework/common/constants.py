# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: 
"""

import yaml
class Const(object):
    def __setattr__(self, name, value):
        if name in self.__dict__:
            print(f"change const.{name}={value}")
        self.__dict__[name] = value

const = Const()

const.CONF_FILE = "/etc/ubus_ci/test_env.yaml"
with open(const.CONF_FILE, 'r', encoding="utf-8") as load_f:
    const.CONF_INFO = yaml.safe_load(load_f)

const.TMOUT = 300
const.CASE_PATH = ""
const.CASE_DIR = ""
const.CASE_NAME = ""
const.CORE_PATH = "/Images/core/"
const.IP_VERSION = ['ip', 'ipv6']
const.URMA_MODE = ['RM', 'RC', 'UM']
const.TP_KIND = ['TP', 'CTP']
const.GCC_INCLUDE_PATH_URPC = "/usr/include/ub/umdk/urpc"
const.URPC_LIB_LOG_PATH = "/var/log/umdk/urpc"
const.UMQ_MODE = ['UB_PLUS', 'UB_IPC', 'UBMM_PLUS']
const.FLAG_LOCK_FREE = 0
const.BONDING_DEV = 1