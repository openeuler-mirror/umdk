# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: base function
"""
import inspect
import logging
import os

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

def get_caller_info():
    caller = inspect.currentframe().f_back.f_back
    filename  = os.path.basename(caller.f_code.co_filename)
    linerno = caller.f_lineno
    return f"[ {filename}:{linerno} ]"

def parse_cpu_list(cpu_txt):
    """
    解析cpu，例如1-10,20,30
    """
    cpu_list = []
    if cpu_txt is not None:
        for cpu in cpu_txt.split(","):
            if '-' in cpu:
                c = cpu.split("-")
                cpu_list.extend(i for i in range(int(c[0]), int(c[1]) +1))
            else:
                cpu_list.append(int(cpu))
    return cpu_list

def convert_set_str_to_int(set_str):
    new_set = set()
    for s in set_str:
        try:
            num = int(s)
            new_set.add(num)
        except ValueError:
            pass
    return new_set

class BaseObject(object):
    @staticmethod
    def adapt_factor(args1, args2):
        try:
            if isinstance(args1, str):
                args1 = float(args1)
            if isinstance(args2, str):
                args2 = float(args2)
        except ValueError:
            return str(args1), str(args2)
        return args1, args2

    @staticmethod
    def assertTrue(flag, msg=""):
        log.info(f'{get_caller_info()} assert {flag}')
        assert flag is True, msg 

    @staticmethod
    def assertFalse(flag, msg=""):
        log.info(f'{get_caller_info()} assert {flag}')
        assert flag is False, msg 

    def assertEqual(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} = {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 == args2, msg 
    
    def assertNotEqual(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} != {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 != args2, msg 

    def assertGreater(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} > {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 > args2, msg 

    def assertGreaterEqual(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} >= {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 >= args2, msg 

    def assertLess(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} < {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 < args2, msg

    def assertLessEqual(self, args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} <= {args2}')
        args1, args2 = self.adapt_factor(args1, args2)
        assert args1 <= args2, msg

    @staticmethod
    def assertIn(args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} in {args2}')
        assert str(args1) in str(args2), msg

    @staticmethod
    def assertNotIn(args1, args2, msg=""):
        log.info(f'{get_caller_info()} assert {args1} not in {args2}')
        assert str(args1) not in str(args2), msg
