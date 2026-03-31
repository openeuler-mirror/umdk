# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: base function
"""

import datetime
import logging
import os
import signal
import time

from common.constants import const
from common.utils import BaseObject, parse_cpu_list, convert_set_str_to_int
from fabric import Connection
from func_timeout import func_timeout, FunctionTimedOut

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()
local_path = os.path.dirname(os.path.abspath(__file__))

class ResourceInfo(object):
    def __init__(self, res, pid, timeout, interval=1):
        path = os.path.join(local_path, "check_resource.py")
        cmd = f"python {path} {pid} {interval}"
        self.p = res.host.exec_cmd(cmd, background=True, timeout=timeout, silence=2)
        self.info_list = []

    def parse_stdout(self):
        for _ in range(len(self.p.p.runner.stdout)):
            msg = self.p.p.runner.stdout[0].split('\t')
            msg[1] = int(msg[1])
            msg[2] = float(msg[2])
            msg[3] = int(msg[3])
            self.info_list.append(msg)
            del self.p.p.runner.stdout[0]

    @property
    def info(self):
        self.parse_stdout()
        return self.info_list

    @property
    def mem_avg(self):
        self.parse_stdout()
        value_list = [row[1] for row in self.info_list]
        if len(value_list) == 0:
            return 0
        else:
            return sum(value_list) / len(value_list)

    @property
    def mem_max(self):
        self.parse_stdout()
        value_list = [row[1] for row in self.info_list]
        if len(value_list) == 0:
            return 0
        else:
            return max(value_list)

    @property
    def cpu_avg(self):
        self.parse_stdout()
        value_list = [row[2] for row in self.info_list]
        if len(value_list) == 0:
            return 0
        else:
            return sum(value_list) / len(value_list)

    @property
    def cpu_max(self):
        self.parse_stdout()
        value_list = [row[2] for row in self.info_list]
        if len(value_list) == 0:
            return 0
        else:
            return max(value_list)
   
    @property
    def fd_max(self):
        self.parse_stdout()
        value_list = [row[3] for row in self.info_list]
        if len(value_list) == 0:
            return 0
        else:
            return max(value_list)

class BackgroundCmdRes(BaseObject):
    def __init__(self, host, p, timeout, silence, log_path, pid, port, exp_ret):
        self.host = host
        self.p = p
        self.command = self.p.command
        self.timeout = timeout
        self.reason = None
        self.need_kill = 1
        self.silence = silence
        self.log_path = log_path
        self.pid = pid
        self.port = port
        self.res_info = {}
        self.exp_ret = exp_ret

    @property
    def process_is_finished(self):
        return self.p.runner.process_is_finished or self.p.runner.has_dead_threads

    @property
    def process_is_running(self):
        return not self.process_is_finished

    @property
    def stdout(self):
        return "".join(self.p.runner.stdout)

    @property
    def stderr(self):
        return "".join(self.p.runner.stderr)

    @property
    def ret(self):
        return self.p.runner.returncode()
    
    @property
    def all_pid(self):
        return self.host.get_child_pid(self.pid)

    def check_resource(self,timeout=0, interval=1):
        if timeout == 0:
            timeout = self.timeout
        self.res_info = {}
        for pid in self.all_pid:
            self.res_info[pid] = ResourceInfo(self, pid, timeout, interval)
        return self.res_info

    def stop_check_resource(self):
        for value in self.res_info.values():
            value.p.kill()

    def kill(self):
        try:
            self.stop_check_resource()
            if not self.process_is_finished:
                self.p.runner.send_interrupt(signal.SIGKILL)
            self.p.runner.kill()
        except Exception as reason:
            log.info(f"kill failed!!!reason={reason}")
        self.wait()

    def wait(self, timeout=0):
        if timeout == 0:
            timeout = self.timeout
        try:
            if self.process_is_finished is False:
                func_timeout(timeout, self.p.runner.wait)
        except FunctionTimedOut:
            if not self.process_is_finished:
                self.p.runner.send_interrupt(signal.SIGKILL)
            self.p.runner.kill()
            log.info("wait timeout, kill process !!!")
        finally:
            pass

        try:
            self.reason = self.p.join()
        except Exception as reason:
            self.reason = reason
        finally:
            pass

        self.need_kill = 0
        if self.silence == 0:
            log.info(f"[ {self.host.manage_ip} exec_cmd end ] cmd={self.p.command} ret={self.ret} stdout=\n{self.stdout}")
        if self.log_path is not None:
            self.log_path.close()
        if self.exp_ret is not None:
            self.assertEqual(self.ret, self.exp_ret)

    def stdin(self, msg):
        log.info(f"stdin '{msg}'")
        self.p.runner.write_proc_stdin(msg)

    def match_keyword(self, keyword):
        count = 0
        for line in self.stdout.split('\n'):
            if keyword in line:
                count = count + 1
        return count

    def expect(self, keyword, msg=None, now=False, timeout=20, interval=0.1):
        log.info(f"expect '{keyword}' in stdout")
        if now:
            key_cnt_start = self.match_keyword(keyword)
        else:
            key_cnt_start = 0

        for _ in range(int(timeout / interval)):
            key_cnt = self.match_keyword(keyword)
            if key_cnt > key_cnt_start:
                if msg is not None:
                    self.stdin(msg)
                return 0
            if self.process_is_finished:
                break
            time.sleep(interval)
        log.info(f"expect timeout or process is finished!!!")
        return -1


class UBUSHost(BaseObject):
    def __init__(self, host_name, host_dict, connect=True):
        self.name = host_name
        self.info = host_dict
        self.conn = None
        self.conn_pid = -1
        self.process = []
        self.ns_list = []

        self.bmc = self.info.get('bmc')
        self.manage_nic = self.info.get('manage_nic')
        self.manage_nic_dev = self.info.get('manage_nic').get('name')
        self.manage_ip = self.info.get('manage_nic').get('ip')
        self.manage_mac = self.info.get('manage_nic').get('mac')
        self.user = self.info.get('user')
        self.passwd = self.info.get('passwd')
        self.ssh_ip = self.info.get('ssh_ip') if self.info.get('ssh_ip') is not None else self.manage_ip
        self.ssh_port = self.info.get('ssh_port') if self.info.get('ssh_port') is not None else 22
        self.isolcpu = parse_cpu_list(self.info.get('isolcpu'))
        self.env_type = self.info.get('env_type')
        self.arch = self.info.get('arch')

        self.test_nic = {}
        if self.info.get('test_nic1') is not None:
            self.test_nic[1] = self.info.get('test_nic1')
            self.test_nic1 = self.info.get('test_nic1').get('name')
            self.test_nic1_dev = self.info.get('test_nic1').get('dev')
            self.test_nic1_gid = self.info.get('test_nic1').get('gid')
            self.test_nic1_ip = self.info.get('test_nic1').get('ip')
            self.test_nic1_ipv6 = self.info.get('test_nic1').get('ipv6')
            self.test_nic1_eid = self.info.get('test_nic1').get('eid')
        if self.info.get('test_nic2') is not None:
            self.test_nic[2] = self.info.get('test_nic2')
            self.test_nic2 = self.info.get('test_nic2').get('name')
            self.test_nic2_dev = self.info.get('test_nic2').get('dev')
            self.test_nic2_gid = self.info.get('test_nic2').get('gid')
            self.test_nic2_ip = self.info.get('test_nic2').get('ip')
            self.test_nic2_ipv6 = self.info.get('test_nic2').get('ipv6')
            self.test_nic2_eid = self.info.get('test_nic2').get('eid')

        if connect:
            self.connect()

    def connect(self):
        try:
            self.conn = Connection(host=self.ssh_ip, port=self.ssh_port, user=self.user, inline_ssh_env=True,
                                    connect_kwargs={'password':self.passwd}, connect_timeout=60)
        except Exception as reason:
            log.error(f"remote_exec_cmd task execute failed, reason:{reason}!!!")
        finally:
            pass
        
        pid = self.exec_cmd("ps --no-headers -eo ppid -fp $$", silence=2)
        try:
            self.conn_pid = int(pid.stdout)
        except Exception as reason:
            self.conn_pid = -1
        log.info(f"Connect {self.manage_ip} success! conn_pid = {self.conn_pid}")

    def get_child_pid(self, pid):
        if pid == -1:
            return set()
        cmd = f"pstree -T -a -p {pid}"
        self.exec_cmd(cmd)
        cmd = f"pstree -T -p {pid} | grep -o '([0-9]\+)' | grep -o '[0-9]\+'"
        try:
            pid_set = set(self.exec_cmd(cmd, silence=2).stdout.split("\r\n"))
        except Exception as reason:
            pid_set = set()
        return convert_set_str_to_int(pid_set)

    def get_process_pid(self):
        if self.conn_pid  == -1:
            return set()
        cmd = f"pgrep -P {self.conn_pid}"
        try:
            pid_set = set(self.exec_cmd(cmd, silence=2).stdout.split("\r\n"))
        except Exception as reason:
            pid_set = set()
        return convert_set_str_to_int(pid_set)

    def exec_cmd(self, cmd, background=False, timeout=0, log_path=None, env=None, silence=0, get_pid=True,
                 port=None, exp_ret=None):
        """
        执行命令行
        :param cmd:用例执行的命令行
        :param background:是否后台执行
        :param timeout:超时时间,单位秒
        :param log_path:日志保存到指定路径
        :param silence:控制台是否打印日志 0:打印执行的命令和结果 1:打印执行的命令，不打印结果 2:什么日志都不打
        :param get_pid:是否获取pid，用于配合check_resource监控内存、cpu占用
        """
        if timeout == 0:
            timeout = const.TMOUT
        cmd_args = f"cmd='{cmd}' background={background} timeout={timeout} log_path={log_path} env={env}"
        if log_path is not None:
            log_path = open(log_path, "a+", encoding="utf-8")
        if background:
            if get_pid:
                pid_set1 = self.get_process_pid()
            res = self.conn.run(cmd, asynchronous=True, timeout=timeout, out_stream=log_path, err_stream=log_path,
                                warn=True, pty=True, env=env)
            pid = -1
            if get_pid:
                pid_set2 = self.get_process_pid()
                pid_diff = pid_set2.difference(pid_set1)
                if len(pid_diff) == 1:
                    pid = pid_diff.pop()
            res = BackgroundCmdRes(self, res, timeout, silence, log_path, pid, port, exp_ret)
            if silence <= 1:
                log.info(f" [ {self.manage_ip}  exec_cmd ] {cmd_args} pid={pid}")
            self.process.append(res)
        else:
            if silence <= 1:
                log.info(f" [ {self.manage_ip}  exec_cmd ] {cmd_args}")
            res = None
            try:
                res  = self.conn.run(cmd, hide=True, timeout=timeout, out_stream=log_path, err_stream=log_path,
                                        warn=True, pty=True, env=env)
                res.ret = res.return_code
                if silence == 0:
                    log.info(f" [ {self.manage_ip}  exec_cmd end ] {cmd_args} ret={res.ret} stdout=\n{res.stdout}")
                if log_path is not None:
                    log_path.close()
            except Exception as reason:
                log.error(f" [ {self.manage_ip} exec_cmd failed ] cmd={cmd} reason:{reason}!!!")
            finally:
                pass
            if exp_ret is not None:
                self.assertEqual(res.ret, exp_ret)
        return res

    def try_put(self, src_path, dst_host, dst_path):
        _cmd = f"scp -P {dst_host.ssh_port} -r {src_path} {dst_host.ssh_ip}:{dst_path}"
        self.exec_cmd(_cmd)

    def try_get(self, src_path, src_host, dst_path):
        _cmd = f"scp -P {src_host.ssh_port} -r  {src_host.ssh_ip}:{src_path}/tsan* {dst_path}"
        self.exec_cmd(_cmd)

    def capture_log(self, log_path, output=None, silence=2):
        return self.exec_cmd(f"tail -n 0 -F {log_path}", background=True, log_path=output, silence=silence)

    def reconnect(self, wait_time=30, timeout=0):
        if timeout == 0:
            timeout = const.TMOUT
        start_time = datetime.datetime.now()
        time.sleep(wait_time)
        timeout = timeout - wait_time
        i = 0
        while True:
            try:
                self.connect()
            except Exception:
                i = i + 1
                log.error(f"[ {self.manage_ip} ] 第{i}次连接恢复失败")
            use_time = (datetime.datetime.now() - start_time).total_seconds()
            if self.conn.is_connected:
                log.info(f"[ {self.manage_ip} ] 连接恢复成功！耗时{use_time}秒")
                break
            if use_time > timeout:
                log.error(f"[ {self.manage_ip} ] 连接恢复失败！")
                break
            time.sleep(10)