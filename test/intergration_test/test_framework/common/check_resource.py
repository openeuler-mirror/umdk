# -*- coding: utf-8 -*-
"""
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description:
"""

import datetime
import sys
import psutil

pid = int(sys.argv[1])
interval = float(sys.argv[2])
try:
    p = psutil.Process(pid)
except Exception as reason:
    Exception

while True:
    try:
        cpu = p.cpu_percent(interval=interval)
        mem = p.memory_info().rss
        fds = p.num_fds()
        t = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S.%f")
        print(f"{t}\t{mem}\t{cpu}\t{fds}")
    except Exception as reason:
        break
    finally:
        pass