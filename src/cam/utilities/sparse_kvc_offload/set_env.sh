# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

#!/bin/bash
## The IP addresses of all nodes. Ensure the first IP is the master, and multiple node IPs are separated by spaces
export IPs=('xxx.xxx.xxx.xxx' 'xxx.xxx.xxx.xxx')

rm -rf /root/atc_data/
SCRIPT_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# In umdk the runnable stack (executor/ module/ models/) is self-contained under
# this directory, so PYTHONPATH points at the script dir itself instead of the
# original repo root.
export PYTHONPATH=$PYTHONPATH:$SCRIPT_PATH
source /usr/local/Ascend/driver/bin/setenv.bash
CANN_PATH=/usr/local/Ascend/ascend-toolkit/latest
export ASCEND_HOME_PATH=$CANN_PATH
