#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind setup options support file
# Create: 2025-11-29
# Note:
# History: 2025-11-29 create pybind setup options support file
#

import os
import glob
import subprocess

from wheel.bdist_wheel import bdist_wheel

# valid manylinux tags
manylinux_tags = [
    "manylinux1_x86_64",
    "manylinux2010_x86_64",
    "manylinux2014_x86_64",
    "manylinux2014_aarch64",
    "manylinux_2_5_x86_64",
    "manylinux_2_12_x86_64",
    "manylinux_2_17_x86_64",
    "manylinux_2_17_aarch64",
    "manylinux_2_24_x86_64",
    "manylinux_2_24_aarch64",
    "manylinux_2_27_x86_64",
    "manylinux_2_27_aarch64",
    "manylinux_2_28_x86_64",
    "manylinux_2_28_aarch64",
    "manylinux_2_31_x86_64",
    "manylinux_2_31_aarch64",
    "manylinux_2_34_x86_64",
    "manylinux_2_34_aarch64",
    "manylinux_2_35_x86_64",
    "manylinux_2_35_aarch64",
]
is_manylinux = os.environ.get("AUDITWHEEL_PLAT", None) in manylinux_tags

print("is_manylinux", is_manylinux)

class BdistWheelBuild(bdist_wheel):
    dependencies = []
    def run(self):
        self.run_command('egg_info')
        bdist_wheel.run(self)
        if is_manylinux:
            file = glob.glob(os.path.join(self.dist_dir, "*.whl"))[0]
            auditwheel_cmd = ["auditwheel", "-v", "repair", "-w", self.dist_dir, file]
            for i in self.dependencies:
                auditwheel_cmd += ["--exclude", i]
            try:
                print("auditwheel_cmd:", auditwheel_cmd)
                subprocess.run(auditwheel_cmd, check=True, stdout=subprocess.PIPE)
            finally:
                for entry in glob.glob(os.path.join(self.dist_dir, "*.whl")):
                    if "manylinux" not in entry:
                        print("remove:", entry)
                        os.remove(entry)
                    else:
                        print("remain:", entry)