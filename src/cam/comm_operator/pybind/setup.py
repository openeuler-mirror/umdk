#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind setup file
# Create: 2025-12-11
# Note:
# History: 2025-12-11 create pybind setup file
#

import os
import sys
import torch
import platform
import importlib.util

sys.path.append(os.path.join(os.path.dirname(__file__), "./pytorch_extension"))
from bdist_wheel_build import BdistWheelBuild
from setuptools import setup, find_packages
from torch.utils.cpp_extension import BuildExtension
from torch_npu.utils.cpp_extension import NpuExtension

# 格式: V版本.R版本.C版本.B版本
env_version = os.getenv("CAM_WHL_VERSION", "208.1.0.B001")

torch_path = os.path.dirname(torch.__file__)
torch_npu_spec = importlib.util.find_spec("torch_npu")
torch_npu_path = os.path.dirname(torch_npu_spec.origin)
print(f"torch_path: {torch_path}")
print(f"torch_npu_path: {torch_npu_path}")
PYTORCH_NPU_INSTALL_PATH = os.path.dirname(os.path.abspath(torch_npu_spec.origin))
architecture = str(platform.machine())
if architecture.startswith("x86"):
    arch = "x86_64"
else:
    arch = "aarch64"

env_names = ["ASCEND_HOME_PATH"]
for env_name in env_names:
    if env_name not in os.environ:
        print(f"{env_name} is not in env, please export {env_name} first")
compile_args = [
    "-I" + os.path.join(PYTORCH_NPU_INSTALL_PATH, "include/third_party/acl/inc"),
    "-fPIC", "-fstack-protector-strong", "-w",
    "-D_FORTIFY_SOURCE=2",
]
if "BUILD_TYPE" in os.environ and os.environ.get("BUILD_TYPE") == "Debug":
    compile_args.extend(["-g", "-O0"])
else:
    compile_args.extend(["-O2"])
if "ENABLE_COV" in os.environ and os.environ.get("ENABLE_COV") == "1":
    compile_args.extend(["-coverage"])
print(compile_args)

exts = []
ext1 = NpuExtension(
    name="umdk_cam_op_lib",
    include_dirs=[
        os.path.join(torch_npu_path, "include"),
        os.path.join(torch_npu_path, "include/third_party/acl/inc/acl/"),
        os.path.join(torch_npu_path, "include/third_party/acl/inc"),
        os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "include"),
        os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "include", "hccl"),
        os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "include", "experiment", "runtime"),
        os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "include", "experiment", "msprof"),
        os.path.join(torch_path, "include"),
        os.path.join(os.path.dirname(__file__), "./", "pytorch_extension")],

    library_dirs=[
        os.path.join(torch_path, "lib"),
        os.path.join(torch_npu_path, "lib"),
        os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "lib64")],
    libraries=[
        "torch_npu",
        "gcov",
        "runtime",
        "torch",
        "ascendcl",
        "profapi"],
    sources=["./fused_deep_moe.cpp",
             "./get_dispatch_layout.cpp",
             "./moe_dispatch_prefill.cpp",
             "./moe_combine_prefill.cpp",
             "./moe_dispatch_shmem.cpp",
             "./moe_combine_shmem.cpp",
             "./pybind.cpp",
             "./pytorch_extension/NPUBridge.cpp",
             "./pytorch_extension/NPUStorageImpl.cpp",
            ],
    
    extra_compile_args = compile_args,
    extra_link_args = [
        "-s", "-Wl,-z,relro,-z,now"
    ],
)

exts.append(ext1)
BdistWheelBuild.dependencies = ["libc10.so", "libtorch.so", "libtorch_cpu.so", "libtorch_python.so", "libtorch_npu.so"]

setup(
    name="umdk_cam_op_lib",
    version=env_version,
    keywords="umdk_cam_op_lib",
    ext_modules=exts,
    packages=find_packages(),
    cmdclass={
        "build_ext": BuildExtension,
        "bdist_wheel": BdistWheelBuild
    },
)