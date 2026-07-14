#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind setup file
# Create: 2025-12-11
# Note:
# History: 2025-12-11 create pybind setup file
#

import importlib.util
import os
import platform
import subprocess
import sys
import sysconfig
import tempfile

import torch

sys.path.append(os.path.join(os.path.dirname(__file__), "./pytorch_extension"))
from bdist_wheel_build import BdistWheelBuild
from setuptools import setup, find_packages
from torch.utils.cpp_extension import BuildExtension
from torch_npu.utils.cpp_extension import NpuExtension

# Format: V_version.R_version.C_version.B_version
env_version = os.getenv("CAM_WHL_VERSION", "209.0.0.B001")

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


def _acl_has_fp8_fp4():
    """Probe whether the active acl_base.h declares the FP8/FP4 aclDataType enumerators.

    The enumerators (ACL_FLOAT8_E5M2/E4M3FN/E8M0, ACL_FLOAT4_E2M1) are C enum members,
    not macros, so they cannot be #ifdef-detected in the header. Older torch_npu (e.g.
    2.8.0.post2 on CANN 8.5) ships an acl_base.h whose enum stops at ACL_BF16; newer
    builds include the FP8/FP4 members. Compile a tiny translation unit referencing them
    with the same include paths the extension uses; on success define CAM_ACL_HAS_FP8_FP4
    so pytorch_npu_helper.hpp populates the low-precision dtype table, otherwise it
    leaves those entries as ACL_DT_UNDEFINED (falling back to the view(int8) workaround).
    """
    if not os.environ.get("ASCEND_HOME_PATH"):
        return False
    # Mirror the include_dirs order passed to NpuExtension below so the probe resolves
    # <acl/acl_base.h> from the same header (torch_npu's copy shadows the CANN toolkit's
    # when its include dir comes first) that the real extension compilation will see.
    toolkit_inc = os.path.join(os.environ["ASCEND_HOME_PATH"], f"{arch}-linux", "include")
    inc_dirs = [
        os.path.join(torch_npu_path, "include"),
        os.path.join(torch_npu_path, "include/third_party/acl/inc/acl/"),
        os.path.join(torch_npu_path, "include/third_party/acl/inc"),
        toolkit_inc,
        os.path.join(torch_path, "include"),
        os.path.join(torch_path, "include", "torch", "csrc", "api", "include"),
    ]
    py_inc = sysconfig.get_path("include")
    if py_inc:
        inc_dirs.append(py_inc)
    src = (
        "#include <acl/acl_base.h>\n"
        "static aclDataType a = ACL_FLOAT8_E5M2;\n"
        "static aclDataType b = ACL_FLOAT8_E8M0;\n"
        "static aclDataType c = ACL_FLOAT4_E2M1;\n"
        "int main() { return (int)a + (int)b + (int)c; }\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        srcfile = os.path.join(tmp, "probe.cpp")
        with open(srcfile, "w") as fh:
            fh.write(src)
        cxx = os.environ.get("CXX", "c++")
        cmd = [cxx, "-fsyntax-only", "-std=c++17", "-w"]
        cmd += ["-I" + d for d in inc_dirs]
        cmd.append(srcfile)
        try:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode == 0
        except OSError:
            return False


acl_has_fp8_fp4 = _acl_has_fp8_fp4()
print(f"acl_has_fp8_fp4: {acl_has_fp8_fp4}")

compile_args = [
    "-I" + os.path.join(PYTORCH_NPU_INSTALL_PATH, "include/third_party/acl/inc"),
    "-fPIC", "-fstack-protector-strong", "-w",
    "-D_FORTIFY_SOURCE=2",
]
if acl_has_fp8_fp4:
    compile_args.append("-DCAM_ACL_HAS_FP8_FP4")
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