# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

"""
Includes default copts.
"""

UMQ_DEFAULT_COPTS = [
    "-Wall",
    "-Werror",
    "-Wfloat-equal",
    "-Wtrampolines",
    "-g",
    "-rdynamic",
    "-fno-strict-aliasing",
    "-fstack-protector-strong",
    "-fPIC",
    "-Wextra",
    "-Wno-unused-parameter",
    "-Wno-missing-field-initializers",
    "-Wno-type-limits",
    "-fno-common",
    "-D_GNU_SOURCE",
] + select({
    "@platforms//cpu:x86_64": ["-msse4.2", "-DUB_ARCH_X86_64"],
    "@platforms//cpu:aarch64": ["-march=armv8-a+crc", "-DUB_ARCH_ARM64"],
    "//conditions:default": [],
})

UMQ_DEFAULT_LINKOPTS = [
    "-Wl,-z,noexecstack",
    "-Wl,-z,relro",
    "-Wl,-z,now",
]