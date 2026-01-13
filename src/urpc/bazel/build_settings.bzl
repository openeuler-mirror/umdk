# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

OpensslModeInfo = provider(fields = ['type'])

openssl_modes = ["bazel", "system"]

def _impl(ctx):
    raw_openssl_mode = ctx.build_setting_value

    if raw_openssl_mode not in openssl_modes:
        fail(str(ctx.label) + "build setting allowed to take values {" +
            ", ".join(openssl_modes) + "} but was set to unallowed value " +
            raw_openssl_mode)

    return OpensslModeInfo(type = raw_openssl_mode)

openssl_mode = rule(
    implementation = _impl,
    build_setting = config.string(flag = True)
)