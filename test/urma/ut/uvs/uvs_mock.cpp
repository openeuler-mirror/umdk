/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UVS unit test mocks.
 */

#include "uvs_fixture.h"

namespace urma_test_uvs {
UvsIoctlCapture g_uvsIoctl;
} // namespace urma_test_uvs

using namespace urma_test_uvs;

extern "C" int ioctl(int, unsigned long request, ...)
{
    va_list ap;
    void *arg = nullptr;

    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);

    g_uvsIoctl.callCount++;
    if (!g_uvsIoctl.succeed || arg == nullptr) {
        errno = g_uvsIoctl.errnoValue;
        return -1;
    }

    if (request == UVS_UBAGG_CMD) {
        return HandleUbaggIoctl(static_cast<uvs_ubagg_cmd_hdr *>(arg));
    }
    if (request != TPSA_CMD) {
        errno = EINVAL;
        return -1;
    }

    auto *hdr = static_cast<tpsa_cmd_hdr_t *>(arg);
    if (hdr->args_len != 0 && hdr->args_addr == 0) {
        errno = EINVAL;
        return -1;
    }
    CaptureTlvAttrs(hdr);
    return 0;
}

extern "C" int open(const char *path, int flags, ...)
{
    mode_t mode = 0;

    if ((flags & O_CREAT) != 0) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    if (std::strcmp(path, "/dev/ubagg") == 0 || std::strcmp(path, "/dev/ubcore/ubcore") == 0) {
        if (g_uvsIoctl.mockDeviceOpen) {
            return 77;
        }
        errno = ENOENT;
        return -1;
    }

    return static_cast<int>(syscall(SYS_openat, AT_FDCWD, path, flags, mode));
}

extern "C" int close(int fd)
{
    if (fd == 77) {
        return 0;
    }
    return static_cast<int>(syscall(SYS_close, fd));
}
