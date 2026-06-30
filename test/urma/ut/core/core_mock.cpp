/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core unit test wrap mocks.
 */

#include "core_fixture.h"

namespace urma_test_core {
int g_logCallbackCount = 0;
int g_locLogCallbackCount = 0;
int g_lastLogLevel = -1;
int g_coreIoctlReturn = -1;
int g_coreIoctlErrno = ENOTTY;
uint32_t g_coreAsyncEventType = URMA_EVENT_PORT_ACTIVE;
uint64_t g_coreAsyncEventData = 0x7;
uint32_t g_coreQueryJettyFlag = URMA_SHARE_JFR;
uint32_t g_coreBatchBadIndex = 0;
std::string g_coreSysfsRedirectRoot;
std::string g_coreProviderDliPath;
int g_coreDlopenCount = 0;
int g_coreDlcloseCount = 0;
} // namespace urma_test_core

using namespace urma_test_core;

extern "C" int __real_stat(const char *path, struct stat *buf);
extern "C" char *__real_realpath(const char *path, char *resolved_path);
extern "C" DIR *__real_opendir(const char *name);
extern "C" int __real_dladdr(const void *addr, Dl_info *info);
extern "C" void *__real_dlopen(const char *filename, int flags);
extern "C" int __real_dlclose(void *handle);

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    urma_cmd_hdr_t *hdr = nullptr;

    va_start(args, request);
    hdr = va_arg(args, urma_cmd_hdr_t *);
    va_end(args);

    (void)fd;
    (void)request;
    FillCoreIoctlOutput(hdr);
    errno = g_coreIoctlErrno;
    return g_coreIoctlReturn;
}

extern "C" int __wrap_stat(const char *path, struct stat *buf)
{
    std::string mapped = MapCoreSysfsPath(path);

    return __real_stat(mapped.c_str(), buf);
}

extern "C" char *__wrap_realpath(const char *path, char *resolved_path)
{
    std::string mapped = MapCoreSysfsPath(path);

    return __real_realpath(mapped.c_str(), resolved_path);
}

extern "C" DIR *__wrap_opendir(const char *name)
{
    std::string mapped = MapCoreSysfsPath(name);

    return __real_opendir(mapped.c_str());
}

extern "C" int __wrap_dladdr(const void *addr, Dl_info *info)
{
    if (g_coreProviderDliPath.empty()) {
        return __real_dladdr(addr, info);
    }

    (void)addr;
    (void)memset(info, 0, sizeof(*info));
    info->dli_fname = g_coreProviderDliPath.c_str();
    return 1;
}

extern "C" void *__wrap_dlopen(const char *filename, int flags)
{
    if (g_coreProviderDliPath.empty()) {
        return __real_dlopen(filename, flags);
    }

    (void)filename;
    (void)flags;
    g_coreDlopenCount++;
    return reinterpret_cast<void *>(static_cast<uintptr_t>(0x1));
}

extern "C" int __wrap_dlclose(void *handle)
{
    if (g_coreProviderDliPath.empty()) {
        return __real_dlclose(handle);
    }

    EXPECT_NE(nullptr, handle);
    g_coreDlcloseCount++;
    return 0;
}
