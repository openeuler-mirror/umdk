/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding unit test mocks.
 */

#include "bond_fixture.h"

namespace urma_test_bond {
bool g_mockEpollCreateFail = false;
bool g_mockEpollCreate1Fail = false;
bool g_mockEpollCtlFail = false;
bool g_mockEventfdFail = false;
bool g_mockPthreadCreateFail = false;
urma_device_t *g_mockNamedDevice = nullptr;
urma_ops_t *g_mockCreateContextOps = nullptr;
int g_mockCreateContextCount = 0;
bool g_mockCreateContextFail = false;
bool g_mockCreateContextBadFd = false;
bool g_mockDeleteContextFail = false;
bool g_mockUserCtlFail = false;
size_t g_mockCallocFailNmemb = 0;
size_t g_mockCallocFailSize = 0;
} // namespace urma_test_bond

using namespace urma_test_bond;

extern "C" void *calloc(size_t nmemb, size_t size)
{
    using RealFn = void *(*)(size_t, size_t);

    if ((g_mockCallocFailNmemb != 0 && nmemb == g_mockCallocFailNmemb) ||
        (g_mockCallocFailSize != 0 && size == g_mockCallocFailSize)) {
        return nullptr;
    }

    auto realFn = reinterpret_cast<RealFn>(dlsym(RTLD_NEXT, "calloc"));
    return realFn(nmemb, size);
}

extern "C" int ioctl(int, unsigned long request, ...)
{
    va_list ap;
    void *arg = nullptr;

    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);

    if (request != URMA_CMD || arg == nullptr || !urma_test::GetHwMockState().ioctlSucceed) {
        errno = EINVAL;
        return -1;
    }
    urma_test::GetHwMockState().ioctlCount++;

    auto *hdr = static_cast<urma_cmd_hdr_t *>(arg);
    auto *attrs = reinterpret_cast<urma_cmd_attr_t *>(hdr->args_addr);
    uint32_t attrCount = hdr->args_len / sizeof(urma_cmd_attr_t);

    if (attrs == nullptr || hdr->args_len % sizeof(urma_cmd_attr_t) != 0) {
        errno = EINVAL;
        return -1;
    }

    if (hdr->command == URMA_CMD_USER_CTL) {
        if (g_mockUserCtlFail) {
            errno = EINVAL;
            return -1;
        }
        FillUserCtlOutput(attrs, attrCount);
    } else {
        FillCreateOutput(hdr->command, attrs, attrCount);
    }
    return 0;
}

extern "C" int epoll_create(int size)
{
    if (g_mockEpollCreateFail) {
        errno = EMFILE;
        return -1;
    }
    return epoll_create1(0);
}

extern "C" int epoll_create1(int flags)
{
    if (g_mockEpollCreate1Fail) {
        errno = EMFILE;
        return -1;
    }
    return static_cast<int>(syscall(SYS_epoll_create1, flags));
}

extern "C" int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (g_mockEpollCtlFail) {
        errno = EMFILE;
        return -1;
    }
    return static_cast<int>(syscall(SYS_epoll_ctl, epfd, op, fd, event));
}

extern "C" int eventfd(unsigned int initval, int flags)
{
    if (g_mockEventfdFail) {
        errno = EMFILE;
        return -1;
    }
    return static_cast<int>(syscall(SYS_eventfd2, initval, flags));
}

extern "C" int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*startRoutine)(void *), void *arg)
{
    using RealFn = int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

    if (g_mockPthreadCreateFail) {
        return EAGAIN;
    }

    auto realFn = reinterpret_cast<RealFn>(dlsym(RTLD_NEXT, "pthread_create"));
    return realFn(thread, attr, startRoutine, arg);
}

extern "C" int urma_query_eid(urma_device_t *, uint32_t eidIndex, urma_eid_t *eid)
{
    if (eid == nullptr) {
        return -1;
    }
    eid->in6.subnet_prefix = 0x30000000ULL + eidIndex;
    eid->in6.interface_id = 0x40000000ULL + eidIndex;
    return 0;
}

extern "C" urma_device_t *urma_get_device_by_name(char *devName)
{
    if (devName == nullptr || std::strcmp(devName, "mock_phy0") != 0) {
        return nullptr;
    }
    return g_mockNamedDevice;
}

extern "C" urma_context_t *urma_create_context(urma_device_t *dev, uint32_t eidIndex)
{
    if (g_mockCreateContextFail) {
        return nullptr;
    }

    auto *ctx = static_cast<urma_context_t *>(std::calloc(1, sizeof(urma_context_t)));
    if (ctx == nullptr) {
        return nullptr;
    }

    ctx->dev = dev;
    ctx->ops = g_mockCreateContextOps;
    ctx->eid_index = eidIndex;
    if (g_mockCreateContextBadFd) {
        ctx->async_fd = -1;
        g_mockCreateContextCount++;
        return ctx;
    }
    ctx->async_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->async_fd < 0) {
        std::free(ctx);
        return nullptr;
    }
    g_mockCreateContextCount++;
    return ctx;
}

extern "C" urma_status_t urma_delete_context(urma_context_t *ctx)
{
    if (ctx == nullptr) {
        return URMA_EINVAL;
    }
    urma_status_t ret = g_mockDeleteContextFail ? URMA_FAIL : URMA_SUCCESS;

    if (ctx->async_fd >= 0) {
        (void)close(ctx->async_fd);
    }
    std::free(ctx);
    return ret;
}

extern "C" urma_status_t urma_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
    urma_test::HwMockState &state = urma_test::GetHwMockState();

    state.bindJettyCount++;
    if (state.bindJettyFailAt == state.bindJettyCount) {
        return URMA_FAIL;
    }
    jetty->remote_jetty = tjetty;
    return URMA_SUCCESS;
}

extern "C" urma_status_t urma_unbind_jetty(urma_jetty_t *jetty)
{
    urma_test::GetHwMockState().unbindJettyCount++;
    jetty->remote_jetty = nullptr;
    return URMA_SUCCESS;
}

extern "C" urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *)
{
    static urma_target_jetty_t target = {};

    urma_test::GetHwMockState().importJettyCount++;
    if (urma_test::GetHwMockState().status != URMA_SUCCESS) {
        return nullptr;
    }
    target = {};
    target.urma_ctx = ctx;
    target.id = rjetty->jetty_id;
    target.trans_mode = rjetty->trans_mode;
    target.policy = rjetty->policy;
    target.type = rjetty->type;
    target.flag = rjetty->flag;
    target.tp_type = rjetty->tp_type;
    return &target;
}

extern "C" urma_status_t urma_unimport_jetty(urma_target_jetty_t *)
{
    return urma_test::GetHwMockState().status;
}

extern "C" urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *)
{
    static urma_target_jetty_t target = {};

    urma_test::GetHwMockState().importJfrCount++;
    if (urma_test::GetHwMockState().status != URMA_SUCCESS) {
        return nullptr;
    }
    target = {};
    target.urma_ctx = ctx;
    target.id = rjfr->jfr_id;
    target.trans_mode = rjfr->trans_mode;
    target.type = URMA_JFR;
    return &target;
}

extern "C" urma_status_t urma_unimport_jfr(urma_target_jetty_t *)
{
    return urma_test::GetHwMockState().status;
}
