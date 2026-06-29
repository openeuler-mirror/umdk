/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA command TLV unit-test ioctl mocks.
 */

#include "cmd_tlv_fixture.h"

namespace urma_cmd_tlv_test {

namespace {
IoctlCapture g_ioctlCapture;
} // namespace

void ResetIoctlCapture()
{
    g_ioctlCapture = {};
    g_ioctlCapture.returnValue = 0;
}

void SetIoctlFailure(int returnValue, int errorNo)
{
    g_ioctlCapture.returnValue = returnValue;
    g_ioctlCapture.errorNo = errorNo;
}

void ExpectCapturedCommand(urma_cmd_t command, const std::vector<urma_test::ExpectedAttr> &expected)
{
    ASSERT_EQ(1U, g_ioctlCapture.callCount);
    EXPECT_EQ(urma_test::MOCK_IOCTL_FD, g_ioctlCapture.fd);
    EXPECT_EQ(static_cast<unsigned long>(URMA_CMD), g_ioctlCapture.request);
    EXPECT_EQ(static_cast<uint32_t>(command), g_ioctlCapture.hdr.command);
    EXPECT_EQ(expected.size() * sizeof(urma_cmd_attr_t), g_ioctlCapture.hdr.args_len);
    ASSERT_EQ(expected.size(), g_ioctlCapture.attrs.size());
    urma_test::ExpectAttrsEqual(g_ioctlCapture.attrs.data(), expected);
}

void ExpectCapturedHeader(unsigned long request, uint32_t command)
{
    ASSERT_EQ(1U, g_ioctlCapture.callCount);
    EXPECT_EQ(urma_test::MOCK_IOCTL_FD, g_ioctlCapture.fd);
    EXPECT_EQ(request, g_ioctlCapture.request);
    EXPECT_EQ(command, g_ioctlCapture.hdr.command);
    EXPECT_GT(g_ioctlCapture.hdr.args_len, 0U);
    EXPECT_EQ(0U, g_ioctlCapture.hdr.args_len % sizeof(urma_cmd_attr_t));
    EXPECT_EQ(g_ioctlCapture.hdr.args_len / sizeof(urma_cmd_attr_t), g_ioctlCapture.attrs.size());
}

void InitCmdContext(urma_context_t *ctx)
{
    ctx->dev_fd = urma_test::MOCK_IOCTL_FD;
}

IoctlCapture *MutableIoctlCaptureForWrap()
{
    return &g_ioctlCapture;
}

} // namespace urma_cmd_tlv_test

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    void *argp = nullptr;
    auto *capture = urma_cmd_tlv_test::MutableIoctlCaptureForWrap();

    va_start(args, request);
    argp = va_arg(args, void *);
    va_end(args);

    capture->fd = fd;
    capture->request = request;
    capture->callCount++;

    if (argp != nullptr) {
        const auto *hdr = static_cast<const urma_cmd_hdr_t *>(argp);
        const auto *attrs = reinterpret_cast<const urma_cmd_attr_t *>(static_cast<uintptr_t>(hdr->args_addr));
        size_t attrNum = hdr->args_len / sizeof(urma_cmd_attr_t);

        /* Copy TLV metadata before returning so later stack changes in the caller cannot affect assertions. */
        capture->hdr = *hdr;
        capture->attrs.assign(attrs, attrs + attrNum);
    }

    errno = capture->errorNo;
    return capture->returnValue;
}

extern "C" int __wrap_urma_query_eid(urma_device_t *, uint32_t eidIndex, urma_eid_t *eid)
{
    if (eid == nullptr) {
        return -1;
    }

    eid->in6.subnet_prefix = 0xabc00000ULL + eidIndex;
    eid->in6.interface_id = 0xdef00000ULL + eidIndex;
    return 0;
}
