/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Shared helpers for URMA command TLV unit tests.
 */

#pragma once

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "urma_cmd_mock.h"
#include "urma_private.h"
#include "urma_provider.h"

namespace urma_cmd_tlv_test {

struct IoctlCapture {
    int fd;
    unsigned long request;
    urma_cmd_hdr_t hdr;
    std::vector<urma_cmd_attr_t> attrs;
    int returnValue;
    int errorNo;
    uint32_t callCount;
};

void ResetIoctlCapture();
void SetIoctlFailure(int returnValue, int errorNo);
void ExpectCapturedCommand(urma_cmd_t command, const std::vector<urma_test::ExpectedAttr> &expected);
void ExpectCapturedHeader(unsigned long request, uint32_t command);
void InitCmdContext(urma_context_t *ctx);

#define EXPECT_URMA_IOCTL_WRAPPER(FUNC, CMD, TYPE)                                      \
    do {                                                                                \
        TYPE arg = {};                                                                  \
        ResetIoctlCapture();                                                            \
        EXPECT_EQ(0, FUNC(urma_test::MOCK_IOCTL_FD, &arg));                              \
        ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), static_cast<uint32_t>(CMD)); \
    } while (0)

#define EXPECT_EVENT_IOCTL_WRAPPER(FUNC, REQUEST, CMD, TYPE)                            \
    do {                                                                                \
        TYPE arg = {};                                                                  \
        ResetIoctlCapture();                                                            \
        EXPECT_EQ(0, FUNC(urma_test::MOCK_IOCTL_FD, &arg));                              \
        ExpectCapturedHeader(static_cast<unsigned long>(REQUEST), static_cast<uint32_t>(CMD));  \
    } while (0)

} // namespace urma_cmd_tlv_test
