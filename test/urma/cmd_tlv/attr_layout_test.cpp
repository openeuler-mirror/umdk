/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA command TLV attribute layout unit tests.
 */

#include "cmd_tlv_fixture.h"

using namespace urma_cmd_tlv_test;

TEST(UrmaCmdTlvTest, CreateCtxTlvAttrsMatchExpected)
{
    urma_cmd_create_ctx_t arg = urma_test::MakeCreateCtxCmd();
    std::vector<urma_test::ExpectedAttr> expected = urma_test::ExpectedCreateCtxAttrs(&arg);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_create_ctx(urma_test::MOCK_IOCTL_FD, &arg));
    ExpectCapturedCommand(URMA_CMD_CREATE_CTX, expected);
}

TEST(UrmaCmdTlvTest, TokenIdTlvAttrsMatchExpected)
{
    urma_cmd_alloc_token_id_t allocArg = urma_test::MakeAllocTokenIdCmd();
    urma_cmd_free_token_id_t freeArg = urma_test::MakeFreeTokenIdCmd();
    std::vector<urma_test::ExpectedAttr> allocExpected = urma_test::ExpectedAllocTokenIdAttrs(&allocArg);
    std::vector<urma_test::ExpectedAttr> freeExpected = urma_test::ExpectedFreeTokenIdAttrs(&freeArg);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_alloc_token_id(urma_test::MOCK_IOCTL_FD, &allocArg));
    ExpectCapturedCommand(URMA_CMD_ALLOC_TOKEN_ID, allocExpected);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_free_token_id(urma_test::MOCK_IOCTL_FD, &freeArg));
    ExpectCapturedCommand(URMA_CMD_FREE_TOKEN_ID, freeExpected);
}

TEST(UrmaCmdTlvTest, SegmentTlvAttrsMatchExpected)
{
    urma_cmd_register_seg_t registerArg = urma_test::MakeRegisterSegCmd();
    urma_cmd_import_seg_t importArg = urma_test::MakeImportSegCmd();
    urma_cmd_unregister_seg_t unregisterArg = urma_test::MakeUnregisterSegCmd();

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_register_seg(urma_test::MOCK_IOCTL_FD, &registerArg));
    ExpectCapturedCommand(URMA_CMD_REGISTER_SEG, urma_test::ExpectedRegisterSegAttrs(&registerArg));

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_import_seg(urma_test::MOCK_IOCTL_FD, &importArg));
    ExpectCapturedCommand(URMA_CMD_IMPORT_SEG, urma_test::ExpectedImportSegAttrs(&importArg));

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_unregister_seg(urma_test::MOCK_IOCTL_FD, &unregisterArg));
    ExpectCapturedCommand(URMA_CMD_UNREGISTER_SEG, urma_test::ExpectedUnregisterSegAttrs(&unregisterArg));
}

TEST(UrmaCmdTlvTest, JfsTlvAttrsMatchExpected)
{
    urma_cmd_create_jfs_t createArg = urma_test::MakeCreateJfsCmd();
    urma_cmd_query_jfs_t queryArg = urma_test::MakeQueryJfsCmd();
    urma_cmd_delete_jfs_t deleteArg = urma_test::MakeDeleteJfsCmd();

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_create_jfs(urma_test::MOCK_IOCTL_FD, &createArg));
    ExpectCapturedCommand(URMA_CMD_CREATE_JFS, urma_test::ExpectedCreateJfsAttrs(&createArg));

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_query_jfs(urma_test::MOCK_IOCTL_FD, &queryArg));
    ExpectCapturedCommand(URMA_CMD_QUERY_JFS, urma_test::ExpectedQueryJfsAttrs(&queryArg));

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_delete_jfs(urma_test::MOCK_IOCTL_FD, &deleteArg));
    ExpectCapturedCommand(URMA_CMD_DELETE_JFS, urma_test::ExpectedDeleteJfsAttrs(&deleteArg));
}

TEST(UrmaCmdTlvTest, DeleteJfsBatchTlvAttrsMatchExpected)
{
    urma_jfs_t firstJfs = {};
    urma_jfs_t secondJfs = {};
    urma_jfs_t thirdJfs = {};
    urma_jfs_t *jfsArr[] = { &firstJfs, &secondJfs, &thirdJfs };
    urma_cmd_delete_jfs_batch_t arg = urma_test::MakeDeleteJfsBatchCmd(jfsArr, 3);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_delete_jfs_batch(urma_test::MOCK_IOCTL_FD, &arg));
    ExpectCapturedCommand(URMA_CMD_DELETE_JFS_BATCH, urma_test::ExpectedDeleteJfsBatchAttrs(&arg));
}

TEST(UrmaCmdTlvTest, IoctlErrorIsPropagated)
{
    urma_cmd_create_ctx_t arg = urma_test::MakeCreateCtxCmd();
    urma_cmd_create_ctx_t original = arg;

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);

    EXPECT_EQ(-1, urma_ioctl_create_ctx(urma_test::MOCK_IOCTL_FD, &arg));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_EQ(0, std::memcmp(&original, &arg, sizeof(arg)));
    ExpectCapturedCommand(URMA_CMD_CREATE_CTX, urma_test::ExpectedCreateCtxAttrs(&arg));
}

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
