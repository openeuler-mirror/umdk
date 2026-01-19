/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Nikita Merkulov
 * Note:
 * History:
 */

#include <acl/acl.h>
#include <gtest/gtest.h>

int main(int argc, char* argv[])
{
    setbuf(stdout, NULL); // printf completely unbuffered
    if (aclInit(nullptr) != ACL_SUCCESS) {
        printf("\naclInit has failed: %s", aclGetRecentErrMsg());
        return -1;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}