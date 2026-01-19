/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Nikita Merkulov
 * Note:
 * History:
 */

#ifndef _TEST_UTILS_
#define _TEST_UTILS_

#include <cstddef>
#include <vector>

int read_rands_from_file(const char *file_name, std::vector<size_t> &numbers);

#endif // _TEST_UTILS_