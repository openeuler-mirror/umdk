/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: pybind utils header file
 * Create: 2026-01-19
 * Note:
 * History: 2026-01-19 add pybind utils header file
 */

#pragma once

#include <c10/core/ScalarType.h>
#include <Python.h>

class TorchBindException : public std::exception {
public:
    explicit TorchBindException(const char *name, const char *file, const int line, const std::string &error)
    {
        message = std::string("Failed: ") + name + " error " + file + ":" + std::to_string(line) +
                  " error message or error code is '" + error + "'";
    }

    const char *what() const noexcept override
    {
        return message.c_str();
    }
private:
    std::string message = {};
};

#define TORCH_BIND_ASSERT(cond)                                                \
    do {                                                                       \
        if (not(cond)) {                                                       \
            throw TorchBindException("Assertion", __FILE__, __LINE__, #cond);  \
        }                                                                      \
    } while (0)