/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Exception types and assertion/check macros.
 * Create: 2026-11-03
 * Note: Device header for the CAM DeepEP-compatible operators.
 * History: 2026-11-03 create for the cam_deepep operators
 */
#pragma once

#include <exception>
#include <string>
#include <sstream>

// TODO(HUAWEI): do we have a better include path?
#include <utils/debug/asc_assert.h>

#ifndef EP_STATIC_ASSERT
#define EP_STATIC_ASSERT(cond, ...) static_assert(cond, "" __VA_ARGS__)
#endif

class EPException : public std::exception {
    std::string message = {};

  public:
    explicit EPException(const char *name, const char *file, const int line, const std::string &error)
    {
        std::stringstream ss;
        ss << name << " exception (" << file << ":" << line << "): " << error;
        message = ss.str();
    }

    const char *what() const noexcept override
    {
        return message.c_str();
    }
};

#define EPExceptionWithLineInfo(name, message) EPException(name, __FILE__, __LINE__, message)

#ifndef EP_HOST_ASSERT
#define EP_HOST_ASSERT(cond)                                                                                           \
    do {                                                                                                               \
        if (not(cond)) {                                                                                               \
            throw EPException("Assertion", __FILE__, __LINE__, #cond);                                                 \
        }                                                                                                              \
    } while (0)
#endif

#ifdef __CLION_IDE__
#define EP_DEVICE_ASSERT(cond) void()
#else
#define EP_DEVICE_ASSERT(cond) assert(cond)
#endif

#ifndef EP_HOST_UNREACHABLE
#define EP_HOST_UNREACHABLE(reason) (throw EPException("Assertion", __FILE__, __LINE__, reason))
#endif

#ifndef ACL_CHECK
#define ACL_CHECK(cmd)                                                                                                 \
    do {                                                                                                               \
        const auto e = (cmd);                                                                                          \
        if (e != 0) {                                                                                                  \
            std::stringstream ss;                                                                                      \
            ss << "Error code: " << static_cast<int>(e) << ", detail: " << aclGetRecentErrMsg();                       \
            throw EPException("ACL runtime", __FILE__, __LINE__, ss.str());                                            \
        }                                                                                                              \
    } while (0)
#endif

#ifndef HCCL_CHECK
#define HCCL_CHECK(cmd)                                                                                                \
    do {                                                                                                               \
        const auto e = (cmd);                                                                                          \
        if (e != HCCL_SUCCESS) {                                                                                       \
            std::stringstream ss;                                                                                      \
            ss << "Error code: " << static_cast<int>(e) << ", detail: " << HcclGetErrorString(e);                      \
            throw EPException("HCCL runtime", __FILE__, __LINE__, ss.str());                                           \
        }                                                                                                              \
    } while (0)
#endif

#ifndef HCOMM_CHECK
#define HCOMM_CHECK(cmd)                                                                                               \
    do {                                                                                                               \
        const auto e = (cmd);                                                                                          \
        if (e != 0) {                                                                                                  \
            std::stringstream ss;                                                                                      \
            ss << "Error code: " << static_cast<int>(e)                                                                \
               << ", detail: " << HcclGetErrorString(static_cast<HcclResult>(e));                                      \
            throw EPException("HCOMM runtime", __FILE__, __LINE__, ss.str());                                          \
        }                                                                                                              \
    } while (0)
#endif
