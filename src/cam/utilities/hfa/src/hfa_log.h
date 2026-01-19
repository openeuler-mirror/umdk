/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA log utils
 * Author: David Yaron
 * Note:
 * History:
 */

#ifndef HFA_LOG_H
#define HFA_LOG_H

#include <cstdio>

// Log levels
enum HfaLogLevel {
    HFA_LOG_DEBUG   = 0,
    HFA_LOG_INFO    = 1,
    HFA_LOG_WARNING = 2,
    HFA_LOG_ERROR   = 3
};

// Global log level (single-definition via inline). Default: WARNING
inline HfaLogLevel g_hfa_log_level = HFA_LOG_WARNING;

// Setter / getter
inline void hfa_set_log_level(HfaLogLevel lvl)  { g_hfa_log_level = lvl; }
inline HfaLogLevel hfa_get_log_level()          { return g_hfa_log_level; }

// Internal helper macro to print when message level >= current level.
// Uses printf-style variadic args and flushes the stream. Prefixes messages
// with a human-readable level tag like "[Error]: "
#define HFA_LOG_PRINT_IF(msg_level, stream, ...)                                     \
    do {                                                                             \
        if ((msg_level) >= g_hfa_log_level) {                                        \
            const char* _hfa_level_str =                                             \
                  ((msg_level) == HFA_LOG_ERROR)   ? "Error"   :                     \
                  ((msg_level) == HFA_LOG_WARNING) ? "Warning" :                     \
                  ((msg_level) == HFA_LOG_INFO)    ? "Info"    : "Debug";            \
            std::fprintf((stream), "[%s]: ", _hfa_level_str);                        \
            std::fprintf((stream), __VA_ARGS__);                                     \
            std::fflush((stream));                                                   \
        }                                                                            \
    } while (0)

// Per-level macros (keep names used in codebase)
#define DEBUG_PRINT(...)   HFA_LOG_PRINT_IF(HFA_LOG_DEBUG,   stdout, __VA_ARGS__)
#define INFO_PRINT(...)    HFA_LOG_PRINT_IF(HFA_LOG_INFO,    stdout, __VA_ARGS__)
#define WARNING_PRINT(...) HFA_LOG_PRINT_IF(HFA_LOG_WARNING, stdout, __VA_ARGS__)
#define ERROR_PRINT(...)   HFA_LOG_PRINT_IF(HFA_LOG_ERROR,   stderr, __VA_ARGS__)

#endif // HFA_LOG_H

