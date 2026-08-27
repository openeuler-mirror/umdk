/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* main: script reader + command dispatcher. Main thread does no business —
 * alloc/free are dispatched to worker threads via 'thread_K <cmd>'.
 *
 * Four parsing states (BlockState):
 *   LINE_MODE           — top-level, line-by-line dispatch (original behaviour)
 *   PARALLEL_MODE       — collecting lines between 'parallel' and 'join'; on
 *                         'join' DoParallelBlock dispatches them all
 *                         asynchronously + SyncAll
 *   REPEAT_MODE         — collecting lines between 'repeat N' and 'end'; on
 *                         'end' DoRepeatBlock runs the collected lines N
 *                         times serially
 *   STRESS_REPEAT_MODE  — like REPEAT_MODE but for 'stress_repeat'/'end';
 *                         DoStressRepeatBlock runs infinitely in stress mode
 *                         (no g_actions logging, bounded memory for days-
 *                         long stability runs; stopped by SIGINT/SIGTERM)
 *
 * repeat / stress_repeat blocks may contain parallel/join sub-blocks. parallel
 * blocks may NOT contain nested parallel. snapshot directives are allowed
 * inside both repeat and stress_repeat blocks (handled as no-op by
 * ExecuteBlockLines; the outer loop pre-scans for them). */

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "qbuf_pool_tool.h"

namespace {
enum BlockState {
    LINE_MODE,
    PARALLEL_MODE,
    REPEAT_MODE,
    STRESS_REPEAT_MODE
};

/* Dispatch a single top-level (LINE_MODE) command. Returns 0 on success,
 * non-zero on failure. Mirrors the original main loop's command switch. */
int DispatchLineCommand(const std::vector<std::string> &toks)
{
    const std::string &cmd = toks[0];
    if (cmd.compare(0, 7, "thread_") == 0) {
        size_t widx = (size_t)strtoul(cmd.c_str() + 7, nullptr, 10);
        if (toks.size() < 2) {
            fprintf(stderr, "ERROR: '%s' needs a sub-command (alloc/free)\n", cmd.c_str());
            return -1;
        }
        std::vector<std::string> subargs(toks.begin() + 1, toks.end());
        const std::string &sub = subargs[0];
        if (sub == "alloc") {
            return DoAlloc(subargs, widx);
        }
        if (sub == "free") {
            return DoFree(subargs, widx);
        }
        fprintf(stderr, "ERROR: thread_%zu only supports alloc/free, got '%s'\n", widx, sub.c_str());
        return -1;
    }
    if (cmd == "init") {
        return DoInit(toks);
    }
    if (cmd == "info") {
        return DoInfo(toks);
    }
    if (cmd == "status") {
        return DoStatus(toks);
    }
    if (cmd == "sleep") {
        return DoSleep(toks);
    }
    if (cmd == "quit" || cmd == "exit") {
        return 1; /* signal: caller should break the main loop */
    }
    fprintf(stderr,
            "ERROR: unknown command '%s' (use 'thread_K alloc|free' or "
            "init/info/status/sleep/quit/parallel/repeat)\n",
            cmd.c_str());
    return -1;
}
} /* namespace */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <script.txt>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "r");
    if (f == nullptr) {
        perror("fopen");
        return 1;
    }

    char line[1024];
    int exit_code = 0;
    BlockState state = LINE_MODE;
    int repeat_count = 0;
    bool stress_repeat = false; /* tracks which kind of repeat block is active */
    std::vector<std::string> raw_block; /* raw source lines for current block */

    while (fgets(line, sizeof(line), f) != nullptr) {
        /* First peek the first non-whitespace token to detect block markers
         * without consuming the line. Tokenize is cheap; reuse it. */
        std::vector<std::string> toks = Tokenize(line);

        if (toks.empty()) {
            /* blank or comment-only line: keep in block buffer so line
             * numbers stay aligned for error messages; harmless to dispatch. */
            if (state != LINE_MODE) {
                raw_block.push_back(line);
            }
            continue;
        }
        const std::string &cmd = toks[0];

        switch (state) {
            case LINE_MODE: {
                if (cmd == "parallel") {
                    state = PARALLEL_MODE;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "repeat" || cmd == "stress_repeat") {
                    stress_repeat = (cmd == "stress_repeat");
                    if (stress_repeat) {
                        /* stress_repeat is infinite — no count arg. If user
                         * provides one, warn and ignore (don't error, since
                         * old scripts with count still work conceptually —
                         * they just don't get bounded behavior). */
                        if (toks.size() >= 2) {
                            fprintf(stderr,
                                    "WARNING: stress_repeat no longer takes a count "
                                    "(now infinite). Ignoring '%s'. Use SIGINT (Ctrl-C) "
                                    "to stop the loop gracefully.\n",
                                    toks[1].c_str());
                        }
                        repeat_count = 0; /* unused for stress_repeat */
                        state = STRESS_REPEAT_MODE;
                    } else {
                        if (toks.size() < 2) {
                            fprintf(stderr, "ERROR: repeat needs a count (repeat N)\n");
                            exit_code = 1;
                            break;
                        }
                        repeat_count = (int)strtol(toks[1].c_str(), nullptr, 10);
                        state = REPEAT_MODE;
                    }
                    raw_block.clear();
                    continue;
                }
                int r = DispatchLineCommand(toks);
                if (r == 1) {
                    /* quit/exit requested */
                    fclose(f);
                    Cleanup();
                    return exit_code;
                }
                if (r != 0) {
                    exit_code = 1;
                }
                break;
            }

            case PARALLEL_MODE: {
                if (cmd == "join") {
                    std::vector<std::vector<std::string>> block = TokenizeBlock(raw_block);
                    if (ValidateParallelBlock(block) != 0) {
                        exit_code = 1;
                    } else if (DoParallelBlock(block) != 0) {
                        exit_code = 1;
                    }
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "parallel") {
                    fprintf(stderr, "ERROR: nested 'parallel' inside parallel block "
                                    "(merge into one block)\n");
                    exit_code = 1;
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "repeat" || cmd == "stress_repeat" || cmd == "end") {
                    fprintf(stderr,
                            "ERROR: '%s' not allowed inside parallel block "
                            "(close with 'join' first)\n",
                            cmd.c_str());
                    exit_code = 1;
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "init" || cmd == "info" || cmd == "status" || cmd == "quit" || cmd == "exit") {
                    fprintf(stderr,
                            "ERROR: '%s' not allowed inside parallel block "
                            "(parallel must close with 'join' first)\n",
                            cmd.c_str());
                    exit_code = 1;
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                raw_block.push_back(line);
                break;
            }

            case REPEAT_MODE:
            case STRESS_REPEAT_MODE: {
                if (cmd == "end") {
                    std::vector<std::vector<std::string>> block = TokenizeBlock(raw_block);
                    int r;
                    if (state == STRESS_REPEAT_MODE) {
                        (void)repeat_count; /* stress_repeat is infinite — count unused */
                        r = DoStressRepeatBlock(block);
                    } else {
                        r = DoRepeatBlock(repeat_count, block);
                    }
                    if (r != 0) {
                        exit_code = 1;
                    }
                    state = LINE_MODE;
                    stress_repeat = false;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "repeat" || cmd == "stress_repeat") {
                    fprintf(stderr, "ERROR: nested '%s' not allowed (use a single repeat/stress_repeat)\n",
                            cmd.c_str());
                    exit_code = 1;
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                if (cmd == "parallel" || cmd.compare(0, 7, "thread_") == 0 || cmd == "join" || cmd == "snapshot") {
                    /* Allowed inside repeat/stress_repeat. snapshot is a
                     * directive handled by the outer repeat loop. */
                    raw_block.push_back(line);
                    break;
                }
                if (cmd == "init" || cmd == "info" || cmd == "status" || cmd == "quit" || cmd == "exit") {
                    fprintf(stderr,
                            "ERROR: '%s' not allowed inside %s block "
                            "(close with 'end' first; check conservation after repeat instead)\n",
                            cmd.c_str(), state == STRESS_REPEAT_MODE ? "stress_repeat" : "repeat");
                    exit_code = 1;
                    state = LINE_MODE;
                    raw_block.clear();
                    continue;
                }
                raw_block.push_back(line);
                break;
            }
        }
    }

    fclose(f);

    /* Unterminated block at EOF — error out, do not silently execute. */
    if (state == PARALLEL_MODE) {
        fprintf(stderr, "ERROR: parallel block not terminated (missing 'join' before EOF)\n");
        exit_code = 1;
    } else if (state == REPEAT_MODE) {
        fprintf(stderr, "ERROR: repeat block not terminated (missing 'end' before EOF)\n");
        exit_code = 1;
    } else if (state == STRESS_REPEAT_MODE) {
        fprintf(stderr, "ERROR: stress_repeat block not terminated (missing 'end' before EOF)\n");
        exit_code = 1;
    }

    Cleanup();
    return exit_code;
}
