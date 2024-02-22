/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of generic commands of uvs_admin
 * Author: Ji Lei
 * Create: 2023-06-19
 * Note:
 * History: 2023-06-19 Ji Lei
 */

#ifndef UVS_ADMIN_CMD_H
#define UVS_ADMIN_CMD_H

#include "uvs_admin.h"
#include "ub_util.h"
#include "ub_shash.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct uvs_admin_cmd uvs_admin_cmd_t;

#define NEXT_CMD 256

enum UVS_ADMIN_CMD_PARA_NUM {
    UVS_ADMIN_CMD_PARM_ONE = 1,
    UVS_ADMIN_CMD_PARM_TWO = 2,
    UVS_ADMIN_CMD_PARM_THREE = 3,
    UVS_ADMIN_CMD_PARM_FOUR = 4,
    UVS_ADMIN_CMD_PARM_FIVE = 5,
    UVS_ADMIN_CMD_PARM_SIX = 6,
    UVS_ADMIN_CMD_PARM_SEVEN = 7,
    UVS_ADMIN_CMD_PARM_EIGHT = 8,
    UVS_ADMIN_CMD_PARM_NINE = 9,
};

typedef struct uvs_admin_cmd_ctx {
    int argc;                    /* Number of arguments to parse */
    char **argv;                 /* Arguments */
    uvs_admin_cmd_t *cur_cmd;  /* Current uvs_admin command */
    const char *path;            /* unix sock of uVS service endpoint */
    unsigned int timeout;        /* Timeout of socket connection, range 0-7500 */
} uvs_admin_cmd_ctx_t;

typedef struct uvs_admin_opt_usage {
    const char *opt_long;
    const char *desc;
} uvs_admin_opt_usage_t;

typedef struct uvs_admin_cmd_usage {
    const uvs_admin_opt_usage_t *opt_usage;
    size_t opt_num;
} uvs_admin_cmd_usage_t;

struct uvs_admin_cmd {
    const char *command;                    /* Command name */
    const char *summary;                    /* Command one-line summary */
    const uvs_admin_cmd_usage_t *usage;   /* Option usage info */
    struct shash_node *node;                /* Link to the shash table of parent command */
    struct shash subcmds;                   /* Sub-commands */
    int32_t (*run)(uvs_admin_cmd_ctx_t *ctx); /* Command handler */
    int min_argc;
};

int32_t uvs_admin_exec(int argc, char **argv);
void uvs_admin_cmd_usages(uvs_admin_cmd_ctx_t *ctx);

/*
 * A branch command is an intermediate sub-command between the rootcmd and
 * last level (i.e. leaf) sub-command. The main purpose of branch command is
 * to express namespace hierarchy, rather than taking options/values. The only
 * supported option of a branch command is -h/--help, which should be the
 * last argument provided in argv.
 *
 * uvs_admin_branch_subcmd_exec function provides a convenient wrapper API, so
 * that effort of supporting -h/--help in branch commands can be minimized.
 */
int32_t uvs_admin_branch_subcmd_exec(uvs_admin_cmd_ctx_t *ctx);

#define UVS_ADMIN_BRANCH_SUBCMD_USAGE(name)                        \
    static const uvs_admin_opt_usage_t name##_opt_usage[] = { \
        {"help", "display this help and exit"},                 \
    };                                                          \
    static const uvs_admin_cmd_usage_t name##_usage = {       \
        .opt_usage = name##_opt_usage,                          \
        .opt_num   = ARRAY_SIZE(name##_opt_usage),              \
    };

#define UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(name) &name##_usage

void uvs_admin_register_subcmd(uvs_admin_cmd_t *parent,
    uvs_admin_cmd_t **children, int num);
void uvs_admin_unregister_subcmd(uvs_admin_cmd_t *parent);

#define REGISTER_UVS_ADMIN_COMMANDS(self, subcmds)                              \
    static void __attribute__((constructor, used)) uvs_admin_add_subcmds(void)  \
    {                                                                        \
        uvs_admin_register_subcmd(&(self), subcmds, ARRAY_SIZE(subcmds));         \
    }                                                                        \
    static void __attribute__((destructor, used)) uvs_admin_clear_subcmds(void) \
    {                                                                        \
        uvs_admin_unregister_subcmd(&(self));                                     \
    }

#ifdef __cplusplus
}
#endif

#endif /* UVS_ADMIN_CMD_H */
