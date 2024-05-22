/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of generic commands of uvs_admin
 * Author: Ji Lei
 * Create: 2023-06-19
 * Note:
 * History: 2023-06-19 Ji Lei Initial version
 */
#include <errno.h>
#include <getopt.h>

#include "uvs_admin_cmd_trace.h"
#include "uvs_admin_rootcmd.h"
#include "uvs_admin_cmd.h"

void uvs_admin_register_subcmd(uvs_admin_cmd_t *parent,
                               uvs_admin_cmd_t **children, int num)
{
    uvs_admin_cmd_t *child = NULL;
    int i;

    for (i = 0; i < num; i++) {
        child = children[i];
        if (child->node != NULL) {
            (void)printf("Invalid child node\n");
            return;
        }
        child->node = shash_add(&parent->subcmds, child->command, child);
    }
}

void uvs_admin_unregister_subcmd(uvs_admin_cmd_t *parent)
{
    shash_destroy(&parent->subcmds);
}

static inline void uvs_admin_print_opt_name(const uvs_admin_opt_usage_t *opt)
{
    char opt_name[UVS_ADMIN_MAX_CMD_LEN] = {0};

    if (opt->is_mandatory == true) {
        (void)snprintf(opt_name, UVS_ADMIN_MAX_CMD_LEN, "<--%s>", opt->opt_long);
    } else {
        (void)snprintf(opt_name, UVS_ADMIN_MAX_CMD_LEN, "[--%s]", opt->opt_long);
    }
    (void)printf("  %-23s %s\n", opt_name, opt->desc);
}

void uvs_admin_cmd_usages(uvs_admin_cmd_ctx_t *ctx)
{
    uvs_admin_cmd_t *cmd = ctx->cur_cmd;
    const struct shash_node **nodes = NULL;
    const uvs_admin_cmd_usage_t *usage = cmd->usage;
    const uvs_admin_opt_usage_t *opt = NULL;
    size_t i;

    /* Print usage information of all options of current command */
    if (usage && usage->opt_num > 0) {
        (void)printf("Supported options:\n");
        for (i = 0; i < usage->opt_num; i++) {
            opt = &usage->opt_usage[i];
            if (opt->opt_long) {
                uvs_admin_print_opt_name(opt);
            } else {
                (void)printf(" %s\n", opt->desc);
            }
        }
    }
    /* Print sorted list of sub-commands */
    nodes = shash_sort(&cmd->subcmds);
    /* no sub-command registered */
    if (nodes == NULL) {
        return;
    }

    (void)printf("Supported sub-commands:\n");
    for (i = 0; i < shash_count(&cmd->subcmds); i++) {
        const struct shash_node *n      = nodes[i];
        const uvs_admin_cmd_t *subcmd = n->data;
        (void)printf("  %-25s %s\n", subcmd->command, subcmd->summary);
    }
    free(nodes);
}

static bool uvs_admin_more_subcmd(uvs_admin_cmd_ctx_t *ctx)
{
    return ctx->cur_cmd != NULL;
}

static int32_t uvs_admin_next_subcmd(uvs_admin_cmd_ctx_t *ctx)
{
    uvs_admin_cmd_t *cmd = NULL;
    int32_t status = 0;

    if (ctx->argc < 0) {
        (void)printf("Next argc Invalid");
        status = -EINVAL;
        goto done;
    }

    /* No arguments left */
    if (ctx->argc == 0) {
        goto done;
    }

    cmd = shash_find_data(&ctx->cur_cmd->subcmds, ctx->argv[0]);
    /* Remaining arguments not recognizable */
    if (cmd == NULL) {
        (void)printf("Unrecognized arguments ignored: ");
        int i;
        for (i = 0; i < ctx->argc; i++) {
            (void)printf("%s%s", ctx->argv[i], (i == ctx->argc - 1) ? "\n" : " ");
        }
        status = -EINVAL;
    }

done:
    ctx->cur_cmd = cmd;
    return status;
}

int32_t uvs_admin_exec(int argc, char **argv)
{
    int32_t status = 0;

    uvs_admin_cmd_ctx_t ctx = {
        .argc     = argc,
        .argv     = argv,
        .cur_cmd  = &g_uvs_admin_root_cmd,
        .path = DEFAULT_UVSD_SOCK,
        .timeout = SOCKET_TIME_OUT,
    };

    uvs_admin_trace_t *uvs_admin_trace = trace_create(argv);
    if (uvs_admin_trace == NULL) {
        return -ENOMEM;
    }
    uvs_admin_trace->isOperation = cmd_is_operation(argc, argv);
    uvs_admin_trace->mod_name = "uvs_admin";

    do {
        /* check cur_cmd support argument count and the argc need
         * not be less than cur_cmd->min_argc */
        if (ctx.argc < ctx.cur_cmd->min_argc) {
            uvs_admin_cmd_usages(&ctx);
            break;
        }
        /* Call cmd specific .run if having more arguments to parse */
        status = ctx.cur_cmd->run(&ctx);
        if (status != 0) {
            break;
        }

        status = uvs_admin_next_subcmd(&ctx);
        if (status != 0) {
            break;
        }
    } while (uvs_admin_more_subcmd(&ctx));

    trace_log(uvs_admin_trace, status);
    trace_destroy(uvs_admin_trace);

    return status;
}

int32_t uvs_admin_branch_subcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    int32_t status;
    const struct option rootcmd_long_options[] = {
        {"help", no_argument, NULL, 0},
        {0, 0, 0, 0},
    };

    optind = 1;
    status = 0;
    for (;;) {
        ret =
            getopt_long(ctx->argc, ctx->argv, "+", rootcmd_long_options, NULL);
        if (ret == -1) {
            /*
             * getopt didn't recognize this argument. It might be a sub-command,
             * or, bad option. Just return and let sub-command handlers to
             * process it.
             */
            ctx->argc -= optind;
            ctx->argv += optind;
            break;
        }
        switch (ret) {
            case 0:
                uvs_admin_cmd_usages(ctx);
                status = -EBADMSG;
                break;
            case '?':
                /* Fall through */
            default:
                status = -EINVAL;
                break;
        }
        if (status != 0) {
            break;
        }
    }
    return status;
}
