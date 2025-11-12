/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: URMA client and server example
 * Author: Yan Fangfang
 * Create: 2021-8-26
 * Note:
 * History: 2021-8-26
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <pthread.h>
#include <malloc.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <semaphore.h>
#include "sys/mman.h"
#include "urma_api.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (0x1 << PAGE_SHIFT) // 4KB
#define MEM_SIZE 0x40000000           // 1GB
#define MAX_CLIENT_CNT 10
#define MAX_POLL_JFC_CNT 10
#define SLEEP_TIME (100 * 1000) /* Sleep for 100 ms */
#define TIMEOUT (-1) /* infinity */
#define MSG_SIZE 160
#define DEFAULT_PORT 13857
#define PROC_FILE_NAME 32
/* At most 8 outstanding WQEs can be posted in JFR with size of 256 */
#define RECV_BATCH_CNT 8
#define JETTY_SIZE 256
#define CR_NUM_A_ROUND 2 /* include a send and a recv */
/* #define SIMU 1 */

sem_t semaphore;

typedef struct argument {
    char *dev_name;
    char *server_ip;
    unsigned int server_port;
    bool event_mode;
    unsigned int trans_mode;
    bool multi_path;
    unsigned int tp_type;
    bool cs_coexist;      /* Client and server share the same process */
} argument_t;

typedef struct seg_jetty_info {
    /* Common */
    urma_eid_t eid;
    uint32_t uasid;
    /* segment */
    uint64_t seg_va;
    uint64_t seg_len;
    uint32_t seg_flag;
    uint32_t seg_token_id;
    /* jetty */
    urma_jetty_id_t jetty_id;
} __attribute__((packed)) seg_jetty_info_t;

typedef struct client {
    urma_target_seg_t *import_tseg; /* Imported target segment for read/write/atomic */
    urma_target_jetty_t *t_jetty;
} client_t;

typedef struct server {
    /* Server only */
    int listen_fd;
    uint8_t num_clients;
    int fd[MAX_CLIENT_CNT];
    pthread_t server_sock_thread;
    pthread_t server_jetty_thread;
    pthread_t server_watch_thread;
    bool server_stop;
    urma_target_jetty_t *t_jetty[MAX_CLIENT_CNT];
} server_t;

typedef struct context {
    argument_t args;
    urma_context_t *urma_ctx;
    urma_device_attr_t dev_attr;

    urma_jfce_t *jfce;
    urma_jfc_t *jfc;
    urma_jfr_t *jfr;
    urma_jetty_t *jetty;
    uint64_t rid;
    urma_token_t token;

    void *va;
    urma_target_seg_t *local_tseg; /* Exported target segment for read/write/atomic */

    /* Exchange info */
    urma_seg_t remote_seg;
    urma_jetty_id_t remote_jetty_id;
    union {
        client_t c;
        server_t s;
    };
} context_t;

static int init_urma_lib(const argument_t *args)
{
    urma_init_attr_t init_attr = {
        .uasid = 0,
    };
    if (urma_init(&init_attr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to urma init\n");
        return -1;
    }
    return 0;
}

static void inline uninit_urma_lib(void)
{
    urma_uninit();
}

static int get_eid_index(urma_device_t *dev)
{
    urma_eid_info_t *eid_list;
    uint32_t eid_cnt;
    int eid_index = -1;

    eid_list = urma_get_eid_list(dev, &eid_cnt);
    if (eid_list == NULL) {
        return -1;
    }
    for (int i = 0; eid_list != NULL && i < eid_cnt; i++) {
        printf("device_name :%s (eid%d: "EID_FMT").\n", dev->name, eid_list[i].eid_index, EID_ARGS(eid_list[i].eid));
    }
    if (eid_cnt > 0) {
        eid_index = eid_list[0].eid_index;
    }
    urma_free_eid_list(eid_list);
    return eid_index;
}

static urma_transport_mode_t args_to_trans_mode(const argument_t *args)
{
    switch (args->trans_mode) {
        case 0:
            return URMA_TM_RM;
        case 1:
            return URMA_TM_RC;
        case 2:
            return URMA_TM_UM;
        case 3:
            return URMA_TM_RC;
        default:
            return URMA_TM_RM;
    };
}

static urma_transport_mode_t args_to_tp_type(const argument_t *args)
{
    switch (args->tp_type) {
        case 0:
            return URMA_RTP;
        case 1:
            return URMA_CTP;
        case 2:
            return URMA_UTP;
        default:
            return URMA_RTP;
    };
}

static context_t *init_context(const argument_t *args)
{
    context_t *ctx = calloc(1, sizeof(context_t));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->args = *args;

    urma_device_t *urma_dev = urma_get_device_by_name(args->dev_name);
    if (urma_dev == NULL) {
        fprintf(stderr, "urma get device by name failed!\n");
        goto UNINIT;
    }

    if (urma_query_device(urma_dev, &ctx->dev_attr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to query device %s.\n", args->dev_name);
        goto UNINIT;
    }

    int eid_index = get_eid_index(urma_dev);
    if (eid_index < 0) {
        fprintf(stderr, "Failed to get eid index\n");
        goto UNINIT;
    }

    ctx->urma_ctx = urma_create_context(urma_dev, (uint32_t)eid_index);
    if (ctx->urma_ctx == NULL) {
        fprintf(stderr, "Failed to create instance\n");
        goto UNINIT;
    }
    ctx->token.token = 0xACFE;

    ctx->jfce = urma_create_jfce(ctx->urma_ctx);
    if (ctx->jfce == NULL) {
        fprintf(stderr, "Failed to create jfce\n");
        goto DEL_CTX;
    }

    urma_jfc_cfg_t jfc_cfg = {
        .depth = ctx->dev_attr.dev_cap.max_jfc_depth,
        .flag = {.value = 0},
        .jfce = ctx->jfce,
        .user_ctx = (uint64_t)NULL,
    };
    ctx->jfc = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
    if (ctx->jfc == NULL) {
        fprintf(stderr, "Failed to create jfc\n");
        goto DEL_JFCE;
    }

    if (args->event_mode && urma_rearm_jfc(ctx->jfc, false) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to rearm jfc\n");
        goto DEL_JFC;
    }

    urma_jfr_cfg_t jfr_cfg = {
        .depth = JETTY_SIZE,
        .flag.bs.tag_matching = URMA_NO_TAG_MATCHING,
        .flag.bs.order_type = args->trans_mode == 3 ? 1 : 0,
        .trans_mode = args_to_trans_mode(args),
        .min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER,
        .jfc = ctx->jfc,
        .token_value = ctx->token,
        .id = 0,
        .max_sge = 1
    };
    ctx->jfr = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
    if (ctx->jfr == NULL) {
        fprintf(stderr, "Failed to create jfr\n");
        goto DEL_JFC;
    }

    urma_jfs_cfg_t jfs_cfg = {
        .depth = JETTY_SIZE,
        .flag.bs.order_type = args->trans_mode == 3 ? 1 : 0,
        .flag.bs.multi_path = args->multi_path ? 1 : 0,
        .trans_mode = args_to_trans_mode(args),
        .priority = URMA_MAX_PRIORITY, /* Highest priority */
        .max_sge = 1,
        .max_inline_data = 0,
        .rnr_retry = URMA_TYPICAL_RNR_RETRY,
        .err_timeout = URMA_TYPICAL_ERR_TIMEOUT,
        .jfc = ctx->jfc,
        .user_ctx = (uint64_t)NULL
    };
    urma_jetty_cfg_t jetty_cfg = {
        .flag.bs.share_jfr = 1,
        .jfs_cfg = jfs_cfg,
        //.shared.jfc = ctx->jfc,
        .shared.jfr = ctx->jfr
    };
    ctx->jetty = urma_create_jetty(ctx->urma_ctx, &jetty_cfg);
    if (ctx->jetty == NULL) {
        fprintf(stderr, "Failed to create jetty\n");
        goto DEL_JFR;
    }

    ctx->va = memalign(PAGE_SIZE, MEM_SIZE);
    if (ctx->va == NULL) {
        fprintf(stderr, "Failed to alloc buffer \n");
        goto DEL_JETTY;
    }
    (void)memset(ctx->va, 0, MEM_SIZE);

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = URMA_TOKEN_NONE,
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
        .bs.token_id_valid = 0,
        .bs.reserved = 0
    };

    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)ctx->va,
        .len = MEM_SIZE,
        .token_id = NULL,
        .token_value = ctx->token,
        .flag = flag,
        .user_ctx = (uintptr_t)NULL,
        .iova = 0
    };

    ctx->local_tseg = urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (ctx->local_tseg == NULL) {
        fprintf(stderr, "Failed to register segment\n");
        goto FREE_VA;
    }

    return ctx;

FREE_VA:
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        munmap(ctx->va, MEM_SIZE);
    } else {
        free(ctx->va);
    }
DEL_JETTY:
    urma_delete_jetty(ctx->jetty);
DEL_JFR:
    urma_delete_jfr(ctx->jfr);
DEL_JFC:
    urma_delete_jfc(ctx->jfc);
DEL_JFCE:
    urma_delete_jfce(ctx->jfce);
DEL_CTX:
    (void)urma_delete_context(ctx->urma_ctx);
UNINIT:
    (void)urma_uninit();
    free(ctx);
    return NULL;
}

static void uninit_context(context_t *ctx)
{
    (void)urma_unregister_seg(ctx->local_tseg);
    (void)urma_delete_jetty(ctx->jetty);
    (void)urma_delete_jfr(ctx->jfr);
    (void)urma_delete_jfc(ctx->jfc);
    (void)urma_delete_jfce(ctx->jfce);
    if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        munmap(ctx->va, MEM_SIZE);
    } else {
        free(ctx->va);
    }

    (void)urma_delete_context(ctx->urma_ctx);
    free(ctx);
}

static void pack_seg_jetty_info(seg_jetty_info_t *info, context_t *ctx)
{
    (void)memset(info, 0, sizeof(seg_jetty_info_t));
    info->eid = ctx->urma_ctx->eid;
    info->uasid = ctx->urma_ctx->uasid;
    info->seg_va = ctx->local_tseg->seg.ubva.va;
    info->seg_len = ctx->local_tseg->seg.len;
    info->seg_flag = ctx->local_tseg->seg.attr.value;
    info->seg_token_id = ctx->local_tseg->seg.token_id;
    info->jetty_id = ctx->jetty->jetty_id;
    printf("seg: eid = "EID_FMT", uasid = 0x%x, va = 0x%lx\n", EID_ARGS(info->eid), info->uasid, info->seg_va);
    printf("jetty: eid = "EID_FMT", uasid = 0x%x, id = %d\n", EID_ARGS(info->eid), info->uasid, info->jetty_id.id);
}

static void unpack_seg_jetty_info(seg_jetty_info_t *info, context_t *ctx)
{
    ctx->remote_seg.ubva.eid = info->eid;
    ctx->remote_seg.ubva.uasid = info->uasid;
    ctx->remote_seg.ubva.va = info->seg_va;
    ctx->remote_seg.len = info->seg_len;
    ctx->remote_seg.attr.value = info->seg_flag;
    ctx->remote_seg.token_id = info->seg_token_id;
    ctx->remote_jetty_id = info->jetty_id;
}

static int poll_jfc_wait(context_t *ctx, urma_cr_t *cr)
{
    urma_jfc_t *ev_jfc;
    int cnt;

    if (ctx->args.event_mode) {
        cnt = urma_wait_jfc(ctx->jfce, 1, TIMEOUT, &ev_jfc);
        if (cnt < 0 || (cnt == 1 && ctx->jfc != ev_jfc)) {
            fprintf(stderr, "Failed to wait jfc\n");
            return -1;
        }
        cnt = urma_poll_jfc(ctx->jfc, 1, cr);
        if (cnt <= 0 || cr->status != URMA_CR_SUCCESS) {
            return -1;
        }
        uint32_t ack_cnt = 1;
        urma_ack_jfc((urma_jfc_t **)&ev_jfc, &ack_cnt, 1);
        if (urma_rearm_jfc(ctx->jfc, false) != URMA_SUCCESS) {
            return -1;
        }
        return 0;
    }

    for (int i = 0; i < MAX_POLL_JFC_CNT; i++) {
        cnt = urma_poll_jfc(ctx->jfc, 1, cr);
        if (cnt < 0) {
            fprintf(stderr, "Failed to poll jfc, return_value of urma_poll_jfc is %d\n", cnt);
            return -1;
        } else if (cnt > 0) {
            if (cr->status == URMA_CR_SUCCESS) {
                return 0;
            } else {
                fprintf(stderr, "Failed to poll jfc, cr_status:%d\n", cr->status);
                return -1;
            }
        }
        usleep(SLEEP_TIME);
    }
    return -1;
}

static int sock_sync_data(int sockfd, int size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;

    rc = write(sockfd, local_data, (size_t)size);
    if (rc < size) {
        (void)fprintf(stderr, "Failed writing data during sock_sync_data, errno: %s.\n", strerror(errno));
    } else {
        rc = 0;
    }

    while (rc == 0 && total_read_bytes < size) {
        read_bytes = read(sockfd, remote_data, (size_t)size);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }

    return rc;
}

static int client_connect(context_t *ctx, const argument_t *args)
{
    struct sockaddr_in addr;
    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create socket: %d\n", errno);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->server_port);
    addr.sin_addr.s_addr = inet_addr(args->server_ip);
    printf("s_addr=0x%x, sin_port=0x%x\n", addr.sin_addr.s_addr, addr.sin_port);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr))) {
        fprintf(stderr, "Failed to connect, err: [%d]%s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    seg_jetty_info_t local = {0}, remote = {0};
    pack_seg_jetty_info(&local, ctx);
    if (sock_sync_data(sockfd, sizeof(seg_jetty_info_t), (char*)&local, (char*)&remote)) {
        fprintf(stderr, "Failed to exchange segment and jfr info\n");
    }
    unpack_seg_jetty_info(&remote, ctx);

    printf("remote seg: eid = "EID_FMT", uasid = 0x%x, va = 0x%lx\n",
        EID_ARGS(remote.eid), remote.uasid, remote.seg_va);
    printf("remote jetty: eid = "EID_FMT", uasid = 0x%x id = %d\n",
        EID_ARGS(remote.eid), remote.uasid, remote.jetty_id.id);

    char sync_msg;
    if (sock_sync_data(sockfd, 1, "S", &sync_msg)) {
        fprintf(stderr, "Failed to sync\n");
    }

    close(sockfd);
    return 0;
}

static urma_target_jetty_t *sample_import_jetty(context_t *ctx, const struct argument *args)
{
    urma_rjetty_t remote_jetty = {
        .jetty_id = ctx->remote_jetty_id,
        .trans_mode = args_to_trans_mode(args),
        .type = URMA_JETTY,
        .tp_type = args_to_tp_type(args),
        .flag.bs.order_type = args->trans_mode == 3 ? 1 : 0,
        .flag.bs.share_tp = args->trans_mode == 3 ? 1 : 0
    };
    printf("import remote jetty: eid = "EID_FMT", id = %d\n",
        EID_ARGS(remote_jetty.jetty_id.eid), remote_jetty.jetty_id.id);
    urma_target_jetty_t *t_jetty = urma_import_jetty(ctx->urma_ctx, &remote_jetty, &ctx->token);
    if (t_jetty == NULL) {
        fprintf(stderr, "Failed to import jfr\n");
        return NULL;
    }
    if ((args->trans_mode == 1) || (args->trans_mode == 3)) {
        if (urma_bind_jetty(ctx->jetty, t_jetty) != URMA_SUCCESS) {
            fprintf(stderr, "Failed to bind jetty\n");
            (void)urma_unimport_jetty(t_jetty);
            return NULL;
        }
        printf("bind jetty success.\n");
    }
    return t_jetty;
}

static void *server_sock_thread_main(void *arg)
{
    int fd = -1;
    context_t *ctx = (context_t *)arg;
    seg_jetty_info_t local = {0};
    char sync_msg;

    pack_seg_jetty_info(&local, ctx);

    while (ctx->s.server_stop == false && ctx->s.num_clients < MAX_CLIENT_CNT) {
        seg_jetty_info_t remote = {0};

        fd = accept(ctx->s.listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                fprintf(stderr, "Failed to accept connection\n");
                return NULL;
            }
        }

        if (sock_sync_data(fd, sizeof(seg_jetty_info_t), (char*)&local, (char*)&remote)) {
            fprintf(stderr, "Failed to exchange segment and jfr info\n");
        }
        unpack_seg_jetty_info(&remote, ctx);

        printf("remote seg: eid = "EID_FMT", uasid = 0x%x, va = 0x%lx\n",
            EID_ARGS(remote.eid), remote.uasid, remote.seg_va);
        printf("remote jetty: eid = "EID_FMT", uasid = 0x%x id = %d\n",
            EID_ARGS(remote.eid), remote.uasid, remote.jetty_id.id);

        ctx->s.t_jetty[ctx->s.num_clients] = sample_import_jetty(ctx, &ctx->args);
        ctx->s.fd[ctx->s.num_clients] = fd;

        if (sock_sync_data(fd, 1, "S", &sync_msg)) {
            fprintf(stderr, "Failed to sync\n");
        }
        ctx->s.num_clients++;
        sem_post(&semaphore);
        printf("accepted new connection\n");
    }
    for (int i = 0; i < ctx->s.num_clients; i++) {
        urma_unimport_jetty(ctx->s.t_jetty[i]);
    }

    return NULL;
}

static int server_reply_to_client(context_t *ctx, urma_cr_t *cr)
{
    urma_jetty_id_t src_jetty_id = cr->remote_id;
    urma_target_jetty_t *t_jetty = NULL;

    for (uint8_t i = 0; i < ctx->s.num_clients; i++) {
        t_jetty = ctx->s.t_jetty[i];
        if (memcmp(&t_jetty->id.eid, &src_jetty_id.eid, sizeof(urma_eid_t)) == 0 &&
            t_jetty->id.uasid == src_jetty_id.uasid) {
            break;
        }
    }
    if (t_jetty == NULL) {
        fprintf(stderr, "Failed to find the target jetty to send response\n");
        return -1;
    }

    uint64_t offset = cr->user_ctx;
    urma_sge_t src_sge = {
        .addr = (uint64_t)ctx->va + offset,
        .len = MSG_SIZE,
        .tseg = ctx->local_tseg
    };
    urma_sg_t sg = {
        .sge = &src_sge,
        .num_sge = 1
    };
    urma_send_wr_t send_wr = {
        .src = sg
    };

    urma_jfs_wr_t jfs_wr = {
        .opcode = URMA_OPC_SEND,
        .flag.bs.complete_enable = 1,
        .tjetty = t_jetty,
        .user_ctx = offset,
        .send = send_wr,
        .next = NULL
    };
    urma_jfs_wr_t *bad_jfs_wr = NULL;

    if (snprintf(ctx->va + offset, MSG_SIZE, "Send response from server %d", getpid()) == -1) {
        fprintf(stderr, "fail to prepare the sending response\n");
        return -1;
    }
    if (urma_post_jetty_send_wr(ctx->jetty, &jfs_wr, &bad_jfs_wr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to send response\n");
        return -1;
    }
    return 0;
}

static void *server_jetty_thread_main(void *arg)
{
    context_t *ctx = (context_t *)arg;
    urma_sge_t src_sge = {0};
    urma_sg_t src_sg = {0};
    urma_jfr_wr_t wr = {0};
    urma_jfr_wr_t *bad_wr = NULL;

    /* Usage of ctx buffer starting from ctx->va at server side:
     * [0, MSG_SIZE - 1 ] for urma read/write and cas from client
     * the rest memory [MSG_SIZE, MEM_SIZE - 1] for urma recv
     */
    sem_wait(&semaphore);
    uint64_t offset = MSG_SIZE;
    for (int i = 0; i < RECV_BATCH_CNT; i++) {
        if (offset + MSG_SIZE > MEM_SIZE) {
            return NULL;
        }

        src_sge.addr = (uint64_t)ctx->va + offset;
        src_sge.len = MSG_SIZE;
        src_sge.tseg = ctx->local_tseg;
        src_sg.sge = &src_sge;
        src_sg.num_sge = 1;
        wr.src = src_sg;
        wr.user_ctx = offset;
        wr.next = NULL;
        if (urma_post_jetty_recv_wr(ctx->jetty, &wr, &bad_wr) != URMA_SUCCESS) {
            fprintf(stderr, "Failed to recv %i in server jfr thread\n", i);
            return NULL;
        }
        offset += MSG_SIZE;
    }

    while (ctx->s.server_stop == false) {
        urma_cr_t cr = {0};
        if (poll_jfc_wait(ctx, &cr) != 0) {
            continue;
        }
        offset = cr.user_ctx;
        if (cr.opcode == URMA_CR_OPC_WRITE_WITH_IMM) {
            printf("Msg received: %s with imm data %ld\n", (char *)ctx->va, cr.imm_data);
            continue;
        }
        /* Reuse buffer indicated by the completion */
        if (cr.opcode == URMA_CR_OPC_SEND) {
            printf("Msg received: %s at offset %ld\n", (char *)(ctx->va + offset), offset);
            src_sge.addr = (uint64_t)ctx->va + offset;
            wr.user_ctx = offset;
            if (urma_post_jetty_recv_wr(ctx->jetty, &wr, &bad_wr) != URMA_SUCCESS) {
                fprintf(stderr, "Failed to recv in server jetty thread\n");
                return NULL;
            }
            if (cr.flag.bs.s_r == 1 && server_reply_to_client(ctx, &cr) != 0) {
                break;
            }
        } else {
            printf("Response sent to client successfully\n");
        }
    }
    return NULL;
}

static void *server_watch_thread_main(void *arg)
{
    context_t *ctx = (context_t *)arg;

    while (ctx->s.server_stop == false) {
        sleep(1);
        printf("segment msg: %s\n", (char*)ctx->va);
    }
    return NULL;
}

static int set_socket_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        fprintf(stderr, "Failed to get flags of client socket, err:%d.\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, (uint32_t)flags | O_NONBLOCK) == -1) {
        fprintf(stderr, "Failed to set socket to non block, err:%d.\n", errno);
        return -1;
    }
    return 0;
}

static int server_listen(context_t *ctx, const argument_t *args)
{
    int ret;
    int enable = 1;

    ctx->s.listen_fd = socket(AF_INET, (int)SOCK_STREAM, 0);
    if (ctx->s.listen_fd < 0) {
        fprintf(stderr, "Failed to create socket_fd, err: [%d]%s.\n", errno, strerror(errno));
        return -1;
    }
    if (setsockopt(ctx->s.listen_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
        fprintf(stderr, "Failed to setsockopt, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }
    if (set_socket_nonblock(ctx->s.listen_fd)) {
        (void)close(ctx->s.listen_fd);
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(args->server_port);
    if (bind(ctx->s.listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
        fprintf(stderr, "Failed to bind, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }
    if (listen(ctx->s.listen_fd, MAX_CLIENT_CNT)) {
        fprintf(stderr, "Failed to listen, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }

    // Initialize the semaphore with an initial value of 0
    // Ensuring that RC binds Jetty before usage
    sem_init(&semaphore, 0, 0);
    ctx->s.server_stop = false;
    ret = pthread_create(&ctx->s.server_sock_thread, NULL, server_sock_thread_main, ctx);
    if (ret) {
        fprintf(stderr, "Failed to create server thread, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }

    ret = pthread_create(&ctx->s.server_jetty_thread, NULL, server_jetty_thread_main, ctx);
    if (ret) {
        fprintf(stderr, "Failed to create server thread, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }
    ret = pthread_create(&ctx->s.server_watch_thread, NULL, server_watch_thread_main, ctx);
    sem_destroy(&semaphore);
    if (ret) {
        fprintf(stderr, "Failed to create server thread, err: [%d]%s.\n", errno, strerror(errno));
        (void)close(ctx->s.listen_fd);
        return -1;
    }
    return 0;
}

static void server_stop(context_t *ctx)
{
    ctx->s.server_stop = true;
    (void)pthread_join(ctx->s.server_sock_thread, NULL);
    (void)pthread_join(ctx->s.server_jetty_thread, NULL);
    (void)pthread_join(ctx->s.server_watch_thread, NULL);
    for (uint8_t i = 0; i < ctx->s.num_clients; i++) {
        close(ctx->s.fd[i]);
    }
    close(ctx->s.listen_fd);
}

int prepare_client(const struct argument *args, context_t *ctx)
{
    int ret = -1;

    if (client_connect(ctx, args)) {
        fprintf(stderr, "Failed to connect server %s:%d\n", args->server_ip, args->server_port);
        goto DEL_CTX;
    }

    urma_import_seg_flag_t flag = {
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
        .bs.mapping = URMA_SEG_NOMAP,
        .bs.reserved = 0
    };

    ctx->c.import_tseg = urma_import_seg(ctx->urma_ctx, &ctx->remote_seg, &ctx->token, 0, flag);
    if (ctx->c.import_tseg == NULL) {
        fprintf(stderr, "Failed to import segment\n");
        goto DEL_CTX;
    }

    ctx->c.t_jetty = sample_import_jetty(ctx, args);
    if (ctx->c.t_jetty == NULL) {
        fprintf(stderr, "Failed to import jetty in client.\n");
        goto UNIMPORT_SEG;
    }

    return 0;

UNIMPORT_SEG:
    (void)urma_unimport_seg(ctx->c.import_tseg);
DEL_CTX:
    uninit_context(ctx);
    return ret;
}

void destroy_client(context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    (void)urma_unimport_jetty(ctx->c.t_jetty);
    (void)urma_unimport_seg(ctx->c.import_tseg);
    uninit_context(ctx);
}

int prepare_server(const struct argument *args, context_t *ctx)
{
    /* Outofband socket */
    if (server_listen(ctx, args) == 0) {
        return 0;
    }

    uninit_context(ctx);
    return -1;
}

void destroy_server(context_t *ctx)
{
    server_stop(ctx);
    uninit_context(ctx);
}

static int client_write_read(context_t *ctx)
{
    if (snprintf(ctx->va, MSG_SIZE, "hello,this is user %d", getpid()) == -1) {
        fprintf(stderr, "fail to prepare the writing message\n");
        return -1;
    }

    urma_sge_t src_sge = {
        .addr = (uint64_t)ctx->va,
        .len = MSG_SIZE,
        .tseg = ctx->local_tseg
    };
    urma_sge_t dst_sge = {
        .addr = ctx->remote_seg.ubva.va,
        .len = MSG_SIZE,
        .tseg = ctx->c.import_tseg
    };
    urma_sg_t src_sg = {
        .sge = &src_sge,
        .num_sge = 1
    };
    urma_sg_t dst_sg = {
        .sge = &dst_sge,
        .num_sge = 1
    };
    urma_rw_wr_t rw = {
        .src = src_sg,
        .dst = dst_sg
    };
    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_WRITE,
        .flag.bs.complete_enable = 1,
        .flag.bs.inline_flag = 0,
        .tjetty = ctx->c.t_jetty,
        .user_ctx = ctx->rid,
        .rw = rw,
        .next = NULL
    };
    urma_jfs_wr_t *bad_wr = NULL;
    if (urma_post_jetty_send_wr(ctx->jetty, &wr, &bad_wr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to post write\n");
        return -1;
    }

    urma_cr_t cr = {0};
    if (poll_jfc_wait(ctx, &cr) != 0 || cr.user_ctx != ctx->rid) {
        fprintf(stderr, "Failed to poll jfc for write, cr_status:%d, ctx:%lu, rid:%lu,\n",
            cr.status, cr.user_ctx, ctx->rid);
        return -1;
    }

    printf("Msg write: %s\n", (char *)ctx->va);
    ctx->rid++;

    (void)memset(ctx->va, 0, MEM_SIZE);

    rw.dst = src_sg;
    rw.src = dst_sg;
    wr.rw = rw;
    wr.opcode = URMA_OPC_READ;
    wr.user_ctx = ctx->rid;

    if (urma_post_jetty_send_wr(ctx->jetty, &wr, &bad_wr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to read\n");
        return -1;
    }

    if (poll_jfc_wait(ctx, &cr) != 0 || cr.user_ctx != ctx->rid) {
        fprintf(stderr, "Failed to poll jfc for read, cr_status:%d,\n", cr.status);
        return -1;
    }

    printf("Msg read: %s\n", (char *)ctx->va);
    ctx->rid++;
    return 0;
}

static int client_send(context_t *ctx)
{
    /* Post buffer to recv reponse from server */
    uint64_t offset = MSG_SIZE;
    urma_sge_t src_sge = {
        .addr = (uint64_t)ctx->va + offset,
        .len = MSG_SIZE,
        .tseg = ctx->local_tseg
    };
    urma_sg_t src_sg = {
        .sge = &src_sge,
        .num_sge = 1
    };
    urma_jfr_wr_t wr = {
        .src = src_sg,
        .user_ctx = offset,
        .next = NULL
    };
    urma_jfr_wr_t *bad_wr = NULL;
    if (urma_post_jetty_recv_wr(ctx->jetty, &wr, &bad_wr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to post buffer to recv response");
        return -1;
    }

    if (snprintf(ctx->va, MSG_SIZE, "Send message from user %d", getpid()) == -1) {
        fprintf(stderr, "fail to prepare the sending message\n");
        return -1;
    }
    src_sge.addr = (uint64_t)ctx->va;
    urma_send_wr_t send_wr = {
        .src = src_sg,
        .tseg = ctx->local_tseg
    };


    urma_jfs_wr_t jfs_wr = {
        .opcode = URMA_OPC_SEND,
        .flag.bs.complete_enable = 1,
        .tjetty = ctx->c.t_jetty,
        .user_ctx = ctx->rid,
        .send = send_wr,
        .next = NULL
    };
    urma_jfs_wr_t *bad_jfs_wr = NULL;
    if (urma_post_jetty_send_wr(ctx->jetty, &jfs_wr, &bad_jfs_wr) != URMA_SUCCESS) {
        fprintf(stderr, "Failed to send message\n");
        return -1;
    }
    
    urma_cr_t cr;
    for (int i = 0; i < CR_NUM_A_ROUND; i++) {
        int cr_ret = poll_jfc_wait(ctx, &cr);
        if (cr.flag.bs.s_r == 0) {
            if (cr_ret != 0 || cr.user_ctx != ctx->rid) {
                fprintf(stderr, "Failed to poll jfc for send, cr_status:%d, cr_ret = %d\n", cr.status, cr_ret);
                return -1;
            }
            printf("Msg sent: %s\n", (char *)ctx->va);
        } else {
            if (cr_ret != 0 || cr.user_ctx != offset) {
                fprintf(stderr, "Failed to recv response, cr_status:%d, cr_ret = %d\n", cr.status, cr_ret);
                return -1;
            }
            printf("Response received: %s at offset %ld\n", (char *)(ctx->va + offset), offset);
        }
    }
    return 0;
}

static int run_client(const struct argument *args)
{
    int ret;
    context_t *ctx = init_context(args);
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize URMA context\n");
        return -1;
    }

    ret = prepare_client(args, ctx);
    if (ret != 0) {
        return ret;
    }

    ret = client_write_read(ctx);
    if (ret != 0) {
        destroy_client(ctx);
        return ret;
    }

    ret = client_send(ctx);
    destroy_client(ctx);
    return ret;
}

static int run_server(const struct argument *args)
{
    int ret;

    context_t *ctx = init_context(args);
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize URMA context\n");
        return -1;
    }

    ret = prepare_server(args, ctx);
    if (ret != 0) {
        return ret;
    }

    printf("Type to exit...\n");
    printf("%c\n", getchar());

    destroy_server(ctx);
    return 0;
}

static struct option g_long_options[] = {
    {"trans-mode", required_argument, NULL, 'm'},
    {"dev-name", required_argument, NULL, 'd'},
    {"server-ip", required_argument, NULL, 'i'},
    {"server-port", required_argument, NULL, 'p'},
    {"tp-type", required_argument, NULL, 't'},
    {"multi-path", required_argument, NULL, 'u'},
    {"event-mode", no_argument, NULL, 'e'},
    {"cs-coexist", no_argument, NULL, 'c'},
    {NULL, 0, NULL, 0}
};

static void usage()
{
    printf("Usage:\n");
    printf("  -m, --trans-mode <mode>    urma mode: 0 for RM, 1 for RC, 2 for UM, 3 for RS (default 0)\n");
    printf("  -d, --dev-name <dev>       device name, e.g. udma for UB\n");
    printf("  -i, --server-ip <ip>       server ip address given only by client\n");
    printf("  -p, --server-port <port>   listen on/connect to port <port> (default 18515)\n");
    printf("  -t, --tp-type <type>       0 for URMA_RTP, 1 for URMA_CTP, 2 for URMA_UTP\n");
    printf("  -u, --multi-path           use multipath instead of single path (default false)\n");
    printf("  -e, --event-mode           demo jfc event (default false)\n");
    printf("  -c, --cs-coexist           client and server coexist in a process (default false)\n");
}

static int validate_input_params(struct argument *args, bool tp_type_input_flag, bool multi_path_input_flag)
{
    if (args->trans_mode > 3) {
        fprintf(stderr, "Invalid trans mode %d\n", args->trans_mode);
        return -1;
    }

    if (args->tp_type > 2) {
        fprintf(stderr, "Invalid tp type %d\n", args->tp_type);
        return -1;
    }

    // Determine whether it is a bonding device based on the name
    if (strncmp(args->dev_name, "bonding", strlen("bonding")) == 0) {
        if (tp_type_input_flag) {
            fprintf(stderr, "Warning: TP type should not be set for bonding device.\n");
        }
        if (!((args->trans_mode == 0 && args->multi_path == true) || (args->trans_mode == 1))) {
            fprintf(stderr, "Error: This combination of trans-mode and multi-path is invalid on bonding devices.\n");
            return -1;
        }
        char* loopback = "127.0.0.1";
        if (args->event_mode && args->server_ip != NULL &&
        strncmp(args->server_ip, loopback, strlen(loopback)) == 0 && args->multi_path) {
            fprintf(stderr, "Error: If using the -c option, bonding only supports RC + single_path in loopback.\n");
            return -1;
        }
    } else {
        if (multi_path_input_flag) {
            fprintf(stderr, "Error: Multi path should not be set for non-bonding device.\n");
            return -1;
        }
        if (!(((args->trans_mode != 2) && (args->tp_type != 2)) || (args->trans_mode == 2 && args->tp_type == 2))) {
            fprintf(stderr, "Error: This combination of tp-type and trans-mode is invalid on non-bonding device.\n");
            return -1;
        }
    }

    return 0;
}

/* Parse the command line parameters for client and server */
int parse_arguments(int argc, char *argv[], struct argument *args)
{
    if (argc == 1) {
        usage();
        return -1;
    }

    args->server_port = DEFAULT_PORT;
    args->event_mode = false;
    args->cs_coexist = false;
    args->trans_mode = 0;

    // Used to record whether the user explicitly entered these two parameters.
    bool multi_path_input_flag = false;
    bool tp_type_input_flag = false;

    while (1) {
        int c;
        c = getopt_long(argc, argv, "m:d:i:p:t:uec", g_long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'm':
                args->trans_mode = strtoul(optarg, NULL, 0);
                break;
            case 'd':
                args->dev_name = strdup(optarg);
                if (args->dev_name == NULL) {
                    fprintf(stderr, "failed to allocate memory.\n");
                }
                break;
            case 'i':
                args->server_ip = strdup(optarg);
                if (args->server_ip == NULL) {
                    fprintf(stderr, "failed to allocate memory.\n");
                }
                break;
            case 'p':
                args->server_port = strtoul(optarg, NULL, 0);
                break;
            case 't':
                args->tp_type = strtoul(optarg, NULL, 0);
                tp_type_input_flag = true;
                break;
            case 'u':
                args->multi_path = true;
                multi_path_input_flag = true;
                break;
            case 'e':
                args->event_mode = true;
                break;
            case 'c':
                args->cs_coexist = true;
            default:
                usage();
                return -1;
        }
    }

    // Determine if there are any unprocessed parameters.
    if (optind < argc) {
        usage();
        return -1;
    }

    return validate_input_params(args, tp_type_input_flag, multi_path_input_flag);
}

static void *client_thread_main(void *args)
{
    (void)run_client((struct argument *)args);
    return NULL;
}

int run_client_server(struct argument *args)
{
    int ret;
    pthread_t client_thread;

    ret = pthread_create(&client_thread, NULL, client_thread_main, args);
    if (ret) {
        fprintf(stderr, "Failed to create client thread\n");
        return ret;
    }

    context_t *ctx = init_context(args);
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize URMA context\n");
        return -1;
    }

    ret = prepare_server(args, ctx);
    if (ret != 0) {
        return ret;
    }

    printf("Type to exit...\n");
    printf("%c\n", getchar());

    destroy_server(ctx);
    return 0;
}

int main(int argc, char *argv[])
{
    struct argument args = {0};
    int ret;

    ret = parse_arguments(argc, argv, &args);
    if (ret != 0) {
        goto main_exit;
    }

    ret = init_urma_lib(&args);
    if (ret != 0) {
        goto main_exit;
    }
    if (args.cs_coexist) {
        run_client_server(&args);
    } else {
        if (args.server_ip != NULL) {
            ret = run_client(&args);
        } else {
            ret = run_server(&args);
        }
    }
    uninit_urma_lib();

main_exit:
    if (args.dev_name != NULL) {
        free(args.dev_name);
    }
    if (args.server_ip != NULL) {
        free(args.server_ip);
    }
    return ret;
}
