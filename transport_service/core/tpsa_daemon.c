/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa daemon main file
 * Author: Chen Wen
 * Create: 2022-08-24
 * Note:
 * History: 2022-08-24: Create file
 */

#define _GNU_SOURCE
#include <ifaddrs.h>

#include <errno.h>

#include "ub_util.h"
#include "ub_shash.h"
#include "tpsa_log.h"
#include "tpsa_config.h"
#include "tpsa_worker.h"
#include "tpsa_net.h"

typedef struct tpsa_daemon_context {
    bool keeper_runnig;
    pthread_t keeper_thread;
    tpsa_worker_t *worker;
} tpsa_daemon_ctx_t;

static tpsa_daemon_ctx_t g_tpsa_daemon_ctx;

static void tpsa_sig_cb_func(int signal)
{
    g_tpsa_daemon_ctx.keeper_runnig = false;
}

static void tpsa_register_signal(void)
{
    struct sigaction psa;
    psa.sa_flags = 0;
    psa.sa_handler = tpsa_sig_cb_func;
    (void)sigaction(SIGTSTP, &psa, NULL); /* need SIGTSTP to kill */
}

static void *tpsa_keeper_thread_main(void *arg)
{
    tpsa_daemon_ctx_t *ctx = (tpsa_daemon_ctx_t *)arg;
    if (ctx == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    (void)pthread_setname_np(pthread_self(), (const char *)"tpsa_keeper_thread");

    while (ctx->keeper_runnig == true) {
        (void)sleep(1); /* prevent 100% CPU usage of tpsa daemon process */
    }
    return NULL;
}

static int tpsa_keeper_thread_init(void)
{
    int ret;
    pthread_attr_t attr;

    g_tpsa_daemon_ctx.keeper_runnig = true;
    (void)pthread_attr_init(&attr);
    ret = pthread_create(&g_tpsa_daemon_ctx.keeper_thread, &attr, tpsa_keeper_thread_main, &g_tpsa_daemon_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("pthread create failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
    }
    (void)pthread_attr_destroy(&attr);
    TPSA_LOG_INFO("keeper runnig succeed\n");
    (void)pthread_join(g_tpsa_daemon_ctx.keeper_thread, NULL);
    return ret;
}

int main(int argc, char *argv[])
{
    /* tpsa log init */
    tpsa_log_init();
    tpsa_log_set_level((unsigned)TPSA_VLOG_LEVEL_INFO);
    /* must call net init before config init */
    if (tpsa_net_init() != 0) {
        goto tpsa_log_uninit;
    }

    /* parse config file and set configuration */
    if (tpsa_config_init() < 0) {
        goto tpsa_net_uninit;
    }
    TPSA_LOG_INFO("tpsa init config successfully!\n");

    tpsa_worker_t *worker = tpsa_worker_init();
    if (worker == NULL) {
        goto tpsa_config_uninit;
    }
    g_tpsa_daemon_ctx.worker = worker;

    /* In order to receive the process stop signal */
    tpsa_register_signal();

    if (tpsa_keeper_thread_init() != 0) {
        goto tpsa_worker_unint;
    }
    TPSA_LOG_INFO("tpsa daemon exited!\n");

tpsa_worker_unint:
    tpsa_worker_unint(g_tpsa_daemon_ctx.worker);
tpsa_config_uninit:
    tpsa_config_uninit();
tpsa_net_uninit:
    tpsa_net_uninit();
tpsa_log_uninit:
    tpsa_log_uninit();
    return 0;
}