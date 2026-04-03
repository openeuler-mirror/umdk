/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: urma test_framework
*/

#include <arpa/inet.h>
#include <getopt.h>
#include <malloc.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "urma_atom.h"

#define RETRY_CNT 10
#define EPOLL_TMOUT 100
#define EPOLL_CNT 32
#define NO_SHARE_TP 0
#define SHARE_TP 1
#define POLL_JFC_WAIT_TIME 8
#define UNI_TOKEN 0

test_urma_ctx_t *create_default_ctx(test_context_t *test_ctx)
{
    int ret;
    test_urma_ctx_t *ctx = NULL;
    CHECK_JUMP(test_ctx == NULL, EXIT, "test_ctx=NULL\n");

    ret = test_init_urma();
    CHECK_JUMP(ret != 0, EXIT, "test_init_urma ret=%d\n", ret);
    ctx = test_create_ctx(test_ctx);
    CHECK_JUMP(ctx == NULL, EXIT, "test_create_ctx ctx=NULL\n");
    ret = test_create_urma_ctx(ctx);
    CHECK_JUMP(ret != 0, EXIT, "test_create_urma_ctx ret=%d\n", ret);
    test_set_default_ctx_num(ctx);
    test_set_default_ctx_cfg(ctx);
    ret = test_create_resource(ctx);
    CHECK_JUMP(ret != 0, EXIT, "test_create_resource ret=%d\n", ret);
    ret = test_exchange_resource(ctx);
    CHECK_JUMP(ret != 0, EXIT, "test_exchange_resource ret=%d\n", ret);
    ret = test_import_resource(ctx);
    CHECK_JUMP(ret != 0, EXIT, "test_import_resource ret=%d\n", ret);

    return ctx;
EXIT:
    delete_default_ctx(ctx);
    return NULL;
}

void delete_default_ctx(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    test_unimport_resource(ctx);
    test_delete_resource(ctx);
    test_delete_ctx(ctx);
    urma_uninit();
}

test_urma_ctx_t *test_create_ctx(test_context_t *test_ctx)
{
    CHECK_JUMP(test_ctx == NULL, EXIT, "test_ctx=NULL\n");
    test_urma_ctx_t *ctx = calloc(1, sizeof(test_urma_ctx_t));
    CHECK_JUMP(ctx == NULL, EXIT, "calloc failed\n");

    ctx->test_ctx = test_ctx;
    ctx->app_num = test_ctx->app_num;
    ctx->app_id = test_ctx->app_id;
    ctx->tp_kind = test_ctx->tp_kind;
    ctx->r_ctx = calloc(1, ctx->app_num * sizeof(r_ctx_t));
    CHECK_JUMP(ctx->r_ctx == NULL, EXIT, "malloc err\n");
    ctx->token_value.token = 1;
    ctx->io_thread_num = 1;
    switch (test_ctx->mode) {
        case 0:
            ctx->tp_mode = URMA_TM_RM;
            TEST_LOG_INFO("ctx->tp_mode = URMA_TM_RM\n");
            break;
        case 1:
            ctx->tp_mode = URMA_TM_RC;
            TEST_LOG_INFO("ctx->tp_mode = URMA_TM_RC\n");
            break;
        case 2:
            ctx->tp_mode = URMA_TM_UM;
            TEST_LOG_INFO("ctx->tp_mode = URMA_TM_UM\n");
            break;
        default:
            ctx->tp_mode = URMA_TM_RM;
            TEST_LOG_INFO("ctx->tp_mode = URMA_TM_RM\n");
    }
    pthread_mutex_init(&ctx->ae_lock, NULL);
    ctx->ae_info.event_num = 0;

    return ctx;

EXIT:
    CHECK_FREE(ctx);
    return NULL;
}

static void test_sync_remote_resource_num(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->r_ctx[ctx->app_id - 1].eid = ctx->l_ctx.eid;
    ctx->r_ctx[ctx->app_id - 1].num_jfr = ctx->l_ctx.num_jfr;
    ctx->r_ctx[ctx->app_id - 1].num_jetty = ctx->l_ctx.num_jetty;
    ctx->r_ctx[ctx->app_id - 1].num_tseg = ctx->l_ctx.num_tseg;
    for (int i = 0; i < (int)ctx->app_num; i++) {
        sync_data(i + 1, (char *)&ctx->r_ctx[i].eid, sizeof(urma_eid_t));
        sync_data(i + 1, (char *)&ctx->r_ctx[i].num_jfr, sizeof(uint32_t));
        sync_data(i + 1, (char *)&ctx->r_ctx[i].num_jetty, sizeof(uint32_t));
        sync_data(i + 1, (char *)&ctx->r_ctx[i].num_tseg, sizeof(uint32_t));
    }
}

void test_set_default_ctx_calloc_buf(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->l_ctx.jfc_cfg = calloc(1, ctx->l_ctx.num_jfc * sizeof(test_jfc_cfg_t));
    CHECK_JUMP(ctx->l_ctx.jfc_cfg == NULL, EXIT, "calloc ctx->l_ctx.jfc_cfg failed!\n");
    ctx->l_ctx.jfs_cfg = calloc(1, ctx->l_ctx.num_jfs * sizeof(test_jfs_cfg_t));
    CHECK_JUMP(ctx->l_ctx.jfs_cfg == NULL, EXIT, "calloc ctx->l_ctx.jfs_cfg failed!\n");
    ctx->l_ctx.jfr_cfg = calloc(1, ctx->l_ctx.num_jfr * sizeof(test_jfr_cfg_t));
    CHECK_JUMP(ctx->l_ctx.jfr_cfg == NULL, EXIT, "calloc ctx->l_ctx.jfr_cfg failed!\n");
    ctx->l_ctx.jetty_cfg = calloc(1, ctx->l_ctx.num_jetty * sizeof(test_jetty_cfg_t));
    CHECK_JUMP(ctx->l_ctx.jetty_cfg == NULL, EXIT, "calloc ctx->l_ctx.jetty_cfg failed!\n");
    ctx->l_ctx.seg_cfg = calloc(1, ctx->l_ctx.num_tseg * sizeof(test_seg_cfg_t));
    CHECK_JUMP(ctx->l_ctx.seg_cfg == NULL, EXIT, "calloc ctx->l_ctx.seg_cfg failed!\n");
    ctx->l_ctx.jfce = calloc(1, ctx->l_ctx.num_jfce * sizeof(urma_jfce_t *));
    CHECK_JUMP(ctx->l_ctx.jfce == NULL, EXIT, "calloc ctx->l_ctx.jfce failed!\n");
    ctx->l_ctx.jfc = calloc(1, ctx->l_ctx.num_jfc * sizeof(urma_jfc_t *));
    CHECK_JUMP(ctx->l_ctx.jfc == NULL, EXIT, "calloc ctx->l_ctx.jfc failed!\n");
    ctx->l_ctx.jfs = calloc(1, ctx->l_ctx.num_jfs * sizeof(urma_jfs_t *));
    CHECK_JUMP(ctx->l_ctx.jfs == NULL, EXIT, "calloc ctx->l_ctx.jfs failed!\n");
    ctx->l_ctx.jfr = calloc(1, ctx->l_ctx.num_jfr * sizeof(urma_jfr_t *));
    CHECK_JUMP(ctx->l_ctx.jfr == NULL, EXIT, "calloc ctx->l_ctx.jfr failed!\n");
    ctx->l_ctx.jetty = calloc(1, ctx->l_ctx.num_jetty * sizeof(urma_jetty_t *));
    CHECK_JUMP(ctx->l_ctx.jetty == NULL, EXIT, "calloc ctx->l_ctx.jetty failed!\n");
    ctx->l_ctx.tseg = calloc(1, ctx->l_ctx.num_tseg * sizeof(urma_target_seg_t *));
    CHECK_JUMP(ctx->l_ctx.tseg == NULL, EXIT, "calloc ctx->l_ctx.tseg failed!\n");

    test_sync_remote_resource_num(ctx);
    for (int i = 0; i < ctx->app_num; i++) {
        ctx->r_ctx[i].jfr_id = calloc(1, ctx->r_ctx[i].num_jfr * sizeof(urma_jfr_id_t));
        CHECK_JUMP(ctx->r_ctx[i].jfr_id == NULL, EXIT, "calloc failed!\n");
        ctx->r_ctx[i].jetty_id = calloc(1, ctx->r_ctx[i].num_jetty * sizeof(urma_jetty_id_t));
        CHECK_JUMP(ctx->r_ctx[i].jetty_id == NULL, EXIT, "calloc failed!\n");
        ctx->r_ctx[i].seg = calloc(1, ctx->r_ctx[i].num_tseg * sizeof(urma_seg_t));
        CHECK_JUMP(ctx->r_ctx[i].seg == NULL, EXIT, "calloc failed!\n");
        ctx->r_ctx[i].tjfr = calloc(1, ctx->r_ctx[i].num_jfr * sizeof(urma_target_jetty_t *));
        CHECK_JUMP(ctx->r_ctx[i].tjfr == NULL, EXIT, "calloc failed!\n");
        ctx->r_ctx[i].tjetty = calloc(1, ctx->r_ctx[i].num_jetty * sizeof(urma_target_jetty_t *));
        CHECK_JUMP(ctx->r_ctx[i].tjetty == NULL, EXIT, "calloc failed!\n");
        ctx->r_ctx[i].tseg = calloc(1, ctx->r_ctx[i].num_tseg * sizeof(urma_target_seg_t *));
        CHECK_JUMP(ctx->r_ctx[i].tseg == NULL, EXIT, "calloc failed!\n");
    }
    ctx->token_id_num = ctx->l_ctx.num_tseg;
    ctx->token_id = calloc(1, ctx->token_id_num * sizeof(urma_token_id_t *));
    CHECK_JUMP(ctx->token_id == NULL, EXIT, "calloc failed!\n");
    return;
EXIT:
    test_delete_ctx(ctx);
}

void test_set_default_ctx_jfc(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (int i = 0; i < ctx->l_ctx.num_jfc; i++) {
        ctx->l_ctx.jfc_cfg[i].depth = TEST_JETTY_DEPTH;
        ctx->l_ctx.jfc_cfg[i].flag.value = 0;
        ctx->l_ctx.jfc_cfg[i].jfce_id = 0;
        ctx->l_ctx.jfc_cfg[i].user_ctx = 0;
    }
}

void test_set_default_ctx_jfs(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (int i = 0; i < ctx->l_ctx.num_jfs; i++) {
        ctx->l_ctx.jfs_cfg[i].depth = TEST_JETTY_DEPTH;
        ctx->l_ctx.jfs_cfg[i].trans_mode = ctx->tp_mode;
        ctx->l_ctx.jfs_cfg[i].priority = 0;
        ctx->l_ctx.jfs_cfg[i].max_sge = ctx->dev_attr.dev_cap.max_jfs_sge;
        ctx->l_ctx.jfs_cfg[i].max_rsge = 0;
        ctx->l_ctx.jfs_cfg[i].max_inline_data = 0;
        ctx->l_ctx.jfs_cfg[i].rnr_retry = URMA_TYPICAL_RNR_RETRY;
        ctx->l_ctx.jfs_cfg[i].err_timeout = URMA_TYPICAL_MIN_RNR_TIMER;
        ctx->l_ctx.jfs_cfg[i].jfc_id = 0;
        ctx->l_ctx.jfs_cfg[i].user_ctx = 0;
        if (ctx->tp_kind == URMA_CTP) {
            ctx->l_ctx.jfs_cfg[i].flag.bs.multi_path = 1;
        }
    }
}

void test_set_default_ctx_jfr(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (int i = 0; i < ctx->l_ctx.num_jfr; i++) {
        ctx->l_ctx.jfr_cfg[i].id = 0;
        ctx->l_ctx.jfr_cfg[i].depth = TEST_JETTY_DEPTH;
        ctx->l_ctx.jfr_cfg[i].flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
        ctx->l_ctx.jfr_cfg[i].flag.bs.token_policy = UNI_TOKEN;
        ctx->l_ctx.jfr_cfg[i].trans_mode = ctx->tp_mode;
        ctx->l_ctx.jfr_cfg[i].max_sge = ctx->dev_attr.dev_cap.max_jfr_sge;
        ctx->l_ctx.jfr_cfg[i].min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
        ctx->l_ctx.jfr_cfg[i].jfc_id = 0;
        ctx->l_ctx.jfr_cfg[i].token_value = ctx->token_value;
    }
}

void test_set_default_ctx_jetty(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    uint32_t seed = get_random_u32(&ctx->test_ctx->seed);

    for (int i = 0; i < ctx->l_ctx.num_jetty; i++) {
        ctx->l_ctx.jetty_cfg[i].flag.value = 0;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.depth = TEST_JETTY_DEPTH;
        if (ctx->tp_kind == URMA_CTP) {
            ctx->l_ctx.jetty_cfg[i].jfs_cfg.flag.bs.multi_path = 1;
        }
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.trans_mode = ctx->tp_mode;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.priority = 0; /* Highest priority */
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.max_sge = ctx->dev_attr.dev_cap.max_jfs_sge;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.max_inline_data = 0;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.rnr_retry = URMA_TYPICAL_RNR_RETRY;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.err_timeout = 3;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.jfc_id = 0;
        ctx->l_ctx.jetty_cfg[i].jfs_cfg.user_ctx = 0;

        // 只支持share_jfr
        ctx->l_ctx.jetty_cfg[i].flag.bs.share_jfr = URMA_SHARE_JFR;
        ctx->l_ctx.jetty_cfg[i].shared.jfr_id = i % ctx->l_ctx.num_jfr;
        ctx->l_ctx.jetty_cfg[i].shared.jfc_id = -1;

        // 默认app1、app2的jetty互相bind
        if (ctx->app_id <= PROC_2) {
            ctx->l_ctx.jetty_cfg[i].bind_app_id = PROC_3 - ctx->app_id;
            ctx->l_ctx.jetty_cfg[i].bind_jetty_id = i;
        }
    }
}

void test_set_default_ctx_seg(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (int i = 0; i < ctx->l_ctx.num_tseg; i++) {
        ctx->l_ctx.seg_cfg[i].len = SIZE_128M;
        ctx->l_ctx.seg_cfg[i].token_value = ctx->token_value;
        ctx->l_ctx.seg_cfg[i].flag.bs.token_policy = UNI_TOKEN;
        ctx->l_ctx.seg_cfg[i].flag.bs.cacheable = URMA_NON_CACHEABLE;
        ctx->l_ctx.seg_cfg[i].flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC;
        ctx->l_ctx.seg_cfg[i].user_ctx = (uintptr_t)NULL;
        ctx->l_ctx.seg_cfg[i].iova = 0;

        ctx->token_id[i] = urma_alloc_token_id(ctx->urma_ctx);
        TEST_LOG_INFO("urma_alloc_token_id token_id[%d]=%p\n", i, ctx->token_id[i]);
        ctx->l_ctx.seg_cfg[i].flag.bs.token_id_valid = true;
        ctx->l_ctx.seg_cfg[i].token_id = ctx->token_id[i];
    }
}

void test_set_default_ctx(test_urma_ctx_t *ctx)
{
    test_set_default_ctx_num(ctx);
    test_set_default_ctx_cfg(ctx);
}

void test_set_default_ctx_num(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->l_ctx.eid = ctx->urma_ctx->eid;
    ctx->l_ctx.num_jfce = TEST_DEFAULT_JFCE_NUM;
    ctx->l_ctx.num_jfc = TEST_DEFAULT_JFC_NUM;

    // RC模式不支持jfs、jfr
    if (ctx->tp_mode == URMA_TM_RC) {
        ctx->l_ctx.num_jfs = 0;
    } else {
        ctx->l_ctx.num_jfs = TEST_DEFAULT_JFS_NUM;
    }
    ctx->l_ctx.num_jfr = TEST_DEFAULT_JFR_NUM;
    ctx->l_ctx.num_jetty = TEST_DEFAULT_JETTY_NUM;
    ctx->l_ctx.num_tseg = TEST_DEFAULT_SEG_NUM;
}

void test_set_default_ctx_cfg(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    test_set_default_ctx_calloc_buf(ctx);
    test_set_default_ctx_jfc(ctx);
    test_set_default_ctx_jfs(ctx);
    test_set_default_ctx_jfr(ctx);
    test_set_default_ctx_jetty(ctx);
    test_set_default_ctx_seg(ctx);
}

void test_delete_ctx(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    pthread_mutex_destroy(&ctx->ae_lock);
    CHECK_FREE(ctx->l_ctx.jfce);
    CHECK_FREE(ctx->l_ctx.jfc_cfg);
    CHECK_FREE(ctx->l_ctx.jfc);
    CHECK_FREE(ctx->l_ctx.jfs_cfg);
    CHECK_FREE(ctx->l_ctx.jfs);
    CHECK_FREE(ctx->l_ctx.jfr_cfg);
    CHECK_FREE(ctx->l_ctx.jfr);
    CHECK_FREE(ctx->l_ctx.jetty_cfg);
    CHECK_FREE(ctx->l_ctx.jetty);
    CHECK_FREE(ctx->token_id);
    for (int i = 0; i < ctx->l_ctx.num_tseg; i++) {
        CHECK_FREE(ctx->l_ctx.seg_cfg[i].protect_va);
    }
    CHECK_FREE(ctx->l_ctx.seg_cfg);
    CHECK_FREE(ctx->l_ctx.tseg);
    for (int i = 0; i < ctx->app_num; i++) {
        CHECK_FREE(ctx->r_ctx[i].jfr_id);
        CHECK_FREE(ctx->r_ctx[i].tjfr);
        CHECK_FREE(ctx->r_ctx[i].jetty_id);
        CHECK_FREE(ctx->r_ctx[i].tjetty);
        CHECK_FREE(ctx->r_ctx[i].seg);
        CHECK_FREE(ctx->r_ctx[i].tseg);
    }
    CHECK_FREE(ctx->r_ctx);
    CHECK_FREE(ctx);
}

int test_create_resource(test_urma_ctx_t *ctx)
{
    int ret = TEST_FAILED;
    CHECK_JUMP(ctx == NULL, EXIT, "ctx=NULL!\n");
    for (int i = 0; i < ctx->l_ctx.num_jfce; i++) {
        ctx->l_ctx.jfce[i] = test_create_jfce(ctx);
        CHECK_JUMP(ctx->l_ctx.jfce[i] == NULL, EXIT, "i=%d test_create_jfce failed!\n", i);
    }
    for (int i = 0; i < ctx->l_ctx.num_jfc; i++) {
        ctx->l_ctx.jfc[i] = test_create_jfc(ctx, ctx->l_ctx.jfc_cfg[i]);
        CHECK_JUMP(ctx->l_ctx.jfc[i] == NULL, EXIT, "i=%d test_create_jfc failed!\n", i);
    }
    for (int i = 0; i < ctx->l_ctx.num_jfs; i++) {
        ctx->l_ctx.jfs[i] = test_create_jfs(ctx, ctx->l_ctx.jfs_cfg[i]);
        CHECK_JUMP(ctx->l_ctx.jfs[i] == NULL, EXIT, "i=%d test_create_jfs failed!\n", i);
    }
    for (int i = 0; i < ctx->l_ctx.num_jfr; i++) {
        ctx->l_ctx.jfr[i] = test_create_jfr(ctx, ctx->l_ctx.jfr_cfg[i]);
        CHECK_JUMP(ctx->l_ctx.jfr[i] == NULL, EXIT, "i=%d test_create_jfr failed!\n", i);
        ctx->r_ctx[ctx->app_id - 1].jfr_id[i] = ctx->l_ctx.jfr[i]->jfr_id;
    }
    for (int i = 0; i < ctx->l_ctx.num_jetty; i++) {
        ctx->l_ctx.jetty[i] = test_create_jetty(ctx, ctx->l_ctx.jetty_cfg[i]);
        CHECK_JUMP(ctx->l_ctx.jetty[i] == NULL, EXIT, "i=%d test_create_jetty failed!\n", i);
        ctx->r_ctx[ctx->app_id - 1].jetty_id[i] = ctx->l_ctx.jetty[i]->jetty_id;
    }
    for (int i = 0; i < ctx->l_ctx.num_tseg; i++) {
        // 首尾各加4K保护长度
        ctx->l_ctx.seg_cfg[i].protect_va = memalign(SIZE_4K, SIZE_4K + ctx->l_ctx.seg_cfg[i].len + SIZE_4K);
        CHECK_JUMP(ctx->l_ctx.seg_cfg[i].protect_va == NULL, EXIT, "i=%d calloc seg va failed!\n", i);
        ctx->l_ctx.seg_cfg[i].va = ctx->l_ctx.seg_cfg[i].protect_va + SIZE_4K;
        ctx->l_ctx.tseg[i] = test_create_seg(ctx, ctx->l_ctx.seg_cfg[i]);
        CHECK_JUMP(ctx->l_ctx.tseg[i] == NULL, EXIT, "i=%d test_create_seg failed!\n", i);
        ctx->r_ctx[ctx->app_id - 1].seg[i] = ctx->l_ctx.tseg[i]->seg;
    }
    ret = TEST_SUCCESS;
EXIT:
    return ret;
}

void test_delete_resource(test_urma_ctx_t *ctx)
{
    int ret;
    async_event_info_t ae_info;
    if (ctx == NULL) {
        return;
    }

    // unregister
    for (int i = 0; i < ctx->l_ctx.num_tseg; i++) {
        if (ctx->l_ctx.tseg[i] != NULL) {
            ret = urma_unregister_seg(ctx->l_ctx.tseg[i]);
            TEST_LOG_DEBUG("urma_unregister_seg ret=%d tseg[%d]=%p\n", ret, i, ctx->l_ctx.tseg[i]);
            ctx->l_ctx.tseg[i] = NULL;
        }
    }

    // delete
    for (int i = 0; i < ctx->l_ctx.num_jetty; i++) {
        if (ctx->l_ctx.jetty[i] != NULL) {
            ret = urma_delete_jetty(ctx->l_ctx.jetty[i]);
            TEST_LOG_DEBUG("urma_delete_jetty ret=%d jetty[%d]=%p\n", ret, i, ctx->l_ctx.jetty[i]);
            ctx->l_ctx.jetty[i] = NULL;
        }
    }
    for (int i = 0; i < ctx->l_ctx.num_jfs; i++) {
        if (ctx->l_ctx.jfs[i] != NULL) {
            ret = urma_delete_jfs(ctx->l_ctx.jfs[i]);
            TEST_LOG_DEBUG("urma_delete_jfs ret=%d jfs[%d]=%p\n", ret, i, ctx->l_ctx.jfs[i]);
            ctx->l_ctx.jfs[i] = NULL;
        }
    }
    for (int i = 0; i < ctx->l_ctx.num_jfr; i++) {
        if (ctx->l_ctx.jfr[i] != NULL) {
            ret = urma_delete_jfr(ctx->l_ctx.jfr[i]);
            TEST_LOG_DEBUG("urma_delete_jfr ret=%d jfr[%d]=%p\n", ret, i, ctx->l_ctx.jfr[i]);
            ctx->l_ctx.jfr[i] = NULL;
        }
    }
    for (int i = 0; i < ctx->l_ctx.num_jfc; i++) {
        if (ctx->l_ctx.jfc[i] != NULL) {
            ret = urma_delete_jfc(ctx->l_ctx.jfc[i]);
            TEST_LOG_DEBUG("urma_delete_jfc ret=%d jfc[%d]=%p\n", ret, i, ctx->l_ctx.jfc[i]);
            ctx->l_ctx.jfc[i] = NULL;
        }
    }
    for (int i = 0; i < ctx->l_ctx.num_jfce; i++) {
        if (ctx->l_ctx.jfce[i] != NULL) {
            ret = urma_delete_jfce(ctx->l_ctx.jfce[i]);
            TEST_LOG_DEBUG("urma_delete_jfce ret=%d jfce[%d]=%p\n", ret, i, ctx->l_ctx.jfce[i]);
            ctx->l_ctx.jfce[i] = NULL;
        }
    }
    for (int i = 0; i < ctx->token_id_num; i++) {
        if (ctx->token_id[i] != NULL) {
            ret = urma_free_token_id(ctx->token_id[i]);
            TEST_LOG_DEBUG("urma_free_token_id ret=%d token_id[%d]=%p\n", ret, i, ctx->token_id[i]);
            ctx->token_id[i] = NULL;
        }
    }
    if (ctx->ae_thread != 0) {
        ctx->ae_thread_stop = true;
        pthread_join(ctx->ae_thread, NULL);
        test_get_async_event_list(ctx, &ae_info, 0);
        if (ae_info.event_num != 0) {
            TEST_LOG_ERROR("-------------- ae_info.event_num=%d\n", ae_info.event_num);
        }
        ctx->ae_thread = 0;
    }
    if (ctx->urma_ctx != NULL) {
        ret = urma_delete_context(ctx->urma_ctx);
        if (ret != 0) {
            TEST_LOG_ERROR("urma_delete_context ret=%d ctx=%p\n", ret, ctx->urma_ctx);
        }
        ctx->urma_ctx = NULL;
    }
}

int test_init_urma()
{
    urma_status_t ret;
    urma_init_attr_t init_attr;
    init_attr.token = 0;
    init_attr.uasid = 0;
    ret = urma_init(&init_attr);
    TEST_LOG_INFO("urma_init ret=%d\n", ret);
    return ret;
}

urma_jfce_t *test_create_jfce(test_urma_ctx_t *ctx)
{
    urma_jfce_t *jfce;
    if (ctx == NULL) {
        return NULL;
    }
    jfce = urma_create_jfce(ctx->urma_ctx);
    if (jfce == NULL) {
        TEST_LOG_ERROR("Failed to urma_create_jfce\n");
    } else {
        TEST_LOG_DEBUG("urma_create_jfce jfce.fd=%d\n", jfce->fd);
    }
    return jfce;
}

urma_jfc_t *test_create_jfc(test_urma_ctx_t *ctx, test_jfc_cfg_t test_jfc_cfg)
{
    urma_jfc_t *jfc;
    urma_jfc_cfg_t jfc_cfg = {0};
    if (ctx == NULL) {
        return NULL;
    }
    jfc_cfg.depth = test_jfc_cfg.depth;
    jfc_cfg.flag.value = test_jfc_cfg.flag.value;
    jfc_cfg.jfce = test_jfc_cfg.jfce_id == -1 ? NULL : ctx->l_ctx.jfce[test_jfc_cfg.jfce_id];
    jfc_cfg.user_ctx = test_jfc_cfg.user_ctx;

    jfc = urma_create_jfc(ctx->urma_ctx, &jfc_cfg);
    if (jfc == NULL) {
        TEST_LOG_ERROR("Failed to urma_create_jfc\n");
    } else {
        TEST_LOG_DEBUG("urma_create_jfc eid=0x%x uasid=%u id=%u\n", jfc->jfc_id.eid.in4.addr, jfc->jfc_id.uasid,
                       jfc->jfc_id.id);
    }
    return jfc;
}

urma_jfs_t *test_create_jfs(test_urma_ctx_t *ctx, test_jfs_cfg_t test_jfs_cfg)
{
    urma_jfs_t *jfs;
    urma_jfs_cfg_t jfs_cfg = {0};
    if (ctx == NULL) {
        return NULL;
    }
    jfs_cfg.depth = test_jfs_cfg.depth;
    jfs_cfg.flag.value = test_jfs_cfg.flag.value;
    jfs_cfg.trans_mode = test_jfs_cfg.trans_mode;
    jfs_cfg.priority = test_jfs_cfg.priority;
    jfs_cfg.max_sge = test_jfs_cfg.max_sge;
    jfs_cfg.max_inline_data = test_jfs_cfg.max_inline_data;
    jfs_cfg.rnr_retry = test_jfs_cfg.rnr_retry;
    jfs_cfg.err_timeout = test_jfs_cfg.err_timeout;
    jfs_cfg.jfc = ctx->l_ctx.jfc[test_jfs_cfg.jfc_id];
    jfs_cfg.user_ctx = test_jfs_cfg.user_ctx;

    jfs = urma_create_jfs(ctx->urma_ctx, &jfs_cfg);
    if (jfs == NULL) {
        TEST_LOG_ERROR("Failed to urma_create_jfs\n");
    } else {
        TEST_LOG_DEBUG("urma_create_jfs eid=0x%x uasid=%u id=%u\n", jfs->jfs_id.eid.in4.addr, jfs->jfs_id.uasid,
                       jfs->jfs_id.id);
    }
    return jfs;
}

urma_jfr_t *test_create_jfr(test_urma_ctx_t *ctx, test_jfr_cfg_t test_jfr_cfg)
{
    urma_jfr_t *jfr;
    urma_jfr_cfg_t jfr_cfg = {0};
    if (ctx == NULL) {
        return NULL;
    }
    jfr_cfg.depth = test_jfr_cfg.depth;
    jfr_cfg.max_sge = test_jfr_cfg.max_sge;
    jfr_cfg.flag.value = test_jfr_cfg.flag.value;
    jfr_cfg.trans_mode = test_jfr_cfg.trans_mode;
    jfr_cfg.min_rnr_timer = test_jfr_cfg.min_rnr_timer;
    jfr_cfg.jfc = ctx->l_ctx.jfc[test_jfr_cfg.jfc_id];
    jfr_cfg.token_value = test_jfr_cfg.token_value;
    jfr_cfg.id = test_jfr_cfg.id;

    jfr = urma_create_jfr(ctx->urma_ctx, &jfr_cfg);
    if (jfr == NULL) {
        TEST_LOG_ERROR("Failed to urma_create_jfr\n");
    } else {
        TEST_LOG_DEBUG("urma_create_jfr eid=0x%x uasid=%u id=%u\n", jfr->jfr_id.eid.in4.addr, jfr->jfr_id.uasid,
                       jfr->jfr_id.id);
    }
    return jfr;
}

urma_jetty_t *test_create_jetty(test_urma_ctx_t *ctx, test_jetty_cfg_t test_jetty_cfg)
{
    urma_jetty_t *jetty;
    urma_jetty_cfg_t jetty_cfg = {0};
    urma_jfs_cfg_t jfs_cfg = {0};
    if (ctx == NULL) {
        return NULL;
    }

    jetty_cfg.id = test_jetty_cfg.id;
    jetty_cfg.jfs_cfg.depth = test_jetty_cfg.jfs_cfg.depth;
    jetty_cfg.jfs_cfg.flag.value = test_jetty_cfg.jfs_cfg.flag.value;
    jetty_cfg.jfs_cfg.trans_mode = test_jetty_cfg.jfs_cfg.trans_mode;
    jetty_cfg.jfs_cfg.priority = test_jetty_cfg.jfs_cfg.priority;
    jetty_cfg.jfs_cfg.max_sge = test_jetty_cfg.jfs_cfg.max_sge;
    jetty_cfg.jfs_cfg.max_inline_data = test_jetty_cfg.jfs_cfg.max_inline_data;
    jetty_cfg.jfs_cfg.rnr_retry = test_jetty_cfg.jfs_cfg.rnr_retry;
    jetty_cfg.jfs_cfg.err_timeout = test_jetty_cfg.jfs_cfg.err_timeout;
    jetty_cfg.jfs_cfg.jfc = ctx->l_ctx.jfc[test_jetty_cfg.jfs_cfg.jfc_id];
    jetty_cfg.jfs_cfg.user_ctx = test_jetty_cfg.jfs_cfg.user_ctx;

    jetty_cfg.flag.value = test_jetty_cfg.flag.value;
    jetty_cfg.shared.jfr = ctx->l_ctx.jfr[test_jetty_cfg.shared.jfr_id];
    if (test_jetty_cfg.shared.jfc_id == -1) {
        jetty_cfg.shared.jfc = NULL;
    } else {
        jetty_cfg.shared.jfc = ctx->l_ctx.jfc[test_jetty_cfg.shared.jfc_id];
    }

    jetty = urma_create_jetty(ctx->urma_ctx, &jetty_cfg);
    if (jetty == NULL) {
        TEST_LOG_ERROR("Failed to urma_create_jetty\n");
    } else {
        TEST_LOG_DEBUG("urma_create_jetty eid=0x%x uasid=%u id=%u\n", jetty->jetty_id.eid.in4.addr,
                       jetty->jetty_id.uasid, jetty->jetty_id.id);
    }
    return jetty;
}

urma_target_seg_t *test_create_seg(test_urma_ctx_t *ctx, test_seg_cfg_t test_seg_cfg)
{
    urma_target_seg_t *tseg;
    urma_seg_cfg_t seg_cfg = {0};
    if (ctx == NULL) {
        return NULL;
    }
    seg_cfg.va = (uint64_t)test_seg_cfg.va;
    seg_cfg.len = test_seg_cfg.len;
    seg_cfg.token_id = test_seg_cfg.token_id;
    seg_cfg.token_value = test_seg_cfg.token_value;
    seg_cfg.flag.value = test_seg_cfg.flag.value;
    seg_cfg.user_ctx = test_seg_cfg.user_ctx;
    seg_cfg.iova = test_seg_cfg.iova;

    tseg = urma_register_seg(ctx->urma_ctx, &seg_cfg);
    if (tseg == NULL) {
        TEST_LOG_ERROR("Failed to urma_register_seg\n");
    } else {
        TEST_LOG_DEBUG("urma_register_seg addr=0x%x uasid=%u va=0x%x kid=%d\n", tseg->seg.ubva.eid.in4.addr,
                       tseg->seg.ubva.uasid, tseg->seg.ubva.va, tseg->seg.token_id);
    }
    return tseg;
}

void u32_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(URMA_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

static void *test_get_async_event_thread(void *ptr)
{
    int ret;
    int flags;
    int epollfd = epoll_create(EPOLL_CNT);
    struct epoll_event ep_event;
    struct epoll_event epoll_events[EPOLL_CNT];
    test_urma_ctx_t *ctx = (test_urma_ctx_t *)ptr;

    TEST_LOG_INFO("test_get_async_event_thread start!\n");

    // 学习rdma写法修改为非阻塞
    TEST_LOG_INFO("ctx->urma_ctx->async_fd=%d\n", ctx->urma_ctx->async_fd);
    flags = fcntl(ctx->urma_ctx->async_fd, F_GETFL);
    ret = fcntl(ctx->urma_ctx->async_fd, F_SETFL, flags | O_NONBLOCK);
    ep_event.data.fd = ctx->urma_ctx->async_fd;
    ep_event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctx->urma_ctx->async_fd, &ep_event) == -1) {
        close(epollfd);
        return NULL;
    }

    while (ctx->ae_thread_stop == false) {
        urma_async_event_t event;

        do {
            ret = epoll_wait(epollfd, epoll_events, 1, EPOLL_TMOUT);
        } while (ret == 0 && ctx->ae_thread_stop == false);
        if (ret == 0) {
            break;
        }

        ret = urma_get_async_event(ctx->urma_ctx, &event);
        if (ret != URMA_FAIL) {
            TEST_LOG_ERROR("urma_get_async_event ret=%u event_type=%u\n", (uint32_t)ret, (uint32_t)event.event_type);
            if (ctx->ae_info.event_num < EVENT_LIST_SIZE) {
                pthread_mutex_lock(&ctx->ae_lock);
                ctx->ae_info.event_list[ctx->ae_info.event_num] = event;
                ctx->ae_info.event_num++;
                pthread_mutex_unlock(&ctx->ae_lock);
            } else {
                TEST_LOG_ERROR("event_list out of range, drop new event!\n");
            }
            urma_ack_async_event(&event);
        }
    }
    epoll_ctl(epollfd, EPOLL_CTL_DEL, ctx->urma_ctx->async_fd, NULL);
    TEST_LOG_INFO("test_get_async_event_thread stop!\n");
    return NULL;
}

void test_get_async_event_list(test_urma_ctx_t *ctx, async_event_info_t *ae_info, int timeout)
{
    if (ctx == NULL || ae_info == NULL) {
        return;
    }
    for (int i = 0; i <= timeout * MSEC_IN_SEC; i++) {
        pthread_mutex_lock(&ctx->ae_lock);
        memcpy(ae_info, &ctx->ae_info, sizeof(async_event_info_t));
        memset(&ctx->ae_info, 0, sizeof(async_event_info_t));
        pthread_mutex_unlock(&ctx->ae_lock);
        if (ae_info->event_num != 0) {
            break;
        }
        usleep(URMA_TEST_SLEEP_TIME);
    }
    TEST_LOG_INFO("test_get_async_event_list event_num=%d\n", ae_info->event_num);
}

int test_create_urma_ctx(test_urma_ctx_t *ctx)
{
    urma_status_t ret;
    urma_device_t *urma_dev;
    if (ctx == NULL) {
        return -1;
    }

    if (ctx->test_ctx->device_name != NULL) {
        TEST_LOG_INFO("urma_get_device_by_name dev=%s\n", ctx->test_ctx->device_name);
        urma_dev = urma_get_device_by_name(ctx->test_ctx->device_name);
    } else {
        uint32_t ipv4;
        urma_eid_t eid;
        inet_pton(AF_INET, ctx->test_ctx->test_ip[0], &ipv4);
        u32_to_eid(be32toh(ipv4), &eid);
        TEST_LOG_INFO("-----------eid=" EID_FMT "\n", EID_ARGS(eid));
        urma_dev = urma_get_device_by_eid(eid, ctx->tp_type);
    }
    CHECK_JUMP(urma_dev == NULL, EXIT, "Failed to urma_get_device_by_eid\n");
    ctx->tp_type = urma_dev->type;

    ret = urma_query_device(urma_dev, &ctx->dev_attr);
    if (ret != URMA_SUCCESS) {
        TEST_LOG_INFO("Failed to urma_query_device %s.\n", ctx->test_ctx->device_name);
        return -1;
    }
    uint32_t eid_index = 0;
    if (ctx->test_ctx->xargs != NULL) {
        eid_index = atoi(ctx->test_ctx->xargs);
        TEST_LOG_INFO("eid_index=%d\n", eid_index);
    }
    ctx->urma_ctx = urma_create_context(urma_dev, eid_index);
    CHECK_JUMP(ctx->urma_ctx == NULL, EXIT, "Failed to urma_create_context\n");

    ctx->ae_thread_stop = false;
    pthread_create(&ctx->ae_thread, NULL, test_get_async_event_thread, (void *)ctx);

    return 0;
EXIT:
    return -1;
}

int test_ctx_unimport_seg(test_urma_ctx_t *ctx, int app, int id)
{
    if (ctx == NULL) {
        return -1;
    }
    int ret = urma_unimport_seg(ctx->r_ctx[app].tseg[id]);
    TEST_LOG_DEBUG("urma_unimport_seg ret=%d app[%d].tseg[%d]=%p\n", ret, app, id, ctx->r_ctx[app].tseg[id]);
    if (ret == URMA_SUCCESS) {
        ctx->r_ctx[app].tseg[id] = NULL;
    }
    return ret;
}

int test_ctx_unimport_jetty(test_urma_ctx_t *ctx, int app, int id)
{
    if (ctx == NULL) {
        return -1;
    }
    int ret = urma_unimport_jetty(ctx->r_ctx[app].tjetty[id]);
    TEST_LOG_DEBUG("urma_unimport_jetty ret=%d app[%d].tjetty[%d]=%p\n", ret, app, id, ctx->r_ctx[app].tjetty[id]);
    if (ret == URMA_SUCCESS) {
        ctx->r_ctx[app].tjetty[id] = NULL;
    }
    return ret;
}

int test_ctx_unimport_jfr(test_urma_ctx_t *ctx, int app, int id)
{
    if (ctx == NULL) {
        return -1;
    }
    int ret = urma_unimport_jfr(ctx->r_ctx[app].tjfr[id]);
    TEST_LOG_DEBUG("urma_unimport_jfr ret=%d app[%d].tjfr[%d]=%p\n", ret, app, id, ctx->r_ctx[app].tjfr[id]);
    if (ret == URMA_SUCCESS) {
        ctx->r_ctx[app].tjfr[id] = NULL;
    }
    return ret;
}

int test_exchange_resource(test_urma_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }
    for (int i = 0; i < (int)ctx->app_num; i++) {
        sync_data(i + 1, (char *)ctx->r_ctx[i].jfr_id, ctx->r_ctx[i].num_jfr * sizeof(urma_jfr_id_t));
        for (int j = 0; j < ctx->r_ctx[i].num_jfr; j++) {
            TEST_LOG_DEBUG("exchange_info jfr app[%u].tjfr[%d] eid=0x%x uasid=%u id=%u \n", i, j,
                           ctx->r_ctx[i].jfr_id[j].eid.in4.addr, ctx->r_ctx[i].jfr_id[j].uasid,
                           ctx->r_ctx[i].jfr_id[j].id);
        }
        sync_data(i + 1, (char *)ctx->r_ctx[i].jetty_id, ctx->r_ctx[i].num_jetty * sizeof(urma_jetty_id_t));
        for (int j = 0; j < ctx->r_ctx[i].num_jetty; j++) {
            TEST_LOG_DEBUG("exchange_info jetty app[%u].tjetty[%d] eid=0x%x uasid=%u id=%u \n", i, j,
                           ctx->r_ctx[i].jetty_id[j].eid.in4.addr, ctx->r_ctx[i].jetty_id[j].uasid,
                           ctx->r_ctx[i].jetty_id[j].id);
        }
        sync_data(i + 1, (char *)ctx->r_ctx[i].seg, ctx->r_ctx[i].num_tseg * sizeof(urma_seg_t));
        for (int j = 0; j < ctx->r_ctx[i].num_tseg; j++) {
            TEST_LOG_DEBUG("exchange_info seg app[%u].tseg[%d] eid=0x%x uasid=%u va=0x%x \n", i, j,
                           ctx->r_ctx[i].seg[j].ubva.eid.in4.addr, ctx->r_ctx[i].seg[j].ubva.uasid,
                           ctx->r_ctx[i].seg[j].ubva.va);
        }
    }
    return 0;
}

void test_ctx_import_jfr(test_urma_ctx_t *ctx, int r_ctx_id, int r_jetty_id)
{
    urma_rjfr_t rjfr = {0};
    if (ctx == NULL) {
        return;
    }
    rjfr.jfr_id = ctx->r_ctx[r_ctx_id].jfr_id[r_jetty_id];
    rjfr.trans_mode = ctx->tp_mode;
    rjfr.flag.bs.token_policy = UNI_TOKEN;
    rjfr.flag.bs.share_tp = NO_SHARE_TP;
    if (ctx->tp_mode == URMA_TM_UM) {
        rjfr.tp_type = URMA_UTP;
    } else if (ctx->tp_kind == URMA_CTP) {
        rjfr.tp_type = URMA_CTP;
    } else {
        rjfr.tp_type = URMA_RTP;
    }

    for (int i = 0; i < RETRY_CNT; i++) {
        ctx->r_ctx[r_ctx_id].tjfr[r_jetty_id] = urma_import_jfr(ctx->urma_ctx, &rjfr, &ctx->token_value);
        TEST_LOG_DEBUG("urma_import_jfr app[%d].jfr[%d] tjfr=%p\n", r_ctx_id, r_jetty_id,
                       ctx->r_ctx[r_ctx_id].tjfr[r_jetty_id]);
        if (ctx->r_ctx[r_ctx_id].tjfr[r_jetty_id] != NULL) {
            break;
        }
        TEST_LOG_ERROR("Failed to import app[%d].jfr[%d]\n", r_ctx_id, r_jetty_id);
    }
}

void test_ctx_import_jetty(test_urma_ctx_t *ctx, int r_ctx_id, int r_jetty_id)
{
    urma_rjetty_t rjetty = {0};
    if (ctx == NULL) {
        return;
    }
    rjetty.jetty_id = ctx->r_ctx[r_ctx_id].jetty_id[r_jetty_id];
    rjetty.trans_mode = ctx->tp_mode;
    rjetty.type = URMA_JETTY;
    rjetty.flag.bs.token_policy = UNI_TOKEN;
    rjetty.flag.bs.share_tp = NO_SHARE_TP;
    if (ctx->tp_mode == URMA_TM_UM) {
        rjetty.tp_type = URMA_UTP;
    } else if (ctx->tp_kind == URMA_CTP) {
        rjetty.tp_type = URMA_CTP;
    } else {
        rjetty.tp_type = URMA_RTP;
    }

    for (int i = 0; i < RETRY_CNT; i++) {
        ctx->r_ctx[r_ctx_id].tjetty[r_jetty_id] = urma_import_jetty(ctx->urma_ctx, &rjetty, &ctx->token_value);
        TEST_LOG_DEBUG("urma_import_jetty app[%d].jetty[%d] tjetty=%p\n", r_ctx_id, r_jetty_id,
                       ctx->r_ctx[r_ctx_id].tjetty[r_jetty_id]);
        if (ctx->r_ctx[r_ctx_id].tjetty[r_jetty_id] != NULL) {
            break;
        }
        TEST_LOG_ERROR("Failed to import app[%d].jetty[%d]\n", r_ctx_id, r_jetty_id);
    }
}

void test_ctx_import_seg(test_urma_ctx_t *ctx, int r_ctx_id, int r_seg_id)
{
    urma_import_seg_flag_t flag = {.bs.cacheable = URMA_NON_CACHEABLE,
                                   .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
                                   .bs.mapping = URMA_SEG_NOMAP,
                                   .bs.reserved = 0};
    if (ctx == NULL) {
        return;
    }

    ctx->r_ctx[r_ctx_id].tseg[r_seg_id] =
        urma_import_seg(ctx->urma_ctx, &ctx->r_ctx[r_ctx_id].seg[r_seg_id], &ctx->token_value, 0, flag);
    TEST_LOG_DEBUG("urma_import_seg app[%d].seg[%d] tseg=%p\n", r_ctx_id, r_seg_id,
                   ctx->r_ctx[r_ctx_id].tseg[r_seg_id]);
    if (ctx->r_ctx[r_ctx_id].tseg[r_seg_id] == NULL) {
        TEST_LOG_INFO("Failed to import segment\n");
    }
}

int test_import_resource(test_urma_ctx_t *ctx)
{
    urma_status_t ret;
    if (ctx == NULL) {
        return -1;
    }
    for (int app = 0; app < (int)ctx->app_num; app++) {
        // 跳过自己
        if (app == ctx->app_id - 1) {
            continue;
        }

        // import资源
        for (int i = 0; i < (int)ctx->r_ctx[app].num_jfr; i++) {
            test_ctx_import_jfr(ctx, app, i);
        }
        for (int i = 0; i < (int)ctx->r_ctx[app].num_jetty; i++) {
            test_ctx_import_jetty(ctx, app, i);
        }
        for (int i = 0; i < (int)ctx->r_ctx[app].num_tseg; i++) {
            test_ctx_import_seg(ctx, app, i);
        }
    }
    if (ctx->tp_mode == URMA_TM_RC) {
        for (int i = 0; i < ctx->l_ctx.num_jetty; i++) {
            if (ctx->l_ctx.jetty_cfg[i].bind_app_id != 0) {
                int tapp = ctx->l_ctx.jetty_cfg[i].bind_app_id - 1;
                int tjetty_id = ctx->l_ctx.jetty_cfg[i].bind_jetty_id;
                if (tjetty_id < 0 || tjetty_id >= ctx->r_ctx[tapp].num_jetty) {
                    continue;
                }
                ret = urma_bind_jetty(ctx->l_ctx.jetty[i], ctx->r_ctx[tapp].tjetty[tjetty_id]);
                TEST_LOG_DEBUG("urma_bind_jetty ret=%d jetty[%d] app[%d].tjetty[%d]\n", ret, i, tapp, tjetty_id);
            }
        }
    }
    return 0;
}

void test_unimport_resource(test_urma_ctx_t *ctx)
{
    int ret = 0;
    if (ctx == NULL) {
        return;
    }
    for (int app = 0; app < (int)ctx->app_num; app++) {
        // 跳过自己
        if (app == ctx->app_id - 1) {
            continue;
        }

        if (ctx->tp_mode == URMA_TM_RC) {
            // rc mode need unbind
            for (int i = 0; i < ctx->l_ctx.num_jetty; i++) {
                ret = urma_unbind_jetty(ctx->l_ctx.jetty[i]);
                TEST_LOG_DEBUG("urma_unbind_jetty ret=%d jetty[%d]\n", ret, i);
            }
        }

        for (int i = 0; i < ctx->r_ctx[app].num_jetty; i++) {
            test_ctx_unimport_jetty(ctx, app, i);
        }
        for (int i = 0; i < ctx->r_ctx[app].num_jfr; i++) {
            test_ctx_unimport_jfr(ctx, app, i);
        }
        for (int i = 0; i < ctx->r_ctx[app].num_tseg; i++) {
            test_ctx_unimport_seg(ctx, app, i);
        }
    }
}

int test_poll_jfc_wait(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr, int timeout)
{
    int cnt = 0;
    (void)memset(cr, 0, cr_cnt * sizeof(urma_cr_t));
    for (int i = 0; i <= timeout * MSEC_IN_SEC; i++) {
        int ret = urma_poll_jfc(jfc, cr_cnt - cnt, &cr[cnt]);
        CHECK_JUMP(ret < 0, EXIT, "poll_jfc_wait ret=%d\n", ret);
        for (int j = 0; j < ret; j++) {
            if (cr[cnt + j].status != URMA_CR_SUCCESS) {
                TEST_LOG_ERROR("poll_jfc_wait user_ctx[%d] user_ctx=%llu status=%d\n", cnt + j, cr[cnt + j].user_ctx,
                               cr[cnt + j].status);
            } else {
                TEST_LOG_DEBUG("poll_jfc_wait user_ctx[%d] user_ctx=%llu status=%d\n", cnt + j, cr[cnt + j].user_ctx,
                               cr[cnt + j].status);
            }
        }
        cnt += ret;
        if (cnt == cr_cnt) {
            break;
        }
        usleep(URMA_TEST_SLEEP_TIME);
    }
EXIT:
    TEST_LOG_DEBUG("poll_jfc_wait end cnt=%d\n", cnt);
    return cnt;
}

urma_jfs_wr_flag_t get_default_wr_flag()
{
    urma_jfs_wr_flag_t flag;
    flag.value = 0;
    flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
    return flag;
}

int test_urma_post_jetty_send_wr(const urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    int ret;
    *bad_wr = NULL;
    ret = urma_post_jetty_send_wr(jetty, wr, bad_wr);
    TEST_LOG_DEBUG("urma_post_jetty_send_wr ret=%d\n", ret);
    urma_jfs_wr_t *tmp_bad_wr = *bad_wr;
    while (tmp_bad_wr != NULL) {
        TEST_LOG_ERROR("urma_post_jetty_send_wr ret=%d bad_wr user_ctx=%llu\n", ret, tmp_bad_wr->user_ctx);
        tmp_bad_wr = tmp_bad_wr->next;
    }
    return ret;
}

int test_urma_post_jetty_recv_wr(const urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    int ret;
    *bad_wr = NULL;
    ret = urma_post_jetty_recv_wr(jetty, wr, bad_wr);
    TEST_LOG_DEBUG("urma_post_jetty_recv_wr ret=%d\n", ret);
    urma_jfr_wr_t *tmp_bad_wr = *bad_wr;
    while (tmp_bad_wr != NULL) {
        TEST_LOG_ERROR("urma_post_jetty_recv_wr ret=%d bad_wr user_ctx=%llu\n", ret, tmp_bad_wr->user_ctx);
        tmp_bad_wr = tmp_bad_wr->next;
    }
    return ret;
}

void test_delete_jfs_wr(urma_jfs_wr_t *wr)
{
    if (wr == NULL) {
        return;
    }
    if (wr->opcode == URMA_OPC_WRITE || wr->opcode == URMA_OPC_READ) {
        CHECK_FREE(wr->rw.src.sge);
        CHECK_FREE(wr->rw.dst.sge);
    } else if (wr->opcode == URMA_OPC_SEND) {
        CHECK_FREE(wr->send.src.sge);
    }
    CHECK_FREE(wr);
}

urma_jfs_wr_t *test_fill_jfs_wr_send(test_urma_ctx_t *ctx, uint64_t addr, uint32_t length, urma_target_seg_t *tseg)
{
    uint64_t rva;
    if (ctx == NULL || tseg == NULL) {
        TEST_LOG_ERROR("test_fill_jfs_wr_send failed\n");
        return NULL;
    }

    urma_jfs_wr_t *wr = calloc(1, sizeof(urma_jfs_wr_t));
    CHECK_JUMP(wr == NULL, EXIT, "calloc wr err!\n");
    wr->send.src.num_sge = 1;

    wr->send.src.sge = calloc(wr->send.src.num_sge, sizeof(urma_sge_t));
    CHECK_JUMP(wr->send.src.sge == NULL, EXIT, "calloc sge err!\n");
    wr->send.src.sge[0].addr = addr;
    wr->send.src.sge[0].len = length;
    wr->send.src.sge[0].tseg = tseg;
    wr->send.tseg = NULL;

    memset(wr->send.src.sge[0].addr, 'a', wr->send.src.sge[0].len);
    wr->next = NULL;
    return wr;
EXIT:
    test_delete_jfs_wr(wr);
    return NULL;
}

void test_delete_jfr_wr(urma_jfr_wr_t *wr)
{
    if (wr == NULL) {
        return;
    }
    CHECK_FREE(wr->src.sge);
    CHECK_FREE(wr);
}

urma_jfr_wr_t *test_fill_jfr_wr(test_urma_ctx_t *ctx, uint64_t addr, uint32_t length, urma_target_seg_t *tseg)
{
    if (ctx == NULL) {
        TEST_LOG_ERROR("test_fill_jfr_wr_send failed ctx=null\n", ctx);
        return NULL;
    }
    urma_jfr_wr_t *wr = calloc(1, sizeof(urma_jfr_wr_t));
    CHECK_JUMP(wr == NULL, EXIT, "calloc wr err!\n");
    wr->src.num_sge = 1;
    wr->src.sge = calloc(wr->src.num_sge, sizeof(urma_sge_t));
    CHECK_JUMP(wr->src.sge == NULL, EXIT, "calloc sge failed!\n");
    wr->src.sge[0].addr = addr;
    wr->src.sge[0].len = length;
    wr->src.sge[0].tseg = tseg;
    return wr;
EXIT:
    test_delete_jfr_wr(wr);
    return NULL;
}