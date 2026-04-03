/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: umq test_framework
*/
#include "umq_atom.h"

test_umq_ctx_t g_test_umq_ctx;

const char *ENQUEUE_DATA_DEFAUT = "hello, this is umq enqueue";
size_t enqueue_data_len = strlen(ENQUEUE_DATA_DEFAUT);
const char *POST_DATA_DEFAUT = "hello, this is umq post";
size_t post_data_len = strlen(POST_DATA_DEFAUT);

int test_str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = nullptr;
    if (buf == nullptr || *buf == '-') {
        return TEST_FAILED;
    }
    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return TEST_FAILED;
    }
    if (end == nullptr || *end != '\0' || end == buf) {
        return TEST_FAILED;
    }
    if (ret > UINT_MAX) {
        return TEST_FAILED;
    }
    *u32 = (uint32_t)ret;
    return TEST_SUCCESS;
}

void test_umq_u32_to_eid(uint32_t ipv4, umq_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(UMQ_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int test_umq_str_to_eid(const char *buf, umq_eid_t *eid)
{
    int ret;
    uint32_t ipv4;
    TEST_LOG_INFO("umq_init eid=%s\n", buf);
    if (buf == nullptr || strlen(buf) < UMQ_EID_STR_MIN_LEN || eid == nullptr) {
        TEST_LOG_ERROR("Invalid argument.\n");
        return TEST_FAILED;
    }

    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return TEST_SUCCESS;
    }

    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        test_umq_u32_to_eid(be32toh(ipv4), eid);
        return TEST_SUCCESS;
    }

    ret = test_str_to_u32(buf, &ipv4);
    if (ret == TEST_SUCCESS) {
        test_umq_u32_to_eid(ipv4, eid);
        return TEST_SUCCESS;
    }
    TEST_LOG_ERROR("format error: %s.\n", buf);
    return TEST_FAILED;
}

static uint16_t hexStringToUint16(const char *hexString)
{
    if (strlen(hexString) < 2 || hexString[0] != '0' || hexString[1] != 'x') {
        TEST_LOG_ERROR("Invalid hex string format\n");
        return 0;
    }

    const char *hexPart = hexString + 2;
    long result = strtol(hexPart, NULL, 16);
    if (result < 0 || result > UINT16_MAX) {
        TEST_LOG_ERROR("Value out of uint16_t range\n");
        return 0;
    }

    return (uint16_t)result;
}

void test_get_ubmm_cna(test_umq_ctx_t *ctx)
{
    char cmd_cna[MAX_LINE_LENGTH];
    exec_cmd(cmd_cna, MAX_LINE_LENGTH, "cat /sys/bus/ub/devices/00001/primary_cna");
    ctx->cna = static_cast<uint32_t>(hexStringToUint16(cmd_cna));
    TEST_LOG_INFO("this host cna=%u\n", ctx->cna);
}

void test_get_ubmm_eid(test_umq_ctx_t *ctx)
{
    char cmd_eid[MAX_LINE_LENGTH];
    exec_cmd(cmd_eid, MAX_LINE_LENGTH, "cat /sys/bus/ub/devices/00001/eid");
    ctx->eid = static_cast<uint32_t>(atoi(cmd_eid));
    TEST_LOG_INFO("this host eid=%u\n", ctx->eid);
}

test_umq_ctx_t *test_umq_ctx_init(int argc, char * argv[], int thread_num)
{
    (void)memset(&g_test_umq_ctx, 0, sizeof(test_umq_ctx_t));
    pid_t pid = getpid();
    g_test_umq_ctx.pid = (uint64_t)pid;

    test_context_t *ctx = create_test_ctx(argc, argv, thread_num);
    if (ctx == nullptr) {
        TEST_LOG_ERROR("create_test_ctx failed\n");
        return nullptr;
    }
    g_test_umq_ctx.ctx = ctx;
    g_test_umq_ctx.app_id = ctx->app_id;
    g_test_umq_ctx.app_num = ctx->app_num;

    test_trans_mode_t trans_mode = static_cast<test_trans_mode_t>(ctx->mode);
    switch (trans_mode) {
        case TEST_TRANS_MODE_IP:
        TEST_LOG_INFO("test case trans_mode=%d is IP\n", ctx->mode);
        break;
        case TEST_TRANS_MODE_UB:
        TEST_LOG_INFO("test case trans_mode=%d is UB\n", ctx->mode);
        g_test_umq_ctx.trans_mode = UMQ_TRANS_MODE_UB;
        break;
        case TEST_TRANS_MODE_IB:
        TEST_LOG_INFO("test case trans_mode=%d is IB\n", ctx->mode);
        g_test_umq_ctx.trans_mode = UMQ_TRANS_MODE_IB;
        break;
        case TEST_TRANS_MODE_IPC:
        case TEST_TRANS_MODE_UB_PLUS:
        case TEST_TRANS_MODE_UBMM_PLUS:
            TEST_LOG_INFO("test case trans_mode=%d is PLUS\n", ctx->mode);
            g_test_umq_ctx.trans_mode = static_cast<umq_trans_mode_t>(ctx->mode);
    }

    g_test_umq_ctx.umqh_num = 1;
    return &g_test_umq_ctx;
}

int test_umq_ctx_uninit(test_umq_ctx_t *ctx)
{
    int ret = test_umq_undo_prepare(ctx);
    destroy_test_ctx(g_test_umq_ctx.ctx);
    return ret;
}

int set_trans_dev_info(test_umq_ctx_t *ctx, umq_dev_assign_t *dev_info, umq_dev_assign_mode_t assign_mode)
{
    int ret = TEST_SUCCESS;
    if (assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4) {
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_IPV4;
        (void)sprintf(dev_info->ipv4.ip_addr, "%s", ctx->ctx->test_ip[0]);
        if (ctx->app_id > 1) {
            (void)sprintf(dev_info->ipv4.ip_addr, "%s", ctx->ctx->test_ip[1]);
        }
        TEST_LOG_INFO("ipv4=%s\n", dev_info->ipv4.ip_addr);
    } else if (assign_mode == UMQ_DEV_ASSIGN_MODE_IPV6) {
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_IPV6;
        (void)sprintf(dev_info->ipv6.ip_addr, "%s", ctx->ctx->test_ipv6[0]);
        if (ctx->app_id > 1) {
            (void)sprintf(dev_info->ipv6.ip_addr, "%s", ctx->ctx->test_ipv6[1]);
        }
        TEST_LOG_INFO("ipv6=%s\n", dev_info->ipv6.ip_addr);
    } else if (assign_mode == UMQ_DEV_ASSIGN_MODE_DEV) {
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
        (void)sprintf(dev_info->dev.dev_name, "%s", ctx->ctx->device_name);
        TEST_LOG_INFO("dev_name=%s\n", dev_info->dev.dev_name);
    } else if (assign_mode == UMQ_DEV_ASSIGN_MODE_EID) {
        dev_info->assign_mode = UMQ_DEV_ASSIGN_MODE_EID;
        umq_eid_t eid = {0};
        ret = test_umq_str_to_eid(ctx->ctx->eid, &eid);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("test_umq_str_to_eid failed\n");
        }
        (void *)memcpy(&dev_info->eid.eid, &eid, sizeof(eid));
        TEST_LOG_INFO("eid=%s\n", ctx->ctx->eid);
    } else {
        TEST_LOG_ERROR("error assign_mode\n");
        ret = TEST_FAILED;
    }
    return ret;
}

int set_umq_init_cfg(test_umq_ctx_t *ctx, umq_dev_assign_mode_t assign_mode, umq_trans_mode_t trans_mode)
{
    int ret;
    ctx->cfg.feature = (ctx->cfg.feature == 0) ? UMQ_FEATURE_API_BASE : ctx->cfg.feature;
    ctx->cfg.trans_info_num = 1;
    ctx->cfg.trans_info[0].trans_mode = trans_mode;

    if (trans_mode == UMQ_TRANS_MODE_UBMM_PLUS) {
        test_get_ubmm_cna(ctx);
        ctx->cfg.cna = ctx->cna;
        test_get_ubmm_eid(ctx);
        ctx->cfg.ubmm_eid = ctx->eid;
    }
    return set_trans_dev_info(ctx, &ctx->cfg.trans_info[0].dev_info, assign_mode);
}

int test_umq_init(test_umq_ctx_t *ctx, bool set_default)
{
    int ret;
    if (set_default) {
        set_umq_init_cfg(ctx, UMQ_DEV_ASSIGN_MODE_EID, ctx->trans_mode);
    }
    ret = umq_init(&ctx->cfg);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("umq_init failed, ret=%d\n", ret);
        return TEST_FAILED;
    }
    if (ctx->async_ops.flag == CQ_EVENT_FLAG_ENABLE) {
        ctx->async_ops.epoll_fd = epoll_create1(0);
        if (ctx->async_ops.epoll_fd < 0) {
            TEST_LOG_ERROR("epoll_create1 failed, ret=%d\n", ctx->async_ops.epoll_fd);
        }
    }
    ctx->ctx_flag |= CTX_FLAG_UMQ_INIT;
    return TEST_SUCCESS;
}

void test_umq_uninit(test_umq_ctx_t *ctx)
{
    if ((ctx->ctx_flag & CTX_FLAG_UMQ_INIT) == 0) {
        return;
    }
    TEST_LOG_INFO("umq_uninit\n");
    umq_uninit();
    ctx->ctx_flag &= ~CTX_FLAG_UMQ_INIT;
}

int set_umq_creat_option(test_umq_ctx_t *ctx, bool all_interrupt)
{
    int rc = 0, ret;
    ctx->umqh_ops = (umqh_ops_t *)calloc(ctx->umqh_num, sizeof(umqh_ops_t));
    if (ctx->umqh_ops == nullptr) {
        TEST_LOG_ERROR("umqh_ops calloc failed\n");
        return TEST_FAILED;
    }
    for (uint32_t i = 0; i < ctx->umqh_num; i++) {
        ctx->umqh_ops[i].option.trans_mode = ctx->trans_mode;
        (void *)memcpy(&ctx->umqh_ops[i].option.dev_info, &ctx->cfg.trans_info[0].dev_info,sizeof(umq_dev_assign_t));

        struct timeval tval;
        struct tm log_time;
        (void)gettimeofday(&tval, NULL);
        (void)localtime_r(&tval.tv_sec, &log_time);
        ret = sprintf(ctx->umqh_ops[i].option.name, "%u-%u-%4d%02d%02d%02d%02d%02d", ctx->app_id, i, log_time.tm_year + 1900, 
            log_time.tm_mon + 1, log_time.tm_mday, log_time.tm_hour, log_time.tm_min, log_time.tm_sec);
            if (ret <= 0) {
                TEST_LOG_ERROR("ctx->umqh_ops[%u] set create option name failed\n", i);
                rc++;
            }
            ctx->umqh_ops[i].option.create_flag = UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_RX_DEPTH | UMQ_CREATE_FLAG_TX_BUF_SIZE |
                UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_QUEUE_MODE;
            ctx->umqh_ops[i].option.tx_depth = UMQ_DEFAULT_TX_DEPTH;
            ctx->umqh_ops[i].option.rx_depth = UMQ_DEFAULT_RX_DEPTH;
            ctx->umqh_ops[i].option.tx_buf_size = UMQ_DEFAULT_TX_BUF_SIZE;
            ctx->umqh_ops[i].option.rx_buf_size = UMQ_DEFAULT_RX_BUF_SIZE;

            if (all_interrupt) {
                ctx->umqh_ops[i].option.mode = UMQ_MODE_INTERRUPT;
            } else {
                ctx->umqh_ops[i].option.mode = UMQ_MODE_POLLING;
            }

            if (ctx->trans_mode == UMQ_TRANS_MODE_UBMM_PLUS) {

            }
    }
    return rc;
}

int test_umq_interrupt_fd_get(umqh_ops_t *umqh_ops)
{
    int ret = TEST_SUCCESS;
    umq_interrupt_option_t option = {};
    option.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION;
    option.direction = UMQ_IO_TX;
    umqh_ops->tx_fd = umq_interrupt_fd_get(umqh_ops->qh, &option);
    option.direction = UMQ_IO_RX;
    umqh_ops->rx_fd = umq_interrupt_fd_get(umqh_ops->qh, &option);
    if (umqh_ops->tx_fd <= 0){
        TEST_LOG_ERROR("umqh_ops[%u] umq_interrupt_fd_get tx failed\n", umqh_ops->idx);
        ret = TEST_FAILED;
    }
    if (umqh_ops->rx_fd <= 0) {
        TEST_LOG_ERROR("umqh_ops[%u] umq_interrupt_fd_get rx failed\n", umqh_ops->idx);
        ret = TEST_FAILED;
    }
    struct epoll_event event;
    event.data.fd = umqh_ops->tx_fd;
    event.events = EPOLLIN;
    ret = epoll_ctl(g_test_umq_ctx.async_ops.epoll_fd, EPOLL_CTL_ADD, umqh_ops->tx_fd, &event);
    if (ret != 0) {
        TEST_LOG_ERROR("umqh_ops[%u] epoll_ctl tx failed\n", umqh_ops->idx);
        ret = TEST_FAILED;
    }
    event.data.fd = umqh_ops->rx_fd;
    ret = epoll_ctl(g_test_umq_ctx.async_ops.epoll_fd, EPOLL_CTL_ADD, umqh_ops->rx_fd, &event);
    if (ret != 0) {
        TEST_LOG_ERROR("umqh_ops[%u] epoll_ctl rx failed\n", umqh_ops->idx);
        ret = TEST_FAILED;
    }
    return ret;
}

int test_umq_create(test_umq_ctx_t *ctx, bool set_default)
{
    int rc = 0;
    TEST_LOG_INFO("ctx->umqh_num=%u\n", ctx->umqh_num);
    if (ctx->umqh_num == 0) {
        return TEST_SUCCESS;
    }

    if (set_default) {
        if (set_umq_creat_option(ctx)) {
            return TEST_FAILED;
        }
    }
    uint32_t umqh_num = ctx->umqh_num;
    ctx->umqh_num = 0;
    for (uint32_t i = 0; i < umqh_num; i++) {
        ctx->umqh_ops[i].src_app_id = ctx->app_id;
        ctx->umqh_ops[i].qh = umq_create(&ctx->umqh_ops[i].option);
        if (ctx->umqh_ops[i].qh == UMQ_INVALID_HANDLE) {
            TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_create failed\n", i);
        } else {
            ctx->umqh_num++;
        }
        if (ctx->async_ops.flag == CQ_EVENT_FLAG_ENABLE && ctx->umqh_ops[i].option.mode == UMQ_MODE_INTERRUPT) {
            rc += test_umq_interrupt_fd_get(&ctx->umqh_ops[i]);
        }
    }
    if (ctx->umqh_num > 0) {
        ctx->ctx_flag |= CTX_FLAG_UMQ_CREATE;
    }
    if (ctx->umqh_num != umqh_num || rc != 0) {
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_umq_destroy(test_umq_ctx_t *ctx)
{
    int rc = 0, ret;
    if (ctx->umqh_ops == nullptr || (ctx->ctx_flag & CTX_FLAG_UMQ_CREATE) == 0) {
        return TEST_SUCCESS;
    }
    for (uint32_t i = 0; i < ctx->umqh_num; i++) {
        if ((ctx->cfg.feature & UMQ_FEATURE_API_PRO) != 0) {
            test_umq_flush(&ctx->umqh_ops[i]);
        }
        ret = umq_destroy(ctx->umqh_ops[i].qh);
        if (ret != TEST_SUCCESS) {
            rc++;
            TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_destroy failed\n", i);
        }
    }
    if (rc == 0) {
        ctx->ctx_flag &= ~CTX_FLAG_UMQ_CREATE;
        CHECK_FREE(ctx->umqh_ops);
    }
    return rc;
}

int test_umq_bind_info_get(test_umq_ctx_t *ctx)
{
    int success_num = 0, ret;
    for (uint32_t i = 0; i < ctx->umqh_num; i++) {
        ret = umq_bind_info_get(ctx->umqh_ops[i].qh, ctx->umqh_ops[i].l_binfo, TEST_UMQ_MAX_BIND_INFO_SIZE);
        if (ret <= 0) {
            TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_bind_info_get failed\n", i);
        } else {
            ctx->umqh_ops[i].l_binfo_len = ret;
            success_num++;
        }
    }
    if (success_num > 0) {
        ctx->ctx_flag |= CTX_FLAG_UMQ_L_BINFO_GET;
    }
    if (ctx->umqh_num == success_num) {
        return TEST_SUCCESS;
    }
    return TEST_FAILED;
}

static exchange_bind_info_t test_sync_bind_info(test_umq_ctx_t *ctx, uint32_t src_app_id, exchange_bind_info_t *sinfo, int len)
{
    exchange_bind_info_t rinfo = {0};
    if (ctx->app_id == src_app_id) {
        memcpy(&rinfo, sinfo, len);
    }
    sync_data(src_app_id, (char*)&rinfo, len);
    return rinfo;
}

void test_exchange_bind_info(test_umq_ctx_t *ctx, uint32_t src_app_id, uint32_t dst_app_id, uint32_t l_qidx, uint32_t r_qidx)
{
    exchange_bind_info_t sinfo = {0};
    if (ctx->app_id == src_app_id) {
        sinfo.src_app_id = src_app_id;
        sinfo.dst_app_id = dst_app_id;
        sinfo.l_qidx = l_qidx;
        sinfo.r_qidx = r_qidx;
        sinfo.bind_info_len = ctx->umqh_ops[l_qidx].l_binfo_len;
        (void *)memcpy(&sinfo.bind_info, &ctx->umqh_ops[l_qidx].l_binfo, TEST_UMQ_MAX_BIND_INFO_SIZE);
    }

    if (ctx->app_id != dst_app_id) {
        test_sync_bind_info(ctx, src_app_id, &sinfo, sizeof(exchange_bind_info_t));
    }
    if (ctx->app_id == dst_app_id) {
        exchange_bind_info_t rinfo = test_sync_bind_info(ctx, src_app_id, &sinfo, sizeof(exchange_bind_info_t));
        for (uint32_t i = 0; i < ctx->umqh_num; i++) {
            if (i == rinfo.r_qidx) {
                ctx->umqh_ops[i].r_qidx = rinfo.l_qidx;
                ctx->umqh_ops[i].r_binfo_len = rinfo.bind_info_len;
                (void *)memcpy(&ctx->umqh_ops[i].r_binfo, &rinfo.bind_info, TEST_UMQ_MAX_BIND_INFO_SIZE);
                ctx->umqh_ops[i].dst_app_id = rinfo.src_app_id;
            }
        }
    }
}

void test_umq_bind_info_exchange(test_umq_ctx_t *ctx)
{
    for (uint32_t i = 0; i< ctx->umqh_num; i++) {
        test_exchange_bind_info(ctx, PROC_1, PROC_2, i, i);
    }
    for (uint32_t i = 0; i< ctx->umqh_num; i++) {
        test_exchange_bind_info(ctx, PROC_2, PROC_1, i, i);
    }
}

static bool is_all_zero(const uint8_t *array, size_t length)
{
    uint8_t zero_array[length];
    memset(zero_array, 0, length);
    return memcmp(array, zero_array, length) == 0;
}

int test_umq_bind_one(umqh_ops_t *umqh_ops)
{
    int ret;
    if (umqh_ops->r_binfo_len == 0 || is_all_zero(umqh_ops->r_binfo, TEST_UMQ_MAX_BIND_INFO_SIZE)) {
        return TEST_SUCCESS;
    }
    return umq_bind(umqh_ops->qh, umqh_ops->r_binfo, umqh_ops->r_binfo_len);
}

int test_umq_unbind_one(umqh_ops_t *umqh_ops)
{
    int ret;
    if (umqh_ops->r_binfo_len == 0 || is_all_zero(umqh_ops->r_binfo, TEST_UMQ_MAX_BIND_INFO_SIZE)) {
        return TEST_SUCCESS;
    }
    return umq_unbind(umqh_ops->qh);
}

int test_umq_bind(test_umq_ctx_t *ctx)
{
    int ret;
    for (uint32_t i = 0; i <ctx->umqh_num; i++) {
        ret = test_umq_bind_one(&ctx->umqh_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_bind failed\n", i);
            return TEST_FAILED;
        }
    }
    ctx->ctx_flag |= CTX_FLAG_UMQ_BIND;
    return TEST_SUCCESS;
}

int test_umq_unbind(test_umq_ctx_t *ctx)
{
    int ret;
    if ((ctx->ctx_flag & CTX_FLAG_UMQ_BIND) == 0) {
        return TEST_SUCCESS;
    }
    for (uint32_t i = 0;i < ctx->umqh_num; i++) {
        ret = test_umq_unbind_one(&ctx->umqh_ops[i]);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_bind failed\n", i);
            return TEST_FAILED;
        }
    }
    ctx->ctx_flag &= ~CTX_FLAG_UMQ_BIND;
    return TEST_SUCCESS;
}

int test_umq_prepare(test_umq_ctx_t *ctx)
{
    int ret;
    ret = test_umq_init(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_init", EXIT);
    ret = test_umq_create(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_create", EXIT);
    ret = test_umq_bind_info_get(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_bind_info_get", EXIT);
    
    test_umq_bind_info_exchange(ctx);

    ret = test_umq_bind(ctx);
    CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_bind", EXIT);
    
    if ((ctx->cfg.feature & UMQ_FEATURE_API_PRO) != 0) {
        ret = test_umq_post_rx(ctx);
        CHKERR_JUMP(ret != TEST_SUCCESS, "test_umq_post_rx", EXIT);
    }
EXIT:
    return ret;
}

int test_umq_undo_prepare(test_umq_ctx_t *ctx)
{
    int ret = TEST_FAILED;
    ret = test_umq_unbind(ctx);
    TEST_LOG_INFO("test_umq_unbind return %d\n", ret);
    ret += test_umq_destroy(ctx);
    TEST_LOG_INFO("test_umq_destroy return %d\n", ret);
    test_umq_uninit(ctx);
    return ret;
}

static void md5_hash(const char *str, uint8_t digest[MD5_DIGEST_LENGTH])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    if (ctx == NULL || md == NULL) {
        TEST_LOG_ERROR("Error initializing MD5 context\n");
        if (ctx) 
            EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestInit(ctx, md) != 1) {
        TEST_LOG_ERROR("Error initializing MD5 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestUpdate(ctx, str, strlen(str)) != 1) {
        TEST_LOG_ERROR("Error updating MD5 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestFinal(ctx, digest, NULL) != 1) {
        TEST_LOG_ERROR("Error finalizing MD5 digest\n");
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);
}

static void print_md5(uint8_t digest[MD5_DIGEST_LENGTH])
{
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

static void generate_random_data(char *data, size_t data_size, uint32_t *seed = nullptr)
{
    unsigned int seedd = (seed == nullptr) ?  (unsigned int)get_timestamp_ns() : *seed;
    for (int i = 0; i < (data_size - 1); i++) {
        *(data + i) = 'a' + rand_r(&seedd) % LETTERS_NUM;
    }
    *(data + data_size - 1) = '\0';
}

static int check_buf_data_diff(char * data, uint8_t digest[MD5_DIGEST_LENGTH])
{
    uint8_t ldigest[MD5_DIGEST_LENGTH];
    md5_hash(data, ldigest);
    if (memcmp(ldigest, digest, MD5_DIGEST_LENGTH) != 0) {
        return true;
    }
    return false;
}

int test_umq_buf_fill(umqh_ops_t *umqh_ops, umq_buf_t *buf, const char *data, uint32_t data_size)
{
    if (g_test_umq_ctx.cfg.headroom_size == 0) {
        buf->io_direction = UMQ_IO_TX;
        if (data_size <= UMQ_QBUF_BLOCK_SIZE) {
            (void *)memcpy(buf->buf_data, data, data_size);
            buf->data_size = data_size;
            buf->total_data_size = data_size;
        } else {
            buf->data_size = UMQ_QBUF_BLOCK_SIZE;
            buf->total_data_size = data_size;
        }
        return TEST_SUCCESS;
    }
    if (data_size > UMQ_QBUF_BLOCK_SIZE) {
        TEST_LOG_ERROR("big data should not config headroom_size\n");
        umq_buf_free(buf);
        return TEST_FAILED;
    }

    uint32_t buf_size = data_size - TEST_DATA_HEADER_SIZE;
    buf->buf_data -= TEST_DATA_HEADER_SIZE;
    test_data_header_t *header = (test_data_header_t *)buf->buf_data;
    header->src_app_id = umqh_ops->src_app_id;
    header->dst_app_id = umqh_ops->dst_app_id;
    header->l_qidx = umqh_ops->idx;
    header->r_qidx = umqh_ops->r_qidx;
    header->data_type = SMALL_IO_HAS_RSP;
    header->data_size = data_size;
    header->total_size = data_size;
    if (data != nullptr) {
        md5_hash(data, header->digest);
    }
    

    buf->buf_data += TEST_DATA_HEADER_SIZE;
    buf->headroom_size = TEST_DATA_HEADER_SIZE;
    if (data != nullptr) {
        (void *)memcpy(buf->buf_data, data, buf_size);
    }
    buf->data_size = data_size;
    buf->total_data_size = data_size;

    int ret =  umq_buf_headroom_reset(buf, 0);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("umq_buf_headroom_reset failed\n");
        umq_buf_free(buf);
        return TEST_FAILED;
    }
    return TEST_SUCCESS;
}

int test_umq_buf_parse(umq_buf_t *buf, const char *data, uint32_t data_size)
{
    int ret = TEST_SUCCESS;
    TEST_LOG_INFO("buf->total_data_size=%u buf->headroom_size=%u\n", buf->total_data_size, buf->headroom_size);
    if (g_test_umq_ctx.cfg.headroom_size == TEST_DATA_HEADER_SIZE) {
        test_data_header_t *header = (test_data_header_t *)buf->buf_data;
        TEST_LOG_INFO("header->data_type=%u\n", header->data_type);
        print_md5(header->digest);
        buf->buf_data += TEST_DATA_HEADER_SIZE;
        if (check_buf_data_diff((char *)buf->buf_data, header->digest)) {
            ret = TEST_FAILED;
        }
    } else {
        if (buf->total_data_size != data_size) {
            TEST_LOG_ERROR("polled total_data_size [%u] doesn't match check data_size[%u]\n", buf->total_data_size, data_size);
            ret = TEST_FAILED;
        }
        if (buf->buf_data == nullptr) {
            TEST_LOG_WARN("buf->buf_data is null\n");
            goto EXIT;
        }
        if (buf->total_data_size <= UMQ_QBUF_BLOCK_SIZE) {
            if (memcmp((char *)buf->buf_data, data, data_size) != 0) {
                TEST_LOG_ERROR("buf data doesn't match check data\n");
                ret = TEST_FAILED;
            }
        }
    }
EXIT:
    umq_buf_free(buf);
    return ret;
}

uint64_t get_buf_alloc_umqh(umqh_ops_t *umqh_ops, uint32_t data_size)
{
    uint64_t umqh = 0;
    if (g_test_umq_ctx.trans_mode == UMQ_TRANS_MODE_UBMM_PLUS) {
        if (data_size <= UMQ_QBUF_BLOCK_SIZE) {
            umqh = umqh_ops->qh;
        } else {
            umqh = 0;
        }
    } else if (g_test_umq_ctx.trans_mode == UMQ_TRANS_MODE_IPC) {
        umqh = umqh_ops->qh;
    } else {
        umqh = 0;
    }
    return umqh;
}

umq_buf_t *test_umq_buf_alloc(umqh_ops_t *umqh_ops, umq_alloc_option_t *option, const char *data, uint32_t data_size)
{
    uint32_t request_qbuf_num = data_size % UMQ_QBUF_BLOCK_SIZE == 0 ? data_size / UMQ_QBUF_BLOCK_SIZE : data_size / UMQ_QBUF_BLOCK_SIZE + 1;
    uint32_t request_size = data_size > UMQ_QBUF_BLOCK_SIZE ? UMQ_QBUF_BLOCK_SIZE : data_size;
    TEST_LOG_INFO("umq_buf_alloc request_size=%u request_qbuf_num=%u\n", data_size, request_qbuf_num);
    uint64_t umqh = get_buf_alloc_umqh(umqh_ops, data_size);

    umq_buf_t *buf = umq_buf_alloc(request_size, request_qbuf_num, umqh, option);
    if (buf == nullptr) {
        TEST_LOG_ERROR("umq_buf_alloc buf is null\n");
        return nullptr;
    }

    buf->total_data_size = data_size;
    int ret = test_umq_buf_fill(umqh_ops, buf, data, data_size);
    if (ret != TEST_SUCCESS) {
        umq_buf_free(buf);
        return nullptr;
    }
    return buf;
}

int test_umq_rearm_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, bool solicated)
{
    if (umqh_ops->option.mode != UMQ_MODE_INTERRUPT) {
        return TEST_SUCCESS;
    }

    umq_interrupt_option_t interrupt_option = {.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION, .direction = direction};
    return umq_rearm_interrupt(umqh_ops->qh, false, &interrupt_option);
}

int test_umq_wait_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, int timeout)
{
    if (umqh_ops->option.mode != UMQ_MODE_INTERRUPT) {
        return 1;
    }

    umq_interrupt_option_t interrupt_option = {.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION, .direction = direction};
    return umq_wait_interrupt(umqh_ops->qh, timeout, &interrupt_option);
}

int test_umq_get_cq_event(umqh_ops_t *umqh_ops, umq_io_direction_t direction, int timeout)
{
    int ret, num;
    struct epoll_event epoll_event;
    umq_interrupt_option_t option = {.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION, .direction = direction};
    do {
        ret = epoll_wait(g_test_umq_ctx.async_ops.epoll_fd, &epoll_event, 1, timeout);
    } while (ret == -1 && errno == EINTR);
    if (ret == -1 && errno != EINTR) {
        TEST_LOG_ERROR("epoll_wait, ret:%d errno:%d, message: %s.\n", ret, errno, strerror(errno));
        goto EXIT;
    }
    if (direction == UMQ_IO_TX && epoll_event.data.fd != umqh_ops->tx_fd) {
        TEST_LOG_ERROR("epoll_event.data.fd != umqh_ops->tx_fd.\n");
        goto EXIT;
    }
    if (direction == UMQ_IO_RX && epoll_event.data.fd != umqh_ops->rx_fd) {
        TEST_LOG_ERROR("epoll_event.data.fd != umqh_ops->rx_fd.\n");
        goto EXIT;
    }
    num = umq_get_cq_event(umqh_ops->qh, &option);
    return num;
EXIT:
    return TEST_FAILED;
}

void test_umq_ack_interrupt(umqh_ops_t *umqh_ops, umq_io_direction_t direction, uint32_t nevents)
{
    if (umqh_ops->option.mode != UMQ_MODE_INTERRUPT) {
        return;
    }
    umq_interrupt_option_t interrupt_option = {.flag = UMQ_INTERRUPT_FLAG_IO_DIRECTION, .direction = direction};
    umq_ack_interrupt(umqh_ops->qh, nevents, &interrupt_option);
}

void test_data_args_fill(test_data_args_t *data_args)
{
    int ret = TEST_SUCCESS;
    if (data_args->data != nullptr) {
        return;
    }

    data_args->data_size = (data_args->data_size == 0) ? 1024 : data_args->data_size;
    data_args->data = (char *)malloc(data_args->data_size);
    if (data_args->seed != nullptr) {
        generate_random_data(data_args->data, data_args->data_size, data_args->seed);
        return;
    }
    generate_random_data(data_args->data, data_args->data_size);
}


int test_umq_post_rx_buf(umqh_ops_t *umqh_ops, uint32_t depth, uint32_t size, uint64_t *status)
{
    uint32_t rx_depth = (depth == 0) ? UMQ_MAX_WR_COUNT : depth;
    uint32_t buf_size = (size == 0) ? umqh_ops->option.rx_buf_size : size;
    umq_buf_t *buf = umq_buf_alloc(buf_size, rx_depth, 0, nullptr);
    if (buf == nullptr) {
        TEST_LOG_ERROR("umq_buf_alloc failed\n");
        return TEST_FAILED;
    }

    umq_buf_t *bad_buf = nullptr;
    if (umq_post(umqh_ops->qh, buf, UMQ_IO_RX, &bad_buf) != TEST_SUCCESS) {
        TEST_LOG_ERROR("umq_post rx failed\n");
        umq_buf_free(bad_buf);
        return TEST_FAILED;
    }
    if (status) {
        usleep(STATUS_SLEEP_TIME_US);
        *status += buf->status;
    }
    return TEST_SUCCESS;
}

int test_umq_post_rx(test_umq_ctx_t *ctx, uint32_t depth, umqh_ops_t *umqh_ops, uint64_t *status)
{
    int ret;

    if (umqh_ops == nullptr) {
        for(uint32_t i = 0; i < ctx->umqh_num; i++) {
            ret = test_umq_post_rx_buf(&ctx->umqh_ops[i], depth);
            if (ret != TEST_SUCCESS) {
                TEST_LOG_ERROR("ctx->umqh_ops[%u] umq_post rx failed\n", i);
                return TEST_FAILED;
            }
        }
    } else {
        ret = test_umq_post_rx_buf(umqh_ops, depth);
        if (ret != TEST_SUCCESS) {
            TEST_LOG_INFO("umq_post rx failed\n")
            return TEST_FAILED;
        }
    }
    
    return TEST_SUCCESS;
}

int test_umq_post_tx_buf(umqh_ops_t *umqh_ops, const char *data, uint32_t data_size, uint64_t *status)
{
    umq_buf_t *buf = nullptr;
    if (g_test_umq_ctx.cfg.headroom_size == 0) {
        buf = test_umq_buf_alloc(umqh_ops, nullptr, data, data_size);
    } else {
        uint32_t total_size = data_size + g_test_umq_ctx.cfg.headroom_size;
        umq_alloc_option_t option = {0};
        option.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
        option.headroom_size = g_test_umq_ctx.cfg.headroom_size;
        buf = test_umq_buf_alloc(umqh_ops, &option, data, total_size);
    }
    if (buf == nullptr) {
        return TEST_FAILED;
    }

    umq_buf_pro_t *pro = (umq_buf_pro_t *)buf->qbuf_ext;
    pro->flag.bs.solicited_enable = 1;
    pro->flag.bs.complete_enable = 1;
    if (umqh_ops->opcode == UMQ_OPC_SEND_IMM) {
        pro->imm_data = TEST_IMM_DATA;
        pro->opcode = UMQ_OPC_SEND_IMM;
        TEST_LOG_INFO("UMQ_OPC_SEND_IMM:%d\n", pro->opcode);
    } else if (umqh_ops->opcode == UMQ_OPC_SEND || umqh_ops->opcode ==0) {
        pro->opcode = UMQ_OPC_SEND;
        TEST_LOG_INFO("UMQ_OPC_SEND:%d\n", pro->opcode);
    }
    

    umq_buf_t *bad_buf = nullptr;
    if (umq_post(umqh_ops->qh, buf, UMQ_IO_TX, &bad_buf) != TEST_SUCCESS) {
        TEST_LOG_ERROR("umq_post failed\n");
        umq_buf_free(bad_buf);
        return TEST_FAILED;
    }
    if (status) {
        usleep(STATUS_SLEEP_TIME_US);
        *status += buf->status;
    }

    return TEST_SUCCESS;
}

int test_umq_poll(uint64_t umqh, umq_io_direction_t direction, umq_buf_t **buf, uint32_t buf_count, uint64_t timeout)
{
    int ret = 0;
    uint64_t start = get_timestamp_ms();
    while (ret == 0 && get_timestamp_ms() - start < timeout) {
        ret = umq_poll(umqh, direction, buf, TEST_MAX_POLL_BATCH);
        usleep(DEQUEUE_SLEEP_TIME_US);
    }
    if (ret <= 0 || buf[0] == nullptr) {
        TEST_LOG_ERROR("umq_poll return nothing after timeout,%d %p\n", ret, buf[0]);
        free(buf);
        return TEST_FAILED;
    }
    return ret;
}

int test_umq_poll_tx_buf(umqh_ops_t *umqh_ops, uint64_t timeout, uint64_t *status)
{
    umq_buf_t **buf = (umq_buf_t **)calloc(TEST_MAX_POLL_BATCH, sizeof(umq_buf_t *));
    int ret = test_umq_poll(umqh_ops->qh, UMQ_IO_TX, buf, {}, timeout);
    if (ret == TEST_FAILED) {
        return TEST_FAILED;
    }
    TEST_LOG_INFO("tx polled %d\n", ret);
    for (int i = 0; i < ret; ++i) {
        umq_buf_t *tmp_buf = buf[i];
        int32_t rest_data_size = (int32_t)tmp_buf->total_data_size;
        while (tmp_buf && rest_data_size > 0) {
            rest_data_size -= tmp_buf->data_size;
            if (rest_data_size <=0) {
                tmp_buf->qbuf_next = nullptr;
                break;
            }
            tmp_buf = tmp_buf->qbuf_next;
        }
        if (status) {
            usleep(STATUS_SLEEP_TIME_US);
            *status += buf[i]->status;
        }
        umq_buf_free(buf[i]);
    }
    free(buf);
    return TEST_SUCCESS;
}

int test_umq_poll_rx_buf(umqh_ops_t *umqh_ops, const char *data, uint32_t data_size, uint64_t timeout, uint64_t *status)
{
    umq_buf_t **buf = (umq_buf_t **)calloc(TEST_MAX_POLL_BATCH, sizeof(umq_buf_t *));
    int ret = test_umq_poll(umqh_ops->qh, UMQ_IO_RX, buf, {}, timeout);
    if (ret == TEST_FAILED) {
        return TEST_FAILED;
    }
    TEST_LOG_INFO("rx polled\n");
    if (data != nullptr)
    {
        if (!umqh_ops->not_check_data) {
            ret = test_umq_buf_parse(buf[0], data, data_size);
        }
    }

    buf[0] = nullptr;
    for (int i = 0; i < ret; i++) {
        if (status) {
            usleep(STATUS_SLEEP_TIME_US);
            *status += buf[i]->status;
        }
        umq_buf_free(buf[i]);
    }
    free(buf);
    if (ret == TEST_FAILED) {
        return ret;
    }
    return TEST_SUCCESS;
}

void test_umq_flush(umqh_ops_t *umqh_ops, umq_io_direction_t direction, uint64_t timeout)
{
    int ret = 0;
    umq_buf_t *buf[TEST_MAX_POLL_BATCH];
    uint64_t start = get_timestamp_ms();
    while (get_timestamp_ms() - start < DEFAULT_FLUSH_TIME_MS) {
        ret = umq_poll(umqh_ops->qh, direction, buf, TEST_MAX_POLL_BATCH);
        if (ret > 0) {
            for (int i = 0; i < ret; ++i) {
                umq_buf_t *tmp_buf = buf[i];
                int32_t rest_data_size = (int32_t)tmp_buf->total_data_size;
                while (tmp_buf && rest_data_size > 0) {
                    rest_data_size -= (int32_t)tmp_buf->data_size;
                    if (rest_data_size <= 0) {
                        tmp_buf->qbuf_next = NULL;
                        break;
                    }
                    tmp_buf = tmp_buf->qbuf_next;
                }
                umq_buf_free(buf[i]);
            }
        }
    }
}

int test_umq_pro_func_req(test_data_args_t *data_args)
{
    int ret, nevents;
    if (g_test_umq_ctx.cfg.headroom_size == 0) {
        TEST_LOG_ERROR("umq_init_cfg.headroom_size is 0\n");
        return TEST_FAILED;
    }
    if (test_umq_rearm_interrupt(data_args->umqh_ops, UMQ_IO_TX)) {
        TEST_LOG_ERROR("test_umq_rearm_interrupt failed\n");
        return TEST_FAILED;
    }
    test_data_args_fill(data_args);
    ret = test_umq_post_tx_buf(data_args->umqh_ops, data_args->data, data_args->data_size);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("ctx->umqh_ops[%u] test_post_tx_data failed\n", data_args->umqh_ops->idx);
        CHECK_FREE(data_args->data);
        return TEST_FAILED;
    }
    CHECK_FREE(data_args->data);
    if (g_test_umq_ctx.async_ops.flag == CQ_EVENT_FLAG_ENABLE) {
        nevents = test_umq_get_cq_event(data_args->umqh_ops, UMQ_IO_TX);
        if (nevents < 1) {
            TEST_LOG_ERROR("test_umq_get_cq_event failed\n");
            return TEST_FAILED;
        }
    } else {
        nevents = test_umq_wait_interrupt(data_args->umqh_ops, UMQ_IO_TX);
        if (nevents < 1) {
            TEST_LOG_ERROR("test_umq_wait_interrupt failed\n");
            return TEST_FAILED;
        }
    }
    ret = test_umq_poll_tx_buf(data_args->umqh_ops);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("ctx->umqh_ops[%u] test_umq_poll_tx_buf failed\n", data_args->umqh_ops->idx);
        return TEST_FAILED;
    }
    test_umq_ack_interrupt(data_args->umqh_ops, UMQ_IO_TX, nevents);
    return TEST_SUCCESS;
}

int test_umq_pro_func_rsp(test_data_args_t *data_args)
{
    int ret, nevents;
    if (g_test_umq_ctx.cfg.headroom_size == 0) {
        TEST_LOG_ERROR("umq_init_cfg.headroom_size is 0\n");
        return TEST_FAILED;
    }
    if (test_umq_rearm_interrupt(data_args->umqh_ops, UMQ_IO_RX)) {
        TEST_LOG_ERROR("test_umq_rearm_interrupt failed\n");
        return TEST_FAILED;
    }
    if (g_test_umq_ctx.async_ops.flag == CQ_EVENT_FLAG_ENABLE) {
        nevents = test_umq_get_cq_event(data_args->umqh_ops, UMQ_IO_RX, 30 * 1000);
        if (nevents < 1) {
            TEST_LOG_ERROR("test_umq_get_cq_event failed\n");
            return TEST_FAILED;
        }
    } else {
        nevents = test_umq_wait_interrupt(data_args->umqh_ops, UMQ_IO_RX, 30 * 1000);
        if (nevents < 1) {
            TEST_LOG_ERROR("test_umq_wait_interrupt failed\n");
            return TEST_FAILED;
        }
    }
    ret = test_umq_poll_rx_buf(data_args->umqh_ops, data_args->data, data_args->data_size, DEQUEUE_TIMEOUT_MS);
    if (ret != TEST_SUCCESS) {
        TEST_LOG_ERROR("ctx->umqh_ops[%u] test_umq_poll_rx_buf failed\n", data_args->umqh_ops->idx);
        CHECK_FREE(data_args->data);
        return TEST_FAILED;
    }
    CHECK_FREE(data_args->data);
    test_umq_ack_interrupt(data_args->umqh_ops, UMQ_IO_RX, nevents);
    return TEST_SUCCESS;
}