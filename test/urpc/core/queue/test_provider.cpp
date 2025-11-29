/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc provider test
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include "dp.h"
#include "queue.h"
#include "state.h"
#include "urma_api.h"
#include "urpc_framework_api.h"
#include "urpc_epoll.h"
#include "urpc_framework_errno.h"
#include "urpc_manage.h"
#include "urpc_framework_types.h"

#define MAX_MSG_SIZE (1UL << 20)
#define TEST_DEV_NUM 4
#define EID_NUM 3

class ProviderTest : public ::testing::Test {
public:
    // SetUP 在每一个 TEST_F 测试开始前执行一次
    void SetUp() override
    {
        urpc_state_set(URPC_STATE_UNINIT);
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
        static urma_jfr_t jfr = {0};
        static urma_jfc_t jfc = {0};
        static urma_jetty_t jetty = {0};
        static urma_target_jetty target_jetty = {0};
        MOCKER(urma_create_jfr).stubs().will(returnValue(&jfr));
        MOCKER(urma_delete_jfr).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jfc).stubs().will(returnValue(&jfc));
        MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_create_jetty).stubs().will(returnValue(&jetty));
        MOCKER(urma_delete_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_import_jetty).stubs().will(returnValue(&target_jetty));
        MOCKER(urma_unimport_jetty).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urpc_mange_event_register).stubs().will(returnValue(URPC_SUCCESS));
        urma_target_seg_t seg = {0};
        MOCKER(urma_register_seg).stubs().will(returnValue(&seg));
    }

    // TearDown 在每一个 TEST_F 测试完成后执行一次
    void TearDown() override
    {
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {}

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {}
};

static urma_status_t urma_query_device_mock(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->dev_cap.max_msg_size = MAX_MSG_SIZE;
    return URMA_SUCCESS;
}

TEST_F(ProviderTest, test_one_eid_dev) {
    static urma_device_t dev = {0};
    dev.type = URMA_TRANSPORT_UB;
    static urma_device_t *device_list = &dev;
    int device_num = 1;
    static uint32_t eid_num = 2;
    static urma_eid_info_t eid_info[2] = {0};
    (void)urma_str_to_eid("127.0.0.1", &eid_info[0].eid);
    (void)urma_str_to_eid("11::22", &eid_info[1].eid);
    static urma_context_t urma_ctx = {0};
    urma_ctx.dev = &dev;
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
    MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_get_eid_list)
        .stubs()
        .with(any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
        .will(returnValue((urma_eid_info_t *)eid_info));
    MOCKER(urma_get_device_list)
        .stubs()
        .with(outBoundP((int *)&device_num, sizeof(device_num)))
        .will(returnValue(&device_list));
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    urma_notifier_t notifier;
    notifier.fd = eventfd(0, EFD_NONBLOCK);
    MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
    MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));

    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_SERVER;
    urpc_config.feature |= URPC_FEATURE_TIMEOUT;
    urpc_config.trans_info_num = 1;
    urpc_config.trans_info[0].assign_mode = (urpc_dev_assign_mode_t)10;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "lo");
    ASSERT_NE(urpc_init(&urpc_config), URPC_SUCCESS);

    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    urpc_uninit();

    urpc_config.role = URPC_ROLE_CLIENT;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_IPV4;
    (void)snprintf(urpc_config.trans_info[0].ipv4.ip_addr, URPC_IPV4_SIZE, "%s", "127.0.0.1");
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    urpc_uninit();

    urpc_config.role = URPC_ROLE_SERVER_CLIENT;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_IPV6;
    (void)snprintf(urpc_config.trans_info[0].ipv6.ip_addr, URPC_IPV6_SIZE, "%s", "11::22");
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    urpc_uninit();

    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_EID;
    (void)urma_str_to_eid("127.0.0.1", (urma_eid_t *)&urpc_config.trans_info[0].ub.eid);
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    urpc_uninit();
    close(notifier.fd);
}

static urma_eid_info_t g_eid_list[TEST_DEV_NUM][EID_NUM];
static urma_context_t urma_ctx[TEST_DEV_NUM];
static urma_device_t g_dev_list[TEST_DEV_NUM];
static urma_device_t *g_dev_ptr_list[TEST_DEV_NUM];
static int g_dev_num;

static void init_device_settings(void)
{
    (void)snprintf(g_dev_list[0].name, URPC_DEV_NAME_SIZE, "%s", "dev0");
    g_dev_list[0].type = URMA_TRANSPORT_UB;
    (void)urma_str_to_eid("192.168.0.1", &g_eid_list[0][0].eid);
    (void)urma_str_to_eid("11::1", &g_eid_list[0][1].eid);
    (void)urma_str_to_eid("12::1", &g_eid_list[0][2].eid);
    g_dev_ptr_list[0] = &g_dev_list[0];

    (void)snprintf(g_dev_list[1].name, URPC_DEV_NAME_SIZE, "%s", "dev1");
    g_dev_list[1].type = URMA_TRANSPORT_UB;
    (void)urma_str_to_eid("192.168.0.2", &g_eid_list[1][0].eid);
    (void)urma_str_to_eid("11::2", &g_eid_list[1][1].eid);
    (void)urma_str_to_eid("12::2", &g_eid_list[1][2].eid);
    g_dev_ptr_list[1] = &g_dev_list[1];

    (void)snprintf(g_dev_list[2].name, URPC_DEV_NAME_SIZE, "%s", "dev2");
    g_dev_list[2].type = URMA_TRANSPORT_UB;
    (void)urma_str_to_eid("192.168.0.3", &g_eid_list[2][0].eid);
    (void)urma_str_to_eid("11::3", &g_eid_list[2][1].eid);
    (void)urma_str_to_eid("12::3", &g_eid_list[2][2].eid);
    g_dev_ptr_list[2] = &g_dev_list[2];

    (void)snprintf(g_dev_list[3].name, URPC_DEV_NAME_SIZE, "%s", "dev3");
    g_dev_list[3].type = URMA_TRANSPORT_UB;
    (void)urma_str_to_eid("192.168.0.4", &g_eid_list[3][0].eid);
    (void)urma_str_to_eid("11::4", &g_eid_list[3][1].eid);
    (void)urma_str_to_eid("12::4", &g_eid_list[3][2].eid);
    g_dev_ptr_list[3] = &g_dev_list[3];
    g_dev_num = TEST_DEV_NUM;
}

static urma_device_t *urma_get_device_by_name_mock(char *dev_name)
{
    for (int i = 0; i < g_dev_num; i++) {
        if ((memcmp(dev_name, g_dev_list[i].name, URMA_MAX_NAME) == 0)) {
            return &g_dev_list[i];
        }
    }

    return NULL;
}

urma_context_t *urma_create_context_mock(urma_device_t *dev, uint32_t eid_index)
{
    int dev_idx = ((uint64_t)(uintptr_t)dev - (uint64_t)(uintptr_t)g_dev_list) / sizeof(urma_device_t);
    urma_context_t *ctx = (urma_context_t *)calloc(1, sizeof(urma_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->dev = dev;
    ctx->eid_index = eid_index;
    ctx->eid = g_eid_list[dev_idx][eid_index].eid;

    return ctx;
}

urma_status_t urma_delete_context_mock(urma_context_t *ctx)
{
    free(ctx);
    return URMA_SUCCESS;
}

urma_eid_info_t *urma_get_eid_list_mock(urma_device_t *dev, uint32_t *cnt)
{
    int dev_idx = ((uint64_t)(uintptr_t)dev - (uint64_t)(uintptr_t)g_dev_list) / sizeof(urma_device_t);
    *cnt = EID_NUM;
    return (urma_eid_info_t *)&g_eid_list[dev_idx];
}

urma_device_t **urma_get_device_list_mock(int *num_devices)
{
    *num_devices = g_dev_num;
    return (urma_device_t **)&g_dev_ptr_list;
}

TEST_F(ProviderTest, test_multi_eid_dev_all_success) {
    init_device_settings();
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(invoke(urma_get_device_by_name_mock));
    MOCKER(urma_create_context).stubs().will(invoke(urma_create_context_mock));
    MOCKER(urma_delete_context).stubs().will(invoke(urma_delete_context_mock));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_get_eid_list).stubs().will(invoke(urma_get_eid_list_mock));
    MOCKER(urma_get_device_list).stubs().will(invoke(urma_get_device_list_mock));
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    urma_target_seg_t tseg;
    MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    urma_notifier_t notifier;
    MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
    MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));

    uint32_t trans_info_num = 1;
    urpc_trans_info_t trans_info[32];
    memset(&trans_info, 0, sizeof(trans_info));
    provider_flag_t flag = {0};
    trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev0");
    ASSERT_EQ(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), trans_info_num);
    provider_uninit();

    trans_info_num++;
    trans_info[1].assign_mode = DEV_ASSIGN_MODE_IPV4;
    trans_info[1].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[1].ipv4.ip_addr, URPC_IPV4_SIZE, "%s", "192.168.0.2");
    ASSERT_EQ(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), trans_info_num);
    provider_uninit();

    trans_info_num++;
    trans_info[2].assign_mode = DEV_ASSIGN_MODE_IPV6;
    trans_info[2].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[2].ipv6.ip_addr, URPC_IPV6_SIZE, "%s", "11::3");
    ASSERT_EQ(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), trans_info_num);
    provider_uninit();

    trans_info_num++;
    trans_info[3].assign_mode = DEV_ASSIGN_MODE_IPV6;
    trans_info[3].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[3].ipv6.ip_addr, URPC_IPV6_SIZE, "%s", "12::3");
    ASSERT_EQ(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), trans_info_num);
    provider_uninit();
}

TEST_F(ProviderTest, test_multi_eid_dev_with_failure) {
    init_device_settings();
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(invoke(urma_get_device_by_name_mock));
    MOCKER(urma_create_context).stubs().will(invoke(urma_create_context_mock));
    MOCKER(urma_delete_context).stubs().will(invoke(urma_delete_context_mock));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_get_eid_list).stubs().will(invoke(urma_get_eid_list_mock));
    MOCKER(urma_get_device_list).stubs().will(invoke(urma_get_device_list_mock));
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    urma_target_seg_t tseg;
    MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    urma_notifier_t notifier;
    MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
    MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));

    uint32_t fail_cnt = 0;
    uint32_t trans_info_num = 1;
    urpc_trans_info_t trans_info[32];
    memset(&trans_info, 0, sizeof(trans_info));
    provider_flag_t flag = {0};
    trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev0000");
    ASSERT_NE(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    fail_cnt++;
    ASSERT_EQ(provider_get_list_size(), trans_info_num - fail_cnt);
    provider_uninit();

    trans_info_num++;
    trans_info[1].assign_mode = DEV_ASSIGN_MODE_IPV4;
    trans_info[1].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[1].ipv4.ip_addr, URPC_IPV4_SIZE, "%s", "192.168.0.10");
    ASSERT_NE(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    fail_cnt++;
    ASSERT_EQ(provider_get_list_size(), trans_info_num - fail_cnt);
    provider_uninit();

    trans_info_num++;
    trans_info[2].assign_mode = DEV_ASSIGN_MODE_IPV6;
    trans_info[2].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[2].ipv6.ip_addr, URPC_IPV6_SIZE, "%s", "11::10");
    ASSERT_NE(provider_init(trans_info_num, trans_info, flag), URPC_SUCCESS);
    fail_cnt++;
    ASSERT_EQ(provider_get_list_size(), trans_info_num - fail_cnt);
    provider_uninit();

    trans_info_num++;
    trans_info[3].assign_mode = DEV_ASSIGN_MODE_IPV6;
    trans_info[3].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(trans_info[3].ipv6.ip_addr, URPC_IPV6_SIZE, "%s", "12::3");
    ASSERT_EQ(provider_init(trans_info_num, trans_info, flag), -URPC_ERR_INIT_PART_FAIL);
    ASSERT_EQ(provider_get_list_size(), trans_info_num - fail_cnt);
    provider_uninit();
}

TEST_F(ProviderTest, test_urpc_init_multi_eid_dev_all_success) {
    init_device_settings();
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(invoke(urma_get_device_by_name_mock));
    MOCKER(urma_create_context).stubs().will(invoke(urma_create_context_mock));
    MOCKER(urma_delete_context).stubs().will(invoke(urma_delete_context_mock));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_get_eid_list).stubs().will(invoke(urma_get_eid_list_mock));
    MOCKER(urma_get_device_list).stubs().will(invoke(urma_get_device_list_mock));
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    urma_target_seg_t tseg;
    MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    urma_notifier_t notifier;
    notifier.fd = eventfd(0, EFD_NONBLOCK);
    MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
    MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));

    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_SERVER;
    urpc_config.feature |= URPC_FEATURE_MULTI_EID;
    urpc_config.trans_info_num = 1;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev1");
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), urpc_config.trans_info_num);
    urpc_uninit();

    urpc_config.trans_info_num++;
    urpc_config.trans_info[1].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[1].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[1].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev2");
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), urpc_config.trans_info_num);
    urpc_uninit();

    urpc_config.trans_info_num++;
    urpc_config.trans_info[2].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[2].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[2].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev3");
    ASSERT_EQ(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), urpc_config.trans_info_num);
    urpc_uninit();
    close(notifier.fd);
}

TEST_F(ProviderTest, test_urpc_init_multi_eid_dev_with_failure) {
    init_device_settings();
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
    MOCKER(urma_get_device_by_name).stubs().will(invoke(urma_get_device_by_name_mock));
    MOCKER(urma_create_context).stubs().will(invoke(urma_create_context_mock));
    MOCKER(urma_delete_context).stubs().will(invoke(urma_delete_context_mock));
    MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
    MOCKER(urma_get_eid_list).stubs().will(invoke(urma_get_eid_list_mock));
    MOCKER(urma_get_device_list).stubs().will(invoke(urma_get_device_list_mock));
    MOCKER(urma_free_device_list).stubs().will(ignoreReturnValue());
    urma_target_seg_t tseg;
    MOCKER(urma_register_seg).stubs().will(returnValue(&tseg));
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
    urma_notifier_t notifier;
    notifier.fd = eventfd(0, EFD_NONBLOCK);
    MOCKER(urma_create_notifier).stubs().will(returnValue(&notifier));
    MOCKER(urma_delete_notifier).stubs().will(returnValue(URMA_SUCCESS));

    urpc_config_t urpc_config;
    memset(&urpc_config, 0, sizeof(urpc_config));
    urpc_config.role = URPC_ROLE_SERVER;
    urpc_config.feature = 0;
    urpc_config.trans_info_num = 1;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_IPV4;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].ipv4.ip_addr, URPC_IPV4_SIZE, "%s", "192.168.0.10");
    ASSERT_NE(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), 0);
    urpc_uninit();

    urpc_config.feature |= URPC_FEATURE_MULTI_EID;
    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev0000");
    ASSERT_NE(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), 0);
    urpc_uninit();

    urpc_config.trans_info[0].assign_mode = DEV_ASSIGN_MODE_DEV;
    urpc_config.trans_info[0].trans_mode = URPC_TRANS_MODE_UB;
    (void)snprintf(urpc_config.trans_info[0].dev.dev_name, URPC_DEV_NAME_SIZE, "%s", "dev5");
    ASSERT_NE(urpc_init(&urpc_config), URPC_SUCCESS);
    ASSERT_EQ(provider_get_list_size(), 0);
    urpc_uninit();
    close(notifier.fd);
}