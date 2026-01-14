/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc allocatore test
 */

#include "gtest/gtest.h"
#include "mockcpp/mockcpp.hpp"
#include "allocator.h"
#include "ip_handshaker.h"
#include "channel.h"
#include "urpc_list.h"
#include "urpc_slist.h"
#include "urma_api.h"
#include "state.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "cp.h"

#define MAX_MSG_SIZE (1UL << 20)

extern urpc_channel_info_t *g_urpc_channels[URPC_MAX_CHANNELS];

static urma_status_t urma_query_device_mock(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->dev_cap.max_msg_size = MAX_MSG_SIZE;
    return URMA_SUCCESS;
}

class UT_Alloc : public ::testing::Test {
public:
    void SetUp() override {
        static urma_device_t dev = {0};
        dev.type = URMA_TRANSPORT_UB;
        static urma_eid_info_t eid_info = {0};
        (void)urma_str_to_eid("127.0.0.1", &eid_info.eid);
        static uint32_t eid_num = 1;
        static urma_context_t urma_ctx = {0};
        urma_ctx.dev = &dev;
        MOCKER(urma_init).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_user_ctl).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_mock));
        MOCKER(urma_get_device_by_name).stubs().will(returnValue(&dev));
        MOCKER(urma_create_context).stubs().will(returnValue(&urma_ctx));
        MOCKER(urma_free_eid_list).stubs().will(ignoreReturnValue());
        MOCKER(urma_get_eid_list)
            .stubs()
            .with(mockcpp::any(), outBoundP((uint32_t *)&eid_num, sizeof(eid_num)))
            .will(returnValue(&eid_info));

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
        MOCKER(urma_delete_context).stubs().will(returnValue(URMA_SUCCESS));
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));

        urma_target_seg_t seg = {0};
        MOCKER(urma_register_seg).stubs().will(returnValue(&seg));
        MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_SUCCESS));
        urpc_state_set(URPC_STATE_INIT);
    }

    void TearDown() override {
        MOCKER(urma_uninit).stubs().will(returnValue(URMA_SUCCESS));
        GlobalMockObject::verify();
    }

    static void SetUpTestCase() {}
    static void TearDownTestCase() {
        GlobalMockObject::verify();
    }
};

int query_local_queue1(queue_t *l_queue, void *ptr)
{
    return 0;
}

TEST_F(UT_Alloc, SegRegisterFailTest) {
    uint64_t tt = 0;
    uint64_t ret = urpc_mem_seg_register((uint64_t)(uintptr_t)&tt, sizeof(tt));
    ASSERT_EQ(ret, (uint64_t)URPC_INVALID_HANDLE);
}

TEST_F(UT_Alloc, SegUnregisterFailTest) {
    mem_handle_t *mem_handle = (mem_handle_t *)calloc(1, sizeof(mem_handle_t) + sizeof(uint64_t));
    ASSERT_NE(mem_handle, nullptr);
    mem_handle->num = 1;
    int ret = urpc_mem_seg_unregister((uint64_t)(uintptr_t)mem_handle);
    ASSERT_EQ(ret, URPC_FAIL);
    free(mem_handle);
}

TEST_F(UT_Alloc, SegTokenGetFailTest) {
    mem_seg_token_t token = {0};

    int ret = urpc_mem_seg_token_get(0, &token);
    ASSERT_EQ(ret, URPC_FAIL);

    ret = urpc_mem_seg_token_get(0x123456, NULL);
    ASSERT_EQ((int)ret, URPC_FAIL);
}

TEST_F(UT_Alloc, DefaultAllocTest) {
    MOCKER(urpc_mem_seg_register).stubs().will(returnValue((uint64_t)1));
    MOCKER(urpc_mem_seg_unregister).stubs().will(returnValue(0));

    default_allocator_cfg_t cfg = {
        .need_large_sge = true,
        .large_sge_size = DEFAULT_LARGE_SGE_SIZE,
    };
    urpc_default_allocator_init(&cfg);

    urpc_state_update(URPC_STATE_INIT);

    urpc_allocator_t *allocator = default_allocator_get();
    urpc_sge_t *sge = NULL;
    uint32_t num;

    uint64_t total_size = 2048;
    int ret = allocator->get(&sge, &num, total_size, NULL);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ASSERT_EQ(num, (uint32_t)16);
    ASSERT_NE(sge, nullptr);
    ret = allocator->put(sge, num, NULL);
    ASSERT_EQ(ret, URPC_SUCCESS);

    total_size = 64;
    ret = allocator->get(&sge, &num, total_size, NULL);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ASSERT_EQ(num, (uint32_t)1);
    ASSERT_NE(sge, nullptr);
    ret = allocator->put(sge, num, NULL);
    ASSERT_EQ(ret, URPC_SUCCESS);

    urpc_allocator_option_t opt = {.qcustom_flag = 2};
    total_size = 2048;
    ret = allocator->get(&sge, &num, total_size, &opt);
    ASSERT_EQ(ret, URPC_SUCCESS);
    ASSERT_EQ(num, (uint32_t)1);
    ASSERT_NE(sge, nullptr);
    ret = allocator->put(sge, num, &opt);
    ASSERT_EQ(ret, URPC_SUCCESS);

    urpc_default_allocator_uninit();
}