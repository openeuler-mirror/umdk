/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * File Name     : test_urma_ctx.cpp
 * Description   : dlock unit test cases for the functions of urma_ctx class
 * History       : create file & add functions
 * 1.Date        : 2024-3-19
 * Author        : huying
 * Modification  : Created file
 */
#include <stdlib.h>

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "mockcpp/mockcpp.h"
#include "mockcpp/mockcpp.hpp"

#include "dlock_types.h"
#include "urma_ctx.h"
#include "utils.h"
#include "test_dlock_comm.h"

#ifndef MOCKER_CPP
#define MOCKER_CPP(api, TT) MOCKCPP_NS::mockAPI(#api, reinterpret_cast<TT>(api))
#endif

class test_urma_ctx : public testing::Test {
protected:
    urma_ctx *m_urma_ctx;
    const dlock_eid_t eid = {0};
    trans_mode_t tp_mode = SEPERATE_CONN;

    void SetUp()
    {
        struct urma_ctx_cfg urma_cfg = {
            .num_buf = SERVER_URMA_CTX_REG_BUF_NUM,
            .num_cqe = MAX_NUM_CLIENT * CQ_SIZE_PER_CLIENT,
            .dev_name = nullptr,
            .eid = eid,
            .ub_token_disable = false,
        };

        m_urma_ctx = new(std::nothrow) urma_ctx(urma_cfg);

        ASSERT_NE(m_urma_ctx, nullptr);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_urma_ctx;
    }
};

TEST_F(test_urma_ctx, test_create_ctx_1_device_name_null)
{
    m_urma_ctx->m_dev_name = "";
    dlock_status_t ret = m_urma_ctx->create_ctx();
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_create_ctx_2_malloc_failed)
{
    MOCKER(malloc).stubs().will(returnValue((void *)nullptr));

    dlock_status_t ret = m_urma_ctx->create_ctx();
    EXPECT_EQ(ret, DLOCK_ENOMEM);
}

TEST_F(test_urma_ctx, test_create_ctx_3_strcpy_failed)
{
    MOCKER(strcpy).stubs().will(returnValue(-1));

    dlock_status_t ret = m_urma_ctx->create_ctx();
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_create_ctx_4_urma_get_device_by_name_failed)
{
    MOCKER(urma_get_device_by_name).stubs().will(returnValue((urma_device_t *)nullptr));

    dlock_status_t ret = m_urma_ctx->create_ctx();
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_create_ctx_5_urma_create_context_failed)
{
    MOCKER(urma_create_context).stubs().will(returnValue((urma_context_t *)nullptr));

    dlock_status_t ret = m_urma_ctx->create_ctx();
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_query_urma_device_1_by_eid_succ)
{
    MOCKER_CPP(&urma_ctx::check_urma_device_state_by_eid, dlock_status_t (*)(urma_ctx *, const dlock_eid_t))
        .stubs().will(returnValue(DLOCK_SUCCESS));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->query_urma_device(nullptr, eid);
    EXPECT_EQ(ret, DLOCK_SUCCESS);
}

TEST_F(test_urma_ctx, test_query_urma_device_2_by_eid_failed)
{
    MOCKER_CPP(&urma_ctx::check_urma_device_state_by_eid, dlock_status_t (*)(urma_ctx *, const dlock_eid_t))
        .stubs().will(returnValue(DLOCK_FAIL));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->query_urma_device(nullptr, eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_query_urma_device_3_by_dev_name_succ)
{
    MOCKER_CPP(&urma_ctx::check_urma_device_state, dlock_status_t (*)(urma_ctx *, char *))
        .stubs().will(returnValue(DLOCK_SUCCESS));

    char *dev_name = strdup("mlx5_1");
    const dlock_eid_t eid = {0};
    dlock_status_t ret = m_urma_ctx->query_urma_device(dev_name, eid);
    EXPECT_EQ(ret, DLOCK_SUCCESS);
    free(dev_name);
}

TEST_F(test_urma_ctx, test_query_urma_device_4_by_dev_name_failed)
{
    MOCKER_CPP(&urma_ctx::check_urma_device_state, dlock_status_t (*)(urma_ctx *, char *))
        .stubs().will(returnValue(DLOCK_FAIL));

    char *dev_name = strdup("mlx5_1");
    const dlock_eid_t eid = {0};
    dlock_status_t ret = m_urma_ctx->query_urma_device(dev_name, eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
    free(dev_name);
}

TEST_F(test_urma_ctx, test_query_urma_device_5_query_active_urma_device_succ_1)
{
    const dlock_eid_t eid = {0};
    dlock_status_t ret = m_urma_ctx->query_urma_device(nullptr, eid);
    EXPECT_EQ(ret, DLOCK_SUCCESS);
}

TEST_F(test_urma_ctx, test_query_urma_device_6_urma_get_device_list_failed)
{
    MOCKER(urma_get_device_list).stubs().will(returnValue((urma_device_t **)nullptr));

    const dlock_eid_t eid = {0};
    dlock_status_t ret = m_urma_ctx->query_urma_device(nullptr, eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_query_urma_device_7_check_urma_device_state_failed)
{
    MOCKER_CPP(&urma_ctx::check_urma_device_state, dlock_status_t (*)(urma_ctx *, char *))
        .stubs().will(returnValue(DLOCK_FAIL));

    const dlock_eid_t eid = {0};
    dlock_status_t ret = m_urma_ctx->query_urma_device(nullptr, eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_check_urma_device_state_by_eid_1_urma_get_device_by_eid_failed)
{
    MOCKER(urma_get_device_by_eid).stubs().will(returnValue((urma_device_t *)nullptr));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->check_urma_device_state_by_eid(eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_check_urma_device_state_by_eid_2_get_urma_eid_index_failed)
{
    urma_device_t temp_dev;
    MOCKER(urma_get_device_by_eid).stubs().will(returnValue(&temp_dev));
    MOCKER_CPP(&urma_ctx::get_urma_eid_index,
        dlock_status_t (*)(urma_ctx *, urma_device_t *, urma_eid_t *, uint32_t &))
        .stubs().will(returnValue(DLOCK_FAIL));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->check_urma_device_state_by_eid(eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

static dlock_status_t get_urma_eid_index_stub(urma_ctx *ctx, urma_device_t *urma_dev,
    urma_eid_t *eid, uint32_t &eid_index)
{
    eid_index = 0;
    return DLOCK_SUCCESS;
}

static urma_status_t urma_query_device_stub(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    dev_attr->port_cnt = 1;
    dev_attr->port_attr[0].state = URMA_PORT_ACTIVE;
    return URMA_SUCCESS;
}

TEST_F(test_urma_ctx, test_check_urma_device_state_by_eid_3_urma_query_device_succ)
{
    std::string dev_name = "mlx5_1";
    urma_device_t temp_dev;
    (void)memset(&temp_dev, 0, sizeof(urma_device_t));
    snprintf(temp_dev.name, URMA_MAX_NAME, "%s", dev_name.c_str());

    MOCKER(urma_get_device_by_eid).stubs().will(returnValue(&temp_dev));
    MOCKER_CPP(&urma_ctx::get_urma_eid_index, dlock_status_t (*)(urma_ctx *, urma_device_t *,
        urma_eid_t *, uint32_t &)).stubs().will(invoke(get_urma_eid_index_stub));
    MOCKER(urma_query_device).stubs().will(invoke(urma_query_device_stub));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->check_urma_device_state_by_eid(eid);
    EXPECT_EQ(ret, DLOCK_SUCCESS);
    EXPECT_EQ(m_urma_ctx->m_dev_name.compare(dev_name), 0);
    EXPECT_EQ(m_urma_ctx->m_eid_index, 0u);
}

TEST_F(test_urma_ctx, test_check_urma_device_state_by_eid_4_urma_query_device_failed)
{
    urma_device_t temp_dev;
    MOCKER(urma_get_device_by_eid).stubs().will(returnValue(&temp_dev));
    MOCKER_CPP(&urma_ctx::get_urma_eid_index, dlock_status_t (*)(urma_ctx *, urma_device_t *,
        urma_eid_t *, uint32_t &)).stubs().will(invoke(get_urma_eid_index_stub));
    MOCKER(urma_query_device).stubs().will(returnValue(URMA_FAIL));

    std::string dev_ip_str = "192.168.0.81";
    const dlock_eid_t eid = {0};
    str_to_urma_eid(dev_ip_str.c_str(), const_cast<dlock_eid_t *>(&eid));
    dlock_status_t ret = m_urma_ctx->check_urma_device_state_by_eid(eid);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_check_urma_device_state_1_get_urma_eid_index_failed)
{
    urma_device_t temp_dev;
    temp_dev.type = URMA_TRANSPORT_UB;

    MOCKER(urma_get_device_by_name).stubs().will(returnValue(&temp_dev));
    MOCKER_CPP(&urma_ctx::get_urma_eid_index,
        dlock_status_t (*)(urma_ctx *, urma_device_t *, urma_eid_t *, uint32_t &))
        .stubs().will(returnValue(DLOCK_FAIL));

    char *dev_name = strdup("mlx5_1");
    dlock_status_t ret = m_urma_ctx->check_urma_device_state(dev_name);
    EXPECT_EQ(ret, DLOCK_FAIL);

    free(dev_name);
}

TEST_F(test_urma_ctx, test_check_urma_device_state_2_urma_query_device_failed)
{
    urma_device_t temp_dev;
    temp_dev.type = URMA_TRANSPORT_UB;

    MOCKER(urma_get_device_by_name).stubs().will(returnValue(&temp_dev));
    MOCKER_CPP(&urma_ctx::get_urma_eid_index, dlock_status_t (*)(urma_ctx *, urma_device_t *,
        urma_eid_t *, uint32_t &)).stubs().will(invoke(get_urma_eid_index_stub));
    MOCKER(urma_query_device).stubs().will(returnValue(URMA_FAIL));

    char *dev_name = strdup("mlx5_1");
    dlock_status_t ret = m_urma_ctx->check_urma_device_state(dev_name);
    EXPECT_EQ(ret, DLOCK_FAIL);

    free(dev_name);
}

TEST_F(test_urma_ctx, test_get_urma_eid_index_1_urma_get_eid_list_failed)
{
    MOCKER(urma_get_eid_list).stubs().will(returnValue((urma_eid_info_t *)nullptr));

    urma_device_t temp_dev;
    urma_eid_t temp_eid;
    uint32_t temp_eid_index;
    dlock_status_t ret = m_urma_ctx->get_urma_eid_index(&temp_dev, &temp_eid, temp_eid_index);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

static urma_eid_info_t *urma_get_eid_list_stub(urma_device_t *dev, uint32_t *cnt)
{
    urma_eid_info_t *eid_list = (urma_eid_info_t *)malloc(sizeof(urma_eid_info_t));
    if (eid_list == nullptr) {
        return nullptr;
    }

    eid_list->eid.raw[0] = 1;
    *cnt = 1;
    return eid_list;
}

TEST_F(test_urma_ctx, test_get_urma_eid_index_2_urma_get_eid_list_failed)
{
    MOCKER(urma_get_eid_list).stubs().will(invoke(urma_get_eid_list_stub));

    urma_device_t temp_dev;
    uint32_t temp_eid_index;
    urma_eid_t temp_eid;
    temp_eid.raw[0] = 2;
    dlock_status_t ret = m_urma_ctx->get_urma_eid_index(&temp_dev, &temp_eid, temp_eid_index);
    EXPECT_EQ(ret, DLOCK_FAIL);
}

TEST_F(test_urma_ctx, test_create_jfce_1_urma_create_jfce_failed)
{
    MOCKER(urma_create_jfce).stubs().will(returnValue((urma_jfce_t *)nullptr));

    urma_jfce_t *temp_jfce = m_urma_ctx->m_jfce;
    m_urma_ctx->m_jfce = nullptr;

    dlock_status_t ret = m_urma_ctx->create_jfce();
    EXPECT_EQ(ret, DLOCK_FAIL);

    m_urma_ctx->m_jfce = temp_jfce;
}

TEST_F(test_urma_ctx, test_create_jfc_1_urma_create_jfc_failed)
{
    MOCKER(urma_create_jfc).stubs().will(returnValue((urma_jfc_t *)nullptr));

    urma_jfc_t *temp_jfc = m_urma_ctx->m_jfc;
    m_urma_ctx->m_jfc = nullptr;

    dlock_status_t ret = m_urma_ctx->create_jfc(8);
    EXPECT_EQ(ret, DLOCK_FAIL);

    m_urma_ctx->m_jfc = temp_jfc;
}

TEST_F(test_urma_ctx, test_register_seg_1_urma_register_seg_failed)
{
    MOCKER(urma_register_seg).stubs().will(returnValue((urma_target_seg_t *)nullptr));

    void *temp_va = m_urma_ctx->m_va;
    urma_target_seg_t *temp_local_tseg = m_urma_ctx->m_local_tseg;
    m_urma_ctx->m_va = nullptr;
    m_urma_ctx->m_local_tseg = nullptr;

    dlock_status_t ret = m_urma_ctx->register_seg(8);
    EXPECT_EQ(ret, DLOCK_FAIL);

    m_urma_ctx->m_local_tseg = temp_local_tseg;
    m_urma_ctx->m_va = temp_va;
}

TEST_F(test_urma_ctx, test_unregister_local_tseg_1_urma_unregister_seg_failed)
{
    MOCKER(urma_unregister_seg).stubs().will(returnValue(URMA_FAIL));

    urma_target_seg_t *temp_local_tseg = m_urma_ctx->m_local_tseg;
    m_urma_ctx->unregister_local_tseg();
    EXPECT_EQ(m_urma_ctx->m_local_tseg, nullptr);

    m_urma_ctx->m_local_tseg = temp_local_tseg;
}

TEST_F(test_urma_ctx, test_delete_jfc_1_urma_delete_jfc_failed)
{
    MOCKER(urma_delete_jfc).stubs().will(returnValue(URMA_FAIL));

    urma_jfc_t *temp_jfc = m_urma_ctx->m_jfc;
    m_urma_ctx->delete_jfc();
    EXPECT_EQ(m_urma_ctx->m_jfc, nullptr);

    m_urma_ctx->m_jfc = temp_jfc;
}

TEST_F(test_urma_ctx, test_delete_jfce_1_urma_delete_jfce_failed)
{
    MOCKER(urma_delete_jfce).stubs().will(returnValue(URMA_FAIL));

    urma_jfce_t *temp_jfce = m_urma_ctx->m_jfce;
    m_urma_ctx->delete_jfce();
    EXPECT_EQ(m_urma_ctx->m_jfce, nullptr);

    m_urma_ctx->m_jfce = temp_jfce;
}

TEST_F(test_urma_ctx, test_delete_urma_context_1_urma_delete_context_failed)
{
    MOCKER(urma_delete_context).stubs().will(returnValue(URMA_FAIL));

    urma_context_t *temp_urma_ctx = m_urma_ctx->m_urma_ctx;
    m_urma_ctx->delete_urma_context();
    EXPECT_EQ(m_urma_ctx->m_urma_ctx, nullptr);

    m_urma_ctx->m_urma_ctx = temp_urma_ctx;
}

TEST_F(test_urma_ctx, test_get_memory_1_buf_head_nullptr)
{
    struct urma_buf *temp_buf_head = m_urma_ctx->m_p_buf_head;
    m_urma_ctx->m_p_buf_head = nullptr;

    struct urma_buf *buf = m_urma_ctx->get_memory();
    EXPECT_EQ(buf, nullptr);

    m_urma_ctx->m_p_buf_head = temp_buf_head;
}

TEST_F(test_urma_ctx, test_release_memory_1_param_buf_nullptr)
{
    struct urma_buf *temp_buf_head = m_urma_ctx->m_p_buf_head;

    m_urma_ctx->release_memory(nullptr);
    EXPECT_EQ(m_urma_ctx->m_p_buf_head, temp_buf_head);
}

TEST_F(test_urma_ctx, test_new_jfc_1_urma_create_jfc_failed)
{
    MOCKER(urma_create_jfc).stubs().will(returnValue((urma_jfc_t *)nullptr));

    urma_jfc_t *jfc = m_urma_ctx->new_jfc(8);
    EXPECT_EQ(jfc, nullptr);
}

TEST_F(test_urma_ctx, test_uninit_urma_ctx_1_urma_uninit_failed)
{
    MOCKER(urma_uninit).stubs().will(returnValue(URMA_FAIL));

    dlock_status_t ret = m_urma_ctx->uninit_urma_ctx();
    EXPECT_EQ(ret, DLOCK_FAIL);
}
