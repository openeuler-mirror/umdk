/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * File Name     : test_dlock_server_mgr.cpp
 * Description   : dlock unit test cases for the functions of dlock_server_mgr class
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
#include "dlock_server_api.h"
#include "dlock_server_mgr.h"
#include "test_dlock_comm.h"

#ifndef MOCKER_CPP
#define MOCKER_CPP(api, TT) MOCKCPP_NS::mockAPI(#api, reinterpret_cast<TT>(api))
#endif

class test_server_start : public testing::Test {
protected:
    struct server_cfg m_cfg_s;

    void SetUp()
    {
        prepare_default_primary_server_cfg(m_cfg_s);
        dserver_lib_init(2);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        dserver_lib_deinit();
        free(m_cfg_s.primary.server_ip_str);
        free(m_cfg_s.primary.ctrl_cpuset);
        free(m_cfg_s.primary.cmd_cpuset);
    }
};

TEST_F(test_server_start, test_get_next_server_id_failed)
{
    MOCKER_CPP(&dlock_server_mgr::get_next_server_id, int (*)(dlock_server_mgr *))
        .stubs().will(returnValue(-1));

    int server_id;
    dlock_server_mgr& serverMgr = dlock_server_mgr::instance();
    int ret = serverMgr.server_start(m_cfg_s, server_id);
    EXPECT_EQ(ret, DLOCK_SERVER_NO_RESOURCE);
}

TEST_F(test_server_start, test_server_launch_failed)
{
    MOCKER_CPP(&dlock_server::launch, int (*)(dlock_server *))
        .stubs().will(returnValue(-1));

    int server_id;
    dlock_server_mgr& serverMgr = dlock_server_mgr::instance();
    int ret = serverMgr.server_start(m_cfg_s, server_id);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_server_start, test_server_type_error)
{
    int server_id;
    dlock_server_mgr& serverMgr = dlock_server_mgr::instance();
    m_cfg_s.type = SERVER_MAX;
    int ret = serverMgr.server_start(m_cfg_s, server_id);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_server_start, test_tp_mode_error)
{
    int server_id;
    m_cfg_s.tp_mode = (trans_mode_t)(3u);
    int ret = server_start(m_cfg_s, server_id);
    EXPECT_EQ(ret, -1);
}