/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UVS public API unit tests.
 */

#include "uvs_fixture.h"

using namespace urma_test_uvs;

TEST_F(UrmaUvsTest, PublicApisRejectInvalidParameters)
{
    uvs_eid_t eid = MakeEid(1);
    uvs_eid_t outEid = {};
    char devName[UVS_MAX_DEV_NAME_LEN] = {};
    uvs_path_set_t pathSet = {};

    EXPECT_EQ(-EINVAL, uvs_create_agg_dev(nullptr, "uvs0"));
    EXPECT_EQ(-EINVAL, uvs_create_agg_dev(&eid, nullptr));
    EXPECT_EQ(-EINVAL, uvs_create_agg_dev(&eid, ""));
    EXPECT_EQ(-EINVAL, uvs_delete_agg_dev(nullptr));
    EXPECT_EQ(-EINVAL, uvs_get_device_name_by_eid(nullptr, devName, sizeof(devName)));
    EXPECT_EQ(-EINVAL, uvs_get_device_name_by_eid(&eid, nullptr, sizeof(devName)));
    EXPECT_EQ(-EINVAL, uvs_get_device_name_by_eid(&eid, devName, 0));
    EXPECT_EQ(-EINVAL, uvs_insert_main_ue_eid(nullptr));
    EXPECT_EQ(-EINVAL, uvs_insert_main_ue_eid_batch(nullptr));
    EXPECT_EQ(-EINVAL, uvs_delete_main_ue_eid(nullptr));
    EXPECT_EQ(-EINVAL, uvs_lookup_main_ue_eid(nullptr, &outEid));
    EXPECT_EQ(-EINVAL, uvs_lookup_main_ue_eid(&eid, nullptr));
    EXPECT_EQ(-EINVAL, uvs_set_topo_info(nullptr, sizeof(urma_topo_node), 1));
    EXPECT_EQ(-EINVAL, uvs_set_share_topo_info(nullptr, sizeof(urma_topo_node), 1));
    EXPECT_EQ(-EINVAL, uvs_get_topo_info(nullptr));
    EXPECT_EQ(-EINVAL, uvs_get_path_set(nullptr, &eid, UVS_RTP, false, &pathSet));
    EXPECT_EQ(-EINVAL, uvs_get_path_set(&eid, nullptr, UVS_RTP, false, &pathSet));
    EXPECT_EQ(-EINVAL, uvs_get_path_set(&eid, &eid, UVS_RTP, false, nullptr));
}

TEST_F(UrmaUvsTest, PublicApisPropagateMissingDeviceFailure)
{
    uvs_eid_t eid = MakeEid(2);
    uvs_eid_t outEid = {};
    uvs_main_ue_eid_entry_t entry = { .eid = MakeEid(3), .main_ue_eid = MakeEid(4) };
    uvs_main_ue_eid_batch_entry_t batch = {};
    char devName[UVS_MAX_DEV_NAME_LEN] = {};
    uvs_path_set_t pathSet = {};
    auto *topo = static_cast<urma_topo_map_t *>(std::calloc(1, sizeof(urma_topo_map_t)));
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    uvs_host_eid_batch_entry_t hostBatch = {};
    ASSERT_NE(nullptr, topo);
    ASSERT_NE(nullptr, node);

    batch.main_ue_eid = MakeEid(5);
    batch.eid_num = 1;
    batch.eids[0] = MakeEid(6);

    EXPECT_EQ(-1, uvs_create_agg_dev(&eid, "uvs_ut"));
    EXPECT_EQ(-1, uvs_delete_agg_dev(&eid));
    EXPECT_EQ(-1, uvs_get_device_name_by_eid(&eid, devName, sizeof(devName)));
    EXPECT_EQ(-1, uvs_set_topo_info(node, sizeof(*node), 1));
    EXPECT_EQ(-1, uvs_set_share_topo_info(node, sizeof(*node), 1));
    EXPECT_EQ(-1, uvs_get_topo_info(topo));
    EXPECT_EQ(-1, uvs_insert_main_ue_eid(&entry));
    EXPECT_EQ(-1, uvs_insert_main_ue_eid_batch(&batch));
    EXPECT_EQ(-1, uvs_delete_main_ue_eid(&eid));
    EXPECT_EQ(-1, uvs_lookup_main_ue_eid(&eid, &outEid));
    EXPECT_EQ(-1, uvs_flush_main_ue_eid());
    EXPECT_EQ(-1, uvs_get_path_set(&eid, &entry.main_ue_eid, UVS_RTP, false, &pathSet));
    EXPECT_EQ(-1, uvs_ubcore_ioctl_set_topo(node, 1));
    hostBatch.host_eid = MakeEid(9);
    hostBatch.eid_num = 1;
    hostBatch.eids[0] = MakeEid(10);
    EXPECT_EQ(-1, uvs_ubcore_ioctl_insert_host_eid_batch(&hostBatch));

    std::free(node);
    std::free(topo);
}

TEST_F(UrmaUvsTest, PublicApisSucceedWithMockedDevices)
{
    uvs_eid_t eid = MakeEid(71);
    uvs_eid_t dstEid = MakeEid(72);
    char devName[UVS_MAX_DEV_NAME_LEN] = {};
    uvs_path_set_t pathSet = {};
    auto *topo = static_cast<uvs_ubagg_topo_info_out_t *>(std::calloc(1, sizeof(uvs_ubagg_topo_info_out_t)));
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    auto *shareNode = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, topo);
    ASSERT_NE(nullptr, node);
    ASSERT_NE(nullptr, shareNode);

    g_uvsIoctl.mockDeviceOpen = true;
    FillTopoUe(&node->agg_devs[0].ues[0], 3, 2, 1, 73, 74, 75);

    EXPECT_EQ(0, uvs_create_agg_dev(&eid, "uvs_public"));
    EXPECT_EQ(0, uvs_delete_agg_dev(&eid));
    EXPECT_EQ(0, uvs_get_device_name_by_eid(&eid, devName, sizeof(devName)));
    EXPECT_EQ(0, uvs_set_topo_info(node, sizeof(*node), 1));
    EXPECT_EQ(0, uvs_get_topo_info(topo));
    EXPECT_EQ(0, uvs_get_path_set(&eid, &dstEid, UVS_RTP, false, &pathSet));

    g_uvsIoctl.topoNode.node_id = 0x81;
    FillTopoUe(&g_uvsIoctl.topoNode.agg_devs[0].ues[0], 9, 8, 7, 76, 77, 78);
    shareNode->node_id = 0x81;
    FillTopoUe(&shareNode->agg_devs[0].ues[0], 9, 8, 7, 79, 79, 80);
    EXPECT_EQ(0, uvs_set_share_topo_info(shareNode, sizeof(*shareNode), 1));

    std::free(shareNode);
    std::free(node);
    std::free(topo);
}

TEST_F(UrmaUvsTest, LogAndLockHelpersAreStable)
{
    EXPECT_EQ(-1, uvs_get_worker_idx());
    uvs_set_worker_idx(3);
    EXPECT_EQ(3, uvs_get_worker_idx());

    tpsa_log_init();
    tpsa_log_set_level(TPSA_VLOG_LEVEL_ERR);
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_ERR), tpsa_log_get_level());
    EXPECT_FALSE(tpsa_log_drop(TPSA_VLOG_LEVEL_ERR));
    EXPECT_TRUE(tpsa_log_drop(TPSA_VLOG_LEVEL_DEBUG));
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "debug", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_DEBUG), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "invalid", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_DEBUG), tpsa_log_get_level());
    ASSERT_EQ(0, unsetenv("UVS_LOG_LEVEL"));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_DEBUG), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "fatal", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_CRIT), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "error", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_ERR), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "warning", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_WARNING), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "info", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_INFO), tpsa_log_get_level());
    ASSERT_EQ(0, setenv("UVS_LOG_LEVEL", "012345678901234567890123456789012", 1));
    tpsa_getenv_log_level();
    EXPECT_EQ(static_cast<unsigned>(TPSA_VLOG_LEVEL_INFO), tpsa_log_get_level());
    ASSERT_EQ(0, unsetenv("UVS_LOG_LEVEL"));
    tpsa_log("UrmaUvsTest", __LINE__, TPSA_VLOG_LEVEL_INFO, "uvs log smoke %d", 1);
    tpsa_log_uninit();

    uvs_get_api_rdlock();
    put_uvs_lock();
    uvs_get_api_wrlock();
    put_uvs_lock();
}
