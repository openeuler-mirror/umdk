/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UVS topology helper unit tests.
 */

#include "uvs_fixture.h"

using namespace urma_test_uvs;

TEST_F(UrmaUvsTest, TopoHelpersHandleStableBoundaryInput)
{
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, node);

    EXPECT_EQ(0, uvs_update_main_ue_eid_table_by_topo(nullptr, 0));
    FillTopoUe(&node->agg_devs[0].ues[0], 3, 1, 0, 11, 12, 13);
    EXPECT_EQ(-1, uvs_update_main_ue_eid_table_by_topo(node, 1));
    EXPECT_EQ(-EINVAL, uvs_update_host_eid_table_by_share_topo(nullptr, 1));
    EXPECT_EQ(-EINVAL, uvs_update_host_eid_table_by_share_topo(node, 0));
    EXPECT_EQ(-EINVAL, uvs_update_host_eid_table_by_share_topo(node, MAX_NODE_NUM + 1));

    std::free(node);
}

TEST_F(UrmaUvsTest, TopoHelpersUpdateMainUeBatchesWithMockedUbcore)
{
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, node);

    g_uvsIoctl.mockDeviceOpen = true;
    FillTopoUe(&node->agg_devs[0].ues[0], 20, 2, 0, 31, 32, 33);
    FillTopoUe(&node->agg_devs[0].ues[1], 18, 1, 0, 29, 34, 35);
    FillTopoUe(&node->agg_devs[1].ues[0], 23, 4, 0, 36, 37, 38);
    FillTopoUe(&node->agg_devs[1].ues[1], 20, 2, 0, 28, 39, 40);

    EXPECT_EQ(0, uvs_update_main_ue_eid_table_by_topo(node, 1));
    EXPECT_GT(g_uvsIoctl.callCount, 0U);

    std::free(node);
}

TEST_F(UrmaUvsTest, TopoHelpersPropagateMainUeBatchIoctlFailure)
{
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, node);

    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.succeed = false;
    g_uvsIoctl.errnoValue = ENODEV;
    FillTopoUe(&node->agg_devs[0].ues[0], 4, 1, 0, 51, 52, 53);

    EXPECT_EQ(-ENODEV, uvs_update_main_ue_eid_table_by_topo(node, 1));

    std::free(node);
}

TEST_F(UrmaUvsTest, TopoHelpersBuildHostEidMappingsWithMockedDevices)
{
    auto *shareNode = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, shareNode);

    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.topoNode.node_id = 0x31;
    g_uvsIoctl.topoNode.is_current = 1;
    FillTopoUe(&g_uvsIoctl.topoNode.agg_devs[0].ues[0], 7, 2, 1, 20, 22, 23);
    shareNode->node_id = 0x31;
    FillTopoUe(&shareNode->agg_devs[0].ues[0], 7, 2, 1, 21, 21, 24);

    EXPECT_EQ(0, uvs_update_host_eid_table_by_share_topo(shareNode, 1));
    EXPECT_GE(g_uvsIoctl.callCount, 2U);

    std::free(shareNode);
}

TEST_F(UrmaUvsTest, TopoHelpersRejectInvalidOrUnmatchedShareTopo)
{
    auto *shareNode = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    ASSERT_NE(nullptr, shareNode);

    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.ubaggTopoNum = 0;
    EXPECT_EQ(-EINVAL, uvs_update_host_eid_table_by_share_topo(shareNode, 1));

    ResetUvSioctl();
    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.topoNode.node_id = 0x90;
    shareNode->node_id = 0x91;
    EXPECT_EQ(-ENOENT, uvs_update_host_eid_table_by_share_topo(shareNode, 1));

    ResetUvSioctl();
    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.topoNode.node_id = 0x92;
    FillTopoUe(&g_uvsIoctl.topoNode.agg_devs[0].ues[0], 1, 1, 1, 61, 62, 63);
    shareNode->node_id = 0x92;
    FillTopoUe(&shareNode->agg_devs[0].ues[0], 2, 1, 1, 64, 65, 66);
    EXPECT_EQ(-ENOENT, uvs_update_host_eid_table_by_share_topo(shareNode, 1));

    std::free(shareNode);
}
