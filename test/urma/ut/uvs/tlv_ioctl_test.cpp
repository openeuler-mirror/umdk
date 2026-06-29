/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UVS TLV and ioctl unit tests.
 */

#include "uvs_fixture.h"

using namespace urma_test_uvs;

TEST_F(UrmaUvsTest, TlvWrappersBuildExpectedAttrs)
{
    tpsa_ioctl_ctx_t ctx = {};
    uvs_set_topo_t setTopo = {};
    uvs_get_topo_t getTopo = {};
    uvs_cmd_main_ue_eid_entry_t entry = {};
    uvs_cmd_main_ue_eid_delete_t del = {};
    uvs_cmd_main_ue_eid_lookup_t lookup = {};
    uvs_cmd_main_ue_eid_batch_t batch = {};
    uvs_cmd_host_eid_batch_t hostBatch = {};

    InitIoctlCtx(&ctx);
    EXPECT_EQ(0, uvs_ioctl_set_topo(&ctx, &setTopo));
    EXPECT_EQ(UVS_CMD_SET_TOPO, g_uvsIoctl.command);
    ExpectAttrTypes({SET_TOPO_IN_TOPO_INFO, SET_TOPO_IN_TOPO_NUM});

    EXPECT_EQ(0, uvs_ioctl_get_topo(&ctx, &getTopo));
    EXPECT_EQ(UVS_CMD_GET_TOPO, g_uvsIoctl.command);
    ExpectAttrTypes({GET_TOPO_OUT_TOPO_MAP});

    EXPECT_EQ(0, uvs_ioctl_insert_main_ue_eid(&ctx, &entry));
    EXPECT_EQ(UVS_CMD_INSERT_MAIN_UE_EID, g_uvsIoctl.command);
    ExpectAttrTypes({INSERT_MAIN_UE_EID_IN_ENTRY_EID, INSERT_MAIN_UE_EID_IN_ENTRY_MAIN_UE_EID});

    EXPECT_EQ(0, uvs_ioctl_delete_main_ue_eid(&ctx, &del));
    EXPECT_EQ(UVS_CMD_DELETE_MAIN_UE_EID, g_uvsIoctl.command);
    ExpectAttrTypes({DELETE_MAIN_UE_EID_IN_EID});

    EXPECT_EQ(0, uvs_ioctl_lookup_main_ue_eid(&ctx, &lookup));
    EXPECT_EQ(UVS_CMD_LOOKUP_MAIN_UE_EID, g_uvsIoctl.command);
    ExpectAttrTypes({LOOKUP_MAIN_UE_EID_IN_EID, LOOKUP_MAIN_UE_EID_OUT_MAIN_UE_EID});

    EXPECT_EQ(1, uvs_ioctl_flush_main_ue_eid(&ctx));
    EXPECT_EQ(UVS_CMD_FLUSH_MAIN_UE_EID, g_uvsIoctl.command);
    ExpectAttrTypes({FLUSH_MAIN_UE_EID_OUT_STATUS});

    EXPECT_EQ(0, uvs_ioctl_insert_main_ue_eid_batch(&ctx, &batch));
    EXPECT_EQ(UVS_CMD_INSERT_MAIN_UE_EID_BATCH, g_uvsIoctl.command);
    ExpectAttrTypes({INSERT_MAIN_UE_EID_BATCH_IN_ENTRY_MAIN_UE_EID,
        INSERT_MAIN_UE_EID_BATCH_IN_ENTRY_EID_NUM, INSERT_MAIN_UE_EID_BATCH_IN_ENTRY_EIDS});

    EXPECT_EQ(0, uvs_ioctl_insert_host_eid_batch(&ctx, &hostBatch));
    EXPECT_EQ(UVS_CMD_INSERT_HOST_EID_BATCH, g_uvsIoctl.command);
    ExpectAttrTypes({INSERT_HOST_EID_BATCH_IN_ENTRY});
}

TEST_F(UrmaUvsTest, PathSetWrapperBuildsInAndOutAttrs)
{
    tpsa_ioctl_ctx_t ctx = {};
    uvs_cmd_get_path_set_t arg = {};

    InitIoctlCtx(&ctx);
    arg.in.src_bonding_eid = MakeEid(7);
    arg.in.dst_bonding_eid = MakeEid(8);
    arg.in.tp_type = UVS_CTP;
    arg.in.iodie_level = true;

    EXPECT_EQ(0, uvs_ioctl_get_path_set(&ctx, &arg));
    EXPECT_EQ(UVS_CMD_GET_PATH_SET, g_uvsIoctl.command);
    ExpectAttrTypes({GET_PATH_SET_IN_SRC_BONDING_EID, GET_PATH_SET_IN_DST_BONDING_EID,
        GET_PATH_SET_IN_TP_TYPE, GET_PATH_SET_IN_IODIE_LEVEL, GET_PATH_SET_OUT_PATH_SET_TOPO_TYPE,
        GET_PATH_SET_OUT_PATH_SET_SRC_NODE, GET_PATH_SET_OUT_PATH_SET_DST_NODE,
        GET_PATH_SET_OUT_PATH_SET_CHIP_COUNT, GET_PATH_SET_OUT_PATH_SET_DIE_COUNT,
        GET_PATH_SET_OUT_PATH_SET_PATH_COUNT, GET_PATH_SET_OUT_PATH_SET_PATHS});
}

TEST_F(UrmaUvsTest, IoctlFailureReturnsNegativeErrno)
{
    tpsa_ioctl_ctx_t ctx = {};
    uvs_get_topo_t getTopo = {};

    InitIoctlCtx(&ctx);
    g_uvsIoctl.succeed = false;
    g_uvsIoctl.errnoValue = ENODEV;
    EXPECT_EQ(-ENODEV, uvs_ioctl_get_topo(&ctx, &getTopo));
    EXPECT_EQ(1U, g_uvsIoctl.callCount);
}

TEST_F(UrmaUvsTest, UbaggAndUbcoreIoctlSuccessPathsUseMockedDevices)
{
    uvs_eid_t eid = MakeEid(31);
    uvs_eid_t mainEid = MakeEid(32);
    uvs_main_ue_eid_entry_t entry = { .eid = eid, .main_ue_eid = mainEid };
    uvs_main_ue_eid_batch_entry_t batch = {};
    uvs_host_eid_batch_entry_t hostBatch = {};
    char devName[UVS_MAX_DEV_NAME_LEN] = {};
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    auto *topo = static_cast<uvs_ubagg_topo_info_out_t *>(std::calloc(1, sizeof(uvs_ubagg_topo_info_out_t)));
    ASSERT_NE(nullptr, node);
    ASSERT_NE(nullptr, topo);

    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.topoNode.node_id = 0x51;
    batch.main_ue_eid = mainEid;
    batch.eid_num = 1;
    batch.eids[0] = eid;
    hostBatch.host_eid = MakeEid(33);
    hostBatch.eid_num = 1;
    hostBatch.eids[0] = MakeEid(34);

    EXPECT_EQ(0, uvs_ubagg_ioctl_create_agg_dev(&eid, "uvs_mock"));
    EXPECT_EQ(0, uvs_ubagg_ioctl_delete_agg_dev(&eid));
    EXPECT_EQ(0, uvs_ubagg_ioctl_get_dev_name_by_eid(&eid, devName, sizeof(devName)));
    EXPECT_EQ(0, uvs_ubagg_ioctl_get_topo_info(topo));
    EXPECT_EQ(1U, topo->node_num);
    EXPECT_EQ(0x51U, topo->topo_info[0].node_id);
    EXPECT_EQ(0, uvs_ubagg_ioctl_set_topo(node, 1));
    EXPECT_EQ(0, uvs_ubcore_ioctl_set_topo(node, 1));
    EXPECT_EQ(0, uvs_ubcore_ioctl_insert_main_ue_eid(&entry));
    EXPECT_EQ(0, uvs_ubcore_ioctl_delete_main_ue_eid(&eid));
    EXPECT_EQ(0, uvs_ubcore_ioctl_lookup_main_ue_eid(&eid, &mainEid));
    EXPECT_EQ(1, uvs_ubcore_ioctl_flush_main_ue_eid());
    EXPECT_EQ(0, uvs_ubcore_ioctl_insert_main_ue_eid_batch(&batch));
    EXPECT_EQ(0, uvs_ubcore_ioctl_insert_host_eid_batch(&hostBatch));

    std::free(topo);
    std::free(node);
}

TEST_F(UrmaUvsTest, UbaggAndUbcoreIoctlFailuresPropagate)
{
    uvs_eid_t eid = MakeEid(41);
    uvs_eid_t mainEid = MakeEid(42);
    uvs_main_ue_eid_entry_t entry = { .eid = eid, .main_ue_eid = mainEid };
    uvs_main_ue_eid_batch_entry_t batch = {};
    uvs_host_eid_batch_entry_t hostBatch = {};
    uvs_path_set_t pathSet = {};
    char devName[UVS_MAX_DEV_NAME_LEN] = {};
    auto *node = static_cast<urma_topo_node *>(std::calloc(1, sizeof(urma_topo_node)));
    auto *topo = static_cast<uvs_ubagg_topo_info_out_t *>(std::calloc(1, sizeof(uvs_ubagg_topo_info_out_t)));
    ASSERT_NE(nullptr, node);
    ASSERT_NE(nullptr, topo);

    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.succeed = false;
    g_uvsIoctl.errnoValue = ENODEV;
    batch.main_ue_eid = mainEid;
    batch.eid_num = 1;
    batch.eids[0] = eid;
    hostBatch.host_eid = MakeEid(43);
    hostBatch.eid_num = 1;
    hostBatch.eids[0] = MakeEid(44);

    EXPECT_EQ(-1, uvs_ubagg_ioctl_create_agg_dev(&eid, "uvs_fail"));
    EXPECT_EQ(-1, uvs_ubagg_ioctl_delete_agg_dev(&eid));
    EXPECT_EQ(-1, uvs_ubagg_ioctl_get_dev_name_by_eid(&eid, devName, sizeof(devName)));
    EXPECT_EQ(-1, uvs_ubagg_ioctl_get_topo_info(topo));
    EXPECT_EQ(-1, uvs_ubagg_ioctl_set_topo(node, 1));
    EXPECT_EQ(-1, uvs_ubcore_ioctl_set_topo(node, 1));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_insert_main_ue_eid(&entry));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_delete_main_ue_eid(&eid));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_lookup_main_ue_eid(&eid, &mainEid));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_flush_main_ue_eid());
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_insert_main_ue_eid_batch(&batch));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_insert_host_eid_batch(&hostBatch));
    EXPECT_EQ(-ENODEV, uvs_ubcore_ioctl_get_path_set(&eid, &mainEid, UVS_RTP, true, &pathSet));
    EXPECT_GT(g_uvsIoctl.callCount, 0U);

    std::free(topo);
    std::free(node);
}

TEST_F(UrmaUvsTest, UbaggIoctlRejectsInvalidTopoCount)
{
    auto *topo = static_cast<uvs_ubagg_topo_info_out_t *>(std::calloc(1, sizeof(uvs_ubagg_topo_info_out_t)));
    ASSERT_NE(nullptr, topo);

    EXPECT_EQ(-EINVAL, uvs_ubagg_ioctl_get_topo_info(nullptr));
    g_uvsIoctl.mockDeviceOpen = true;
    g_uvsIoctl.ubaggTopoNum = MAX_NODE_NUM + 1;
    EXPECT_EQ(-EINVAL, uvs_ubagg_ioctl_get_topo_info(topo));

    std::free(topo);
}
