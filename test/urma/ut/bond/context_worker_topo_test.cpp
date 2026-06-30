/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding context, worker and topology unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

TEST(UrmaBondTest, HashTableCreateLookupRemoveAndDestroy)
{
    bondp_hash_table_t tbl = {};
    uint32_t key = 7;
    uint32_t missingKey = 8;
    auto *node = static_cast<HashTableNode *>(std::calloc(1, sizeof(HashTableNode)));
    ASSERT_NE(nullptr, node);
    node->key = key;
    node->payload = 0xabc;

    ASSERT_EQ(0, bondp_hash_table_create(&tbl, 4, HashTableNodeMatches, FreeHashTableNode, HashTableNodeHash));
    bondp_hash_table_add_with_hash(&tbl, &node->hmapNode, HashTableNodeHash(&key));
    EXPECT_EQ(&node->hmapNode, bondp_hash_table_lookup(&tbl, &key, HashTableNodeHash(&key)));
    EXPECT_EQ(&node->hmapNode, bondp_hash_table_lookup_without_lock(&tbl, &key, HashTableNodeHash(&key)));
    EXPECT_EQ(nullptr, bondp_hash_table_lookup(&tbl, &missingKey, HashTableNodeHash(&missingKey)));
    bondp_hash_table_remove(&tbl, &node->hmapNode);
    EXPECT_EQ(nullptr, bondp_hash_table_lookup_without_lock(&tbl, &key, HashTableNodeHash(&key)));
    FreeHashTableNode(&node->hmapNode);

    node = static_cast<HashTableNode *>(std::calloc(1, sizeof(HashTableNode)));
    ASSERT_NE(nullptr, node);
    node->key = key;
    bondp_hash_table_add_with_hash_without_lock(&tbl, &node->hmapNode, HashTableNodeHash(&key));
    bondp_hash_table_destroy(&tbl);

    bondp_hash_table_t firstMatchTbl = {};
    HashTableNode first = { .key = 1, .payload = 1 };
    ASSERT_EQ(0, bondp_hash_table_create(&firstMatchTbl, 4, nullptr, nullptr, HashTableNodeHash));
    bondp_hash_table_add_with_hash_without_lock(&firstMatchTbl, &first.hmapNode, 0x55);
    EXPECT_EQ(&first.hmapNode, bondp_hash_table_lookup(&firstMatchTbl, &missingKey, 0x55));
    EXPECT_EQ(&first.hmapNode, bondp_hash_table_lookup_without_lock(&firstMatchTbl, &missingKey, 0x55));
    bondp_hash_table_destroy(&firstMatchTbl);

    bondp_hash_table_t collisionTbl = {};
    HashTableNode match = { .key = key, .payload = 1 };
    HashTableNode miss = { .key = missingKey, .payload = 2 };
    ASSERT_EQ(0, bondp_hash_table_create(&collisionTbl, 4, HashTableNodeMatches, nullptr, HashTableNodeHash));
    bondp_hash_table_add_with_hash_without_lock(&collisionTbl, &match.hmapNode, 0x66);
    bondp_hash_table_add_with_hash_without_lock(&collisionTbl, &miss.hmapNode, 0x66);
    EXPECT_EQ(&match.hmapNode, bondp_hash_table_lookup(&collisionTbl, &key, 0x66));
    EXPECT_EQ(&match.hmapNode, bondp_hash_table_lookup_without_lock(&collisionTbl, &key, 0x66));
    bondp_hash_table_destroy(&collisionTbl);
}

TEST(UrmaBondTest, ContextTablesMapJettyIdsAndRemoteTokenIds)
{
    bondp_hash_table_t pJettyTable = {};
    bondp_hash_table_t tokenTable = {};
    bondp_comp_t comp = {};
    urma_jetty_id_t pJettyId = MakeJettyId(0x21);
    bondp_v2p_token_id_t tokenItem = {};
    bondp_v2p_token_id_t lookedUpToken = {};
    urma_eid_t remoteEid = MakeEid(0x31);

    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&pJettyTable, 4));
    EXPECT_EQ(BONDP_HASH_MAP_INVALID_PARAM_ERROR,
        bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x11, nullptr));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x11, &comp));
    EXPECT_EQ(&comp, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(nullptr, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JFS));
    EXPECT_EQ(BONDP_HASH_MAP_COLLIDE_ERROR,
        bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x12, &comp));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR, bdp_p_vjetty_id_table_del_without_lock(&pJettyTable, pJettyId, JFS));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_del_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(nullptr, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&pJettyTable));

    ASSERT_EQ(0, bdp_r_v2p_token_id_table_create(&tokenTable, 4));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR,
        bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    tokenItem.key.v_token_id = 0x44;
    tokenItem.key.v_remote_eid = remoteEid;
    tokenItem.v_handle = 0x55667788ULL;
    tokenItem.index = 3;
    tokenItem.connected[0][1] = true;
    tokenItem.peer_p_seg[1].len = 0x99;
    EXPECT_EQ(tokenItem.key.v_token_id, tokenTable.hash_f(&tokenItem.key));
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_add_lockless(&tokenTable, &tokenItem));
    EXPECT_EQ(0, bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    EXPECT_EQ(tokenItem.v_handle, lookedUpToken.v_handle);
    EXPECT_EQ(tokenItem.index, lookedUpToken.index);
    EXPECT_TRUE(lookedUpToken.connected[0][1]);
    EXPECT_EQ(0x99U, lookedUpToken.peer_p_seg[1].len);
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_add_lockless(&tokenTable, &tokenItem));
    EXPECT_EQ(-1, bdp_r_v2p_token_id_del_idx_lockless(&tokenTable, 9));
    EXPECT_EQ(0, bdp_r_v2p_token_id_del_idx_lockless(&tokenTable, tokenItem.index));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR,
        bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_destroy(&tokenTable));
}

TEST(UrmaBondTest, ConnectionTableGetOrCreateReusesExistingConnection)
{
    bondp_hash_table_t tbl = {};
    urma_jetty_id_t firstId = MakeJettyId(0x41);
    urma_jetty_id_t secondId = MakeJettyId(0x42);
    bondp_conn_t *firstConn = nullptr;
    bondp_conn_t *sameConn = nullptr;
    bondp_conn_t *secondConn = nullptr;

    ASSERT_EQ(0, bondp_conn_table_create(&tbl, 4));
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &firstId, &firstConn));
    ASSERT_NE(nullptr, firstConn);
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &firstId, &sameConn));
    EXPECT_EQ(firstConn, sameConn);
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &secondId, &secondConn));
    ASSERT_NE(nullptr, secondConn);
    EXPECT_NE(firstConn, secondConn);
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&firstConn->recv_wnd, 0));
    bondp_hash_table_destroy(&tbl);
}

TEST(UrmaBondTest, TopoInfoMapsPhysicalAndAggregateEids)
{
    bondp_topo_node_t topo = {};
    urma_eid_t aggEid = MakeEid(0x51);
    urma_eid_t primaryEid = MakeEid(0x52);
    urma_eid_t portEid = MakeEid(0x53);
    urma_eid_t missingEid = MakeEid(0x54);
    urma_eid_t output = {};

    EXPECT_EQ(nullptr, create_topo_map(nullptr, 1));
    EXPECT_EQ(nullptr, create_topo_map(&topo, 0));
    EXPECT_EQ(nullptr, create_topo_map(&topo, MAX_NODE_NUM + 1));
    EXPECT_EQ(nullptr, create_topo_map(&topo, 1));
    delete_topo_map(nullptr);

    topo.is_current = true;
    CopyEidToTopo(topo.agg_devs[0].agg_eid, aggEid);
    CopyEidToTopo(topo.agg_devs[0].ues[0].primary_eid, primaryEid);
    CopyEidToTopo(topo.agg_devs[0].ues[0].port_eid[0], portEid);

    topo_map_t *map = create_topo_map(&topo, 1);
    ASSERT_NE(nullptr, map);
    EXPECT_EQ(1U, map->node_num);

    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &aggEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &primaryEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &portEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(map, &missingEid, &output));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(nullptr, &portEid, &output));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(map, nullptr, &output));

    delete_topo_map(map);
}

TEST(UrmaBondTest, WorkerPublicApisScheduleCancelAndHandleFdEvents)
{
    BondWorkerGuard guard;
    WorkerCounter taskCounter = {};
    WorkerCounter fdCounter = {};
    bondp_worker_task_id_t taskId = 0;
    bondp_worker_task_id_t cancelId = 0;

    bondp_worker_destroy();
    EXPECT_EQ(-ENODEV, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, &taskId));
    EXPECT_EQ(-ENODEV, bondp_worker_cancel(1));
    EXPECT_EQ(-EINVAL, bondp_worker_add_fd(-1, CountReadableFd, &fdCounter));
    EXPECT_EQ(-EINVAL, bondp_worker_add_fd(0, nullptr, &fdCounter));
    EXPECT_EQ(-ENODEV, bondp_worker_del_fd(0));
    EXPECT_EQ(-EINVAL, bondp_worker_del_fd(-1));

    ASSERT_EQ(0, bondp_worker_create());
    EXPECT_EQ(-EEXIST, bondp_worker_create());
    EXPECT_EQ(-EINVAL, bondp_worker_schedule(0, nullptr, &taskCounter, &taskId));
    EXPECT_EQ(-EINVAL, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, nullptr));
    EXPECT_EQ(-ENOENT, bondp_worker_cancel(0xdead));

    ASSERT_EQ(0, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, &taskId));
    EXPECT_TRUE(WaitForWorkerCount(&taskCounter, 1));
    EXPECT_EQ(-ENOENT, bondp_worker_cancel(taskId));

    ASSERT_EQ(0, bondp_worker_schedule(1000, CountWorkerTask, &taskCounter, &cancelId));
    EXPECT_EQ(0, bondp_worker_cancel(cancelId));
    usleep(20000);
    EXPECT_EQ(1, taskCounter.count.load());

    fdCounter.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(fdCounter.fd, 0);
    ASSERT_EQ(0, bondp_worker_add_fd(fdCounter.fd, CountReadableFd, &fdCounter));
    EXPECT_EQ(-EEXIST, bondp_worker_add_fd(fdCounter.fd, CountReadableFd, &fdCounter));
    ASSERT_EQ(0, eventfd_write(fdCounter.fd, 1));
    EXPECT_TRUE(WaitForWorkerCount(&fdCounter, 1));
    EXPECT_EQ(0, bondp_worker_del_fd(fdCounter.fd));
    EXPECT_EQ(-ENOENT, bondp_worker_del_fd(fdCounter.fd));
    EXPECT_EQ(0, close(fdCounter.fd));
    fdCounter.fd = -1;

    bondp_worker_destroy();
    bondp_worker_destroy();
}

TEST(UrmaBondTest, WorkerCreatePropagatesEpollCreate1Failure)
{
    g_mockEpollCreate1Fail = true;
    EXPECT_EQ(-EMFILE, bondp_worker_create());
    g_mockEpollCreate1Fail = false;
    bondp_worker_destroy();
}

TEST(UrmaBondTest, WorkerCreatePropagatesEventfdFailure)
{
    g_mockEventfdFail = true;
    EXPECT_EQ(-EMFILE, bondp_worker_create());
    g_mockEventfdFail = false;
    bondp_worker_destroy();
}

TEST(UrmaBondTest, WorkerCreatePropagatesEpollCtlFailure)
{
    g_mockEpollCtlFail = true;
    EXPECT_EQ(-EMFILE, bondp_worker_create());
    g_mockEpollCtlFail = false;
    bondp_worker_destroy();
}

TEST(UrmaBondTest, WorkerCreatePropagatesPthreadCreateFailure)
{
    g_mockPthreadCreateFail = true;
    EXPECT_EQ(-EAGAIN, bondp_worker_create());
    g_mockPthreadCreateFail = false;
    bondp_worker_destroy();
}
