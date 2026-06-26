/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding WR buffer, slide window and timewheel unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

TEST(UrmaBondTest, SlideWindowRejectsInvalidInit)
{
    bdp_slide_wnd_t wnd = {};

    EXPECT_EQ(-1, bdp_slide_wnd_init(nullptr, 8, 4, 0));
    EXPECT_EQ(-1, bdp_slide_wnd_init(&wnd, 4, 4, 0));
    bdp_slide_wnd_uninit(nullptr);
}

TEST(UrmaBondTest, SlideWindowAddsAndSlidesHead)
{
    bdp_slide_wnd_t wnd = {};

    ASSERT_EQ(0, bdp_slide_wnd_init(&wnd, 8, 4, 6));
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&wnd, 6));
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&wnd, 1));
    EXPECT_FALSE(bdp_slide_wnd_seq_in_window(&wnd, 2));

    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(7U, wnd.head);
    EXPECT_EQ(BDP_SLIDE_WND_OUT_OF_WND, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(BDP_SLIDE_WND_OUT_OF_WND, bdp_slide_wnd_add(&wnd, 3));

    bdp_slide_wnd_uninit(&wnd);
}

TEST(UrmaBondTest, SlideWindowRejectsNullAndOutOfRangeSequence)
{
    bdp_slide_wnd_t wnd = {};

    EXPECT_FALSE(bdp_slide_wnd_seq_in_window(nullptr, 0));
    EXPECT_FALSE(bdp_slide_wnd_has(nullptr, 0));
    EXPECT_EQ(-1, bdp_slide_wnd_add(nullptr, 0));

    ASSERT_EQ(0, bdp_slide_wnd_init(&wnd, 8, 4, 0));
    EXPECT_FALSE(bdp_slide_wnd_seq_in_window(&wnd, 8));
    EXPECT_FALSE(bdp_slide_wnd_has(&wnd, 8));
    EXPECT_EQ(BDP_SLIDE_WND_OUT_OF_WND, bdp_slide_wnd_add(&wnd, 8));
    bdp_slide_wnd_uninit(&wnd);
}

TEST(UrmaBondTest, WrBufferAllocGetRelease)
{
    wr_buf_t buf = {};
    jfs_wr_entry_t *jfsEntry = nullptr;
    jfr_wr_entry_t *jfrEntry = nullptr;

    EXPECT_EQ(-EINVAL, wr_buf_init(nullptr, 2));
    EXPECT_EQ(-EINVAL, wr_buf_init(&buf, 0));

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    jfsEntry = jfs_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, jfsEntry);
    EXPECT_EQ(1U, jfsEntry->wr_id);
    EXPECT_EQ(WR_BUF_ENTRY_JFS, jfsEntry->entry_type);
    EXPECT_TRUE(jfsEntry == jfs_wr_buf_get(&buf, jfsEntry->wr_id));

    jfrEntry = jfr_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, jfrEntry);
    EXPECT_EQ(2U, jfrEntry->wr_id);
    EXPECT_EQ(WR_BUF_ENTRY_JFR, jfrEntry->entry_type);
    EXPECT_TRUE(jfrEntry == jfr_wr_buf_get(&buf, jfrEntry->wr_id));

    EXPECT_EQ(nullptr, jfs_wr_buf_alloc(&buf));
    jfs_wr_buf_release(&buf, jfsEntry);
    EXPECT_EQ(nullptr, jfs_wr_buf_get(&buf, 1));
    EXPECT_NE(nullptr, jfs_wr_buf_alloc(&buf));

    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, WrBufferReleaseJfrAndReuse)
{
    wr_buf_t buf = {};
    jfr_wr_entry_t *entry = nullptr;

    ASSERT_EQ(0, wr_buf_init(&buf, 1));
    entry = jfr_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, entry);
    uint64_t wrId = entry->wr_id;
    EXPECT_EQ(entry, jfr_wr_buf_get(&buf, wrId));
    EXPECT_EQ(nullptr, jfr_wr_buf_get(&buf, wrId + buf.max_wr_num));
    EXPECT_EQ(nullptr, jfr_wr_buf_alloc(&buf));
    jfr_wr_buf_release(&buf, entry);
    EXPECT_EQ(nullptr, jfr_wr_buf_get(&buf, wrId));
    EXPECT_NE(nullptr, jfr_wr_buf_alloc(&buf));
    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, HeaderInlineHelpersCoverStablePureLogic)
{
    wr_buf_t buf = {};
    urma_seg_t seg = {};
    urma_seg_t converted = {};
    urma_seg_base_t base = {};
    urma_eid_t eid = {};
    urma_jfs_wr_t wr = {};
    urma_cr_t cr = {};

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    jfs_wr_entry_t *jfsEntry = jfs_wr_buf_alloc(&buf);
    jfr_wr_entry_t *jfrEntry = jfr_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, jfsEntry);
    ASSERT_NE(nullptr, jfrEntry);
    EXPECT_EQ(nullptr, jfs_wr_buf_get(&buf, 0));
    EXPECT_EQ(jfsEntry, jfs_wr_buf_get(&buf, jfsEntry->wr_id));
    EXPECT_EQ(jfrEntry, jfr_wr_buf_get(&buf, jfrEntry->wr_id));
    EXPECT_EQ(nullptr, jfr_wr_buf_get(&buf, jfrEntry->wr_id + buf.max_wr_num));
    wr_buf_uninit(&buf);

    seg.ubva.va = 0x1000;
    seg.ubva.uasid = 0x22;
    seg.len = 0x2000;
    seg.attr.bs.access = 0x5;
    seg.token_id = 0x33;
    bondp_seg_to_base(&seg, &base);
    EXPECT_EQ(seg.ubva.va, base.ubva.va);
    EXPECT_EQ(seg.ubva.uasid, base.ubva.uasid);
    EXPECT_EQ(seg.len, base.len);
    EXPECT_EQ(seg.token_id, base.token_id);
    bondp_seg_base_to_seg(&base, &converted);
    EXPECT_EQ(base.ubva.va, converted.ubva.va);
    EXPECT_EQ(base.ubva.uasid, converted.ubva.uasid);
    EXPECT_EQ(base.len, converted.len);
    EXPECT_FALSE(bondp_seg_has_user_info(&converted));
    EXPECT_TRUE(is_empty_eid(&eid));
    eid.in6.interface_id = 1;
    EXPECT_FALSE(is_empty_eid(&eid));

    wr.opcode = URMA_OPC_CAS;
    EXPECT_TRUE(is_atomic_wr(&wr));
    wr.opcode = URMA_OPC_WRITE;
    EXPECT_TRUE(is_rw_wr(&wr));
    wr.opcode = URMA_OPC_SEND;
    EXPECT_TRUE(is_send_wr(&wr));
    mark_jfs_wr_ctrl(&wr);

    cr.status = URMA_CR_LOC_LEN_ERR;
    EXPECT_TRUE(is_failover_cr(&cr));
    cr.status = URMA_CR_SUCCESS;
    cr.flag.bs.s_r = 1;
    cr.opcode = URMA_CR_OPC_SEND;
    EXPECT_TRUE(is_ctrl_cr(&cr));
    cr.flag.bs.s_r = 0;
    cr.opcode = URMA_CR_OPC_SEND_WITH_IMM;
    cr.user_ctx = BONDP_CTRL_USER_CTX_MASK;
    EXPECT_TRUE(is_ctrl_cr(&cr));
}

TEST(UrmaBondTest, WrBufferBatchAllocReleaseJfs)
{
    wr_buf_t buf = {};
    jfs_wr_entry_t *entries[3] = {};

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    EXPECT_EQ(0U, jfs_wr_buf_alloc_batch(&buf, entries, 0));
    EXPECT_EQ(2U, jfs_wr_buf_alloc_batch(&buf, entries, 3));
    ASSERT_NE(nullptr, entries[0]);
    ASSERT_NE(nullptr, entries[1]);
    EXPECT_EQ(1U, entries[0]->wr_id);
    EXPECT_EQ(2U, entries[1]->wr_id);
    EXPECT_EQ(0U, jfs_wr_buf_alloc_batch(&buf, entries, 1));

    jfs_wr_buf_release_batch(&buf, entries, 2);
    EXPECT_NE(nullptr, jfs_wr_buf_alloc(&buf));
    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, WrBufferBatchAllocReleaseJfrAndRejectOversizedRelease)
{
    wr_buf_t buf = {};
    jfr_wr_entry_t *jfrEntries[2] = {};
    jfs_wr_entry_t *jfsEntries[BONDP_BATCH_POST_MAX_NUM + 1] = {};

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    EXPECT_EQ(0U, jfr_wr_buf_alloc_batch(&buf, jfrEntries, 0));
    EXPECT_EQ(2U, jfr_wr_buf_alloc_batch(&buf, jfrEntries, 2));
    ASSERT_NE(nullptr, jfrEntries[0]);
    ASSERT_NE(nullptr, jfrEntries[1]);

    jfr_wr_buf_release_batch(&buf, jfrEntries, 0);
    jfs_wr_buf_release_batch(&buf, jfsEntries, BONDP_BATCH_POST_MAX_NUM + 1);
    jfr_wr_buf_release_batch(&buf, jfrEntries, BONDP_BATCH_POST_MAX_NUM + 1);

    jfr_wr_buf_release_batch(&buf, jfrEntries, 2);
    EXPECT_NE(nullptr, jfr_wr_buf_alloc(&buf));
    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, SlideWindowHasDuplicateAndWrapAround)
{
    bdp_slide_wnd_t wnd = {};

    ASSERT_EQ(0, bdp_slide_wnd_init(&wnd, 8, 4, 6));
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 7));
    EXPECT_TRUE(bdp_slide_wnd_has(&wnd, 7));
    EXPECT_EQ(BDP_SLIDE_WND_DUPLICATE, bdp_slide_wnd_add(&wnd, 7));
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(8U, bdp_slide_wnd_has(&wnd, 0) ? 8U : wnd.total_size);
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 0));
    bdp_slide_wnd_uninit(&wnd);
}

TEST(UrmaBondTest, TimewheelSchedulesCancelsAndAdvancesDeterministically)
{
    tw_cfg_t cfg = { .tick_ms = 10, .slot_num = 2 };
    uint32_t fired = 0;
    tw_task_id_t firstTask = 0;
    tw_task_id_t cancelTask = 0;
    tw_task_id_t roundTask = 0;

    EXPECT_EQ(nullptr, tw_create(nullptr));
    EXPECT_EQ(0U, tw_get_tick_ms(nullptr));
    EXPECT_EQ(-EINVAL, tw_schedule(nullptr, 0, TimewheelCountCallback, &fired, &firstTask));
    EXPECT_EQ(-EINVAL, tw_cancel(nullptr, firstTask));
    tw_advance(nullptr, 1);

    tw_t *tw = tw_create(&cfg);
    ASSERT_NE(nullptr, tw);
    EXPECT_EQ(10U, tw_get_tick_ms(tw));
    EXPECT_EQ(-EINVAL, tw_schedule(tw, 0, nullptr, &fired, &firstTask));
    EXPECT_EQ(-EINVAL, tw_schedule(tw, 0, TimewheelCountCallback, &fired, nullptr));
    EXPECT_EQ(-EINVAL, tw_cancel(tw, 0));
    EXPECT_EQ(-ENOENT, tw_cancel(tw, 0xdead));
    tw_advance(tw, 0);

    ASSERT_EQ(0, tw_schedule(tw, 0, TimewheelCountCallback, &fired, &firstTask));
    EXPECT_NE(0U, firstTask);
    tw_advance(tw, 1);
    EXPECT_EQ(1U, fired);
    EXPECT_EQ(-ENOENT, tw_cancel(tw, firstTask));

    ASSERT_EQ(0, tw_schedule(tw, 10, TimewheelCountCallback, &fired, &cancelTask));
    EXPECT_EQ(0, tw_cancel(tw, cancelTask));
    tw_advance(tw, 1);
    EXPECT_EQ(1U, fired);

    ASSERT_EQ(0, tw_schedule(tw, 30, TimewheelCountCallback, &fired, &roundTask));
    tw_advance(tw, 2);
    EXPECT_EQ(1U, fired);
    tw_advance(tw, 1);
    EXPECT_EQ(2U, fired);
    tw_destroy(tw);
    tw_destroy(nullptr);
}

TEST(UrmaBondTest, TimewheelUsesDefaultsAndDropsPendingTasksOnDestroy)
{
    tw_cfg_t defaultCfg = {};
    tw_cfg_t pendingCfg = { .tick_ms = 5, .slot_num = 2 };
    uint32_t fired = 0;
    tw_task_id_t pendingTask = 0;

    tw_t *defaultTw = tw_create(&defaultCfg);
    ASSERT_NE(nullptr, defaultTw);
    EXPECT_NE(0U, tw_get_tick_ms(defaultTw));
    tw_destroy(defaultTw);

    tw_t *pendingTw = tw_create(&pendingCfg);
    ASSERT_NE(nullptr, pendingTw);
    ASSERT_EQ(0, tw_schedule(pendingTw, 50, TimewheelCountCallback, &fired, &pendingTask));
    EXPECT_NE(0U, pendingTask);
    tw_destroy(pendingTw);
    EXPECT_EQ(0U, fired);
}
