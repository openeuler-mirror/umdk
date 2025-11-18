/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: topo gtest source file
 * Author: Chen Wen
 * Create: 2025-07-14
 * Note:
 * History:
 */

#include "urma_api.h"
#include "bondp_gtest_basic.h"
#include "ub_hash.h"

extern "C" {
    #include "bondp_types.h"
    #include "topo_info.h"
    #include "bondp_hash_table.h"
    #include "bondp_context_table.h"
    int update_direct_dev_table_entry(topo_map_t *topo_map,
        struct topo_map_idx *local_map_idx, struct topo_map_idx* target_map_idx);
}

class BondpTopoInfoGTest : public BondpBasicGTest {
public:
protected:
};

TEST_F(BondpTopoInfoGTest, Bondp_DirectDevBashTableCreateTest){
    bondp_hash_table_t tbl;
    uint32_t size = 8;
    int ret = direct_dev_hash_table_create(&tbl, size);
    EXPECT_EQ(0, ret);
    bondp_hash_table_destroy(&tbl);
}