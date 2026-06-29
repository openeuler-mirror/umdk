/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UVS unit test helpers.
 */

#ifndef TEST_URMA_UVS_UVS_FIXTURE_H
#define TEST_URMA_UVS_UVS_FIXTURE_H

#include <cerrno>
#include <cstdarg>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

using atomic_ulong = std::atomic_ulong;

extern "C" {
#include "tpsa_ioctl.h"
#include "tpsa_log.h"
#include "tpsa_topo_helper.h"
#include "uvs_api.h"
#include "uvs_cmd_tlv.h"
#include "uvs_private_api.h"
#include "uvs_ubagg_ioctl.h"
}

namespace urma_test_uvs {

struct UvsIoctlCapture {
    bool succeed = true;
    bool mockDeviceOpen = false;
    int errnoValue = EINVAL;
    uint32_t command = 0;
    uint32_t argsLen = 0;
    uint32_t callCount = 0;
    uint32_t ubaggTopoNum = 1;
    std::vector<uint8_t> attrTypes;
    std::vector<uint16_t> fieldSizes;
    urma_topo_node topoNode = {};
};

extern UvsIoctlCapture g_uvsIoctl;

inline void ResetUvSioctl()
{
    g_uvsIoctl = {};
    g_uvsIoctl.succeed = true;
    g_uvsIoctl.errnoValue = EINVAL;
}

inline uvs_eid_t MakeEid(uint8_t seed)
{
    uvs_eid_t eid = {};

    for (size_t i = 0; i < sizeof(eid.raw); i++) {
        eid.raw[i] = static_cast<uint8_t>(seed + i);
    }
    return eid;
}

inline void FillTopoUe(struct urma_topo_ue *ue, uint32_t entityId, uint32_t chipId, uint32_t dieId,
    uint8_t primarySeed, uint8_t portSeed, uint8_t cnaSeed)
{
    uvs_eid_t primary = MakeEid(primarySeed);
    uvs_eid_t port = MakeEid(portSeed);
    uvs_eid_t cna = MakeEid(cnaSeed);

    ue->entity_id = entityId;
    ue->chip_id = chipId;
    ue->die_id = dieId;
    std::memcpy(ue->primary_eid, primary.raw, sizeof(primary.raw));
    std::memcpy(ue->port_eid[0], port.raw, sizeof(port.raw));
    std::memcpy(ue->cna[0], cna.raw, sizeof(cna.raw));
}

inline void InitIoctlCtx(tpsa_ioctl_ctx_t *ctx)
{
    ctx->ubcore_fd = 7;
    ctx->id.store(0);
}

inline void CaptureTlvAttrs(const tpsa_cmd_hdr_t *hdr)
{
    auto *attrs = reinterpret_cast<uvs_cmd_attr_t *>(hdr->args_addr);
    uint32_t attrCount = hdr->args_len / sizeof(uvs_cmd_attr_t);

    g_uvsIoctl.command = hdr->command;
    g_uvsIoctl.argsLen = hdr->args_len;
    g_uvsIoctl.attrTypes.clear();
    g_uvsIoctl.fieldSizes.clear();
    for (uint32_t i = 0; i < attrCount; i++) {
        g_uvsIoctl.attrTypes.push_back(attrs[i].type);
        g_uvsIoctl.fieldSizes.push_back(attrs[i].field_size);
        if (attrs[i].type >= UVS_CMD_OUT_TYPE_INIT && attrs[i].data != 0 &&
            attrs[i].field_size <= sizeof(uint64_t)) {
            uint64_t value = 1;
            std::memcpy(reinterpret_cast<void *>(attrs[i].data), &value, attrs[i].field_size);
        }
    }
}

inline int HandleUbaggIoctl(uvs_ubagg_cmd_hdr *hdr)
{
    if (hdr->command != UVS_UBAGG_CMD_GET_TOPO_INFO) {
        return 0;
    }

    auto *arg = reinterpret_cast<uvs_ubagg_get_topo_info_arg *>(hdr->args_addr);
    auto *topo = static_cast<urma_topo_node *>(arg->out.topo);
    arg->out.topo_num = g_uvsIoctl.ubaggTopoNum;
    if (g_uvsIoctl.ubaggTopoNum <= MAX_NODE_NUM) {
        topo[0] = g_uvsIoctl.topoNode;
    }
    return 0;
}

inline void ExpectAttrTypes(std::initializer_list<uint8_t> expected)
{
    ASSERT_EQ(expected.size(), g_uvsIoctl.attrTypes.size());
    size_t index = 0;

    for (uint8_t type : expected) {
        EXPECT_EQ(type, g_uvsIoctl.attrTypes[index]);
        index++;
    }
}

class UrmaUvsTest : public testing::Test {
protected:
    void SetUp() override
    {
        ResetUvSioctl();
    }
};

} // namespace urma_test_uvs

#endif // TEST_URMA_UVS_UVS_FIXTURE_H
