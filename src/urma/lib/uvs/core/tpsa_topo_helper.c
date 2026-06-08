/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: tpsa topo internal helpers
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tpsa_log.h"
#include "uvs_ubagg_ioctl.h"
#include "tpsa_topo_helper.h"

#define UVS_MAIN_UE_EID_INVALID_INDEX UINT32_MAX

typedef struct uvs_main_ue_eid_topo_range {
    uint32_t min_entity_id;
    uint32_t max_entity_id;
    uint32_t min_chip_id;
    uint32_t max_chip_id;
} uvs_main_ue_eid_topo_range_t;

typedef struct uvs_main_ue_eid_batch_table {
    uvs_main_ue_eid_batch_entry_t *batches;
    uint32_t *batch_index;
    uint32_t batch_num;
    uint32_t batch_max;
    uint32_t eid_num;
    uvs_main_ue_eid_topo_range_t range;
} uvs_main_ue_eid_batch_table_t;

typedef struct uvs_main_ue_eid_topo_count {
    uint32_t endpoint_num;
    uint32_t eid_num;
    uvs_main_ue_eid_topo_range_t range;
} uvs_main_ue_eid_topo_count_t;

static inline bool uvs_topo_eid_is_valid(const char *eid)
{
    const char empty_eid[EID_LEN] = {0};

    return eid != NULL && memcmp(eid, empty_eid, EID_LEN) != 0;
}

static bool uvs_main_ue_eid_mul_overflow(size_t count, size_t item_size)
{
    return count != 0 && item_size > SIZE_MAX / count;
}

static void uvs_update_main_ue_eid_topo_range(
    uvs_main_ue_eid_topo_count_t *count,
    const struct urma_topo_ue *endpoint)
{
    uvs_main_ue_eid_topo_range_t *range = &count->range;

    if (count->endpoint_num == 0) {
        range->min_entity_id = endpoint->entity_id;
        range->max_entity_id = endpoint->entity_id;
        range->min_chip_id = endpoint->chip_id;
        range->max_chip_id = endpoint->chip_id;
        return;
    }

    if (endpoint->entity_id < range->min_entity_id) {
        range->min_entity_id = endpoint->entity_id;
    }
    if (endpoint->entity_id > range->max_entity_id) {
        range->max_entity_id = endpoint->entity_id;
    }
    if (endpoint->chip_id < range->min_chip_id) {
        range->min_chip_id = endpoint->chip_id;
    }
    if (endpoint->chip_id > range->max_chip_id) {
        range->max_chip_id = endpoint->chip_id;
    }
}

static int uvs_count_main_ue_eid_topo_item(
    uvs_main_ue_eid_topo_count_t *count,
    const struct urma_topo_ue *endpoint)
{
    uint32_t port_idx;

    if (!uvs_topo_eid_is_valid(endpoint->primary_eid)) {
        return 0;
    }
    if (count->endpoint_num == UINT32_MAX || count->eid_num == UINT32_MAX) {
        return -EOVERFLOW;
    }

    uvs_update_main_ue_eid_topo_range(count, endpoint);
    count->endpoint_num++;
    count->eid_num++;
    for (port_idx = 0; port_idx < PORT_NUM; port_idx++) {
        if (!uvs_topo_eid_is_valid(endpoint->port_eid[port_idx])) {
            continue;
        }
        if (count->eid_num == UINT32_MAX) {
            return -EOVERFLOW;
        }
        count->eid_num++;
    }
    return 0;
}

static int uvs_main_ue_eid_batch_table_init(
    uvs_main_ue_eid_batch_table_t *table,
    const uvs_main_ue_eid_topo_count_t *count)
{
    uint64_t entity_span;
    uint64_t chip_span;
    size_t index_num;
    size_t batch_size;
    size_t index_size;

    if (table == NULL || count == NULL || count->endpoint_num == 0) {
        return -EINVAL;
    }

    entity_span = (uint64_t)count->range.max_entity_id -
                  count->range.min_entity_id + 1;
    chip_span = (uint64_t)count->range.max_chip_id -
                count->range.min_chip_id + 1;
    if (entity_span > UINT32_MAX || chip_span > UINT32_MAX ||
        uvs_main_ue_eid_mul_overflow((size_t)entity_span, (size_t)chip_span) ||
        uvs_main_ue_eid_mul_overflow((size_t)count->endpoint_num, sizeof(*table->batches))) {
        TPSA_LOG_ERR("main ue eid batch table size is too large.\n");
        return -EOVERFLOW;
    }

    index_num = (size_t)entity_span * (size_t)chip_span;
    if (uvs_main_ue_eid_mul_overflow(index_num, sizeof(*table->batch_index))) {
        TPSA_LOG_ERR("main ue eid batch index size is too large.\n");
        return -EOVERFLOW;
    }

    batch_size = (size_t)count->endpoint_num * sizeof(*table->batches);
    index_size = index_num * sizeof(*table->batch_index);

    (void)memset(table, 0, sizeof(*table));
    table->batches = malloc(batch_size);
    if (table->batches == NULL) {
        return -ENOMEM;
    }

    table->batch_index = malloc(index_size);
    if (table->batch_index == NULL) {
        free(table->batches);
        table->batches = NULL;
        return -ENOMEM;
    }
    (void)memset(table->batches, 0, batch_size);
    (void)memset(table->batch_index, UINT8_MAX, index_size);

    table->batch_max = count->endpoint_num;
    table->range = count->range;
    return 0;
}

static void uvs_main_ue_eid_batch_table_uninit(
    uvs_main_ue_eid_batch_table_t *table)
{
    if (table == NULL) {
        return;
    }

    free(table->batch_index);
    free(table->batches);
    (void)memset(table, 0, sizeof(*table));
}

static uint32_t *uvs_main_ue_eid_batch_index(
    uvs_main_ue_eid_batch_table_t *table, uint32_t entity_id,
    uint32_t chip_id)
{
    const uvs_main_ue_eid_topo_range_t *range;
    uint32_t chip_span;
    size_t index;

    if (table == NULL || table->batch_index == NULL ||
        entity_id < table->range.min_entity_id ||
        chip_id < table->range.min_chip_id) {
        return NULL;
    }

    range = &table->range;
    if (entity_id > range->max_entity_id || chip_id > range->max_chip_id) {
        return NULL;
    }

    chip_span = range->max_chip_id - range->min_chip_id + 1;
    index = (size_t)(entity_id - range->min_entity_id) * chip_span +
            (chip_id - range->min_chip_id);
    return &table->batch_index[index];
}

static int uvs_get_main_ue_eid_batch(uvs_main_ue_eid_batch_table_t *table,
    const struct urma_topo_ue *endpoint,
    uvs_main_ue_eid_batch_entry_t **out_batch)
{
    uvs_main_ue_eid_batch_entry_t *batch;
    uint32_t *batch_idx;

    if (out_batch == NULL) {
        return -EINVAL;
    }
    *out_batch = NULL;

    batch_idx = uvs_main_ue_eid_batch_index(table, endpoint->entity_id,
                                            endpoint->chip_id);
    if (table == NULL || table->batches == NULL || batch_idx == NULL) {
        return -ENOSPC;
    }
    if (*batch_idx != UVS_MAIN_UE_EID_INVALID_INDEX) {
        if (*batch_idx >= table->batch_num) {
            return -EINVAL;
        }
        batch = &table->batches[*batch_idx];
        if (memcmp(batch->main_ue_eid.raw, endpoint->primary_eid,
                   EID_LEN) > 0) {
            (void)memcpy(batch->main_ue_eid.raw,
                         endpoint->primary_eid, EID_LEN);
        }
        *out_batch = batch;
        return 0;
    }

    if (table->batch_num >= table->batch_max) {
        return -ENOSPC;
    }

    batch = &table->batches[table->batch_num];
    batch->eid_num = 0;
    (void)memcpy(batch->main_ue_eid.raw, endpoint->primary_eid,
                 EID_LEN);
    *batch_idx = table->batch_num;
    table->batch_num++;
    *out_batch = batch;
    return 0;
}

static int uvs_append_main_ue_eid_eid(uvs_main_ue_eid_batch_table_t *table,
    uvs_main_ue_eid_batch_entry_t *batch, const char *eid)
{
    if (table == NULL || batch == NULL || eid == NULL) {
        return -EINVAL;
    }
    if (batch->eid_num >= UVS_MAIN_UE_EID_BATCH_EID_MAX ||
        table->eid_num == UINT32_MAX) {
        return -ENOSPC;
    }

    (void)memcpy(batch->eids[batch->eid_num].raw, eid, EID_LEN);
    batch->eid_num++;
    table->eid_num++;
    return 0;
}

static int uvs_collect_main_ue_eid_endpoint(
    uvs_main_ue_eid_batch_table_t *table,
    const struct urma_topo_ue *endpoint)
{
    uvs_main_ue_eid_batch_entry_t *batch;
    uint32_t port_idx;
    int ret;

    if (!uvs_topo_eid_is_valid(endpoint->primary_eid)) {
        return 0;
    }

    ret = uvs_get_main_ue_eid_batch(table, endpoint, &batch);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_append_main_ue_eid_eid(table, batch, endpoint->primary_eid);
    if (ret != 0) {
        return ret;
    }
    for (port_idx = 0; port_idx < PORT_NUM; port_idx++) {
        if (!uvs_topo_eid_is_valid(endpoint->port_eid[port_idx])) {
            continue;
        }
        ret = uvs_append_main_ue_eid_eid(table, batch,
                                         endpoint->port_eid[port_idx]);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

static int uvs_count_main_ue_eid_node(const struct urma_topo_node *node,
    uvs_main_ue_eid_topo_count_t *count)
{
    uint32_t dev_idx;

    for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
        uint32_t iodie_idx;

        for (iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
            const struct urma_topo_ue *endpoint =
                &node->agg_devs[dev_idx].ues[iodie_idx];
            int ret = uvs_count_main_ue_eid_topo_item(count, endpoint);
            if (ret != 0) {
                return ret;
            }
        }
    }

    return 0;
}

static int uvs_collect_main_ue_eid_node(const struct urma_topo_node *node,
    uvs_main_ue_eid_batch_table_t *table)
{
    uint32_t dev_idx;

    for (dev_idx = 0; dev_idx < DEV_NUM; dev_idx++) {
        uint32_t iodie_idx;

        for (iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
            const struct urma_topo_ue *endpoint =
                &node->agg_devs[dev_idx].ues[iodie_idx];
            int ret = uvs_collect_main_ue_eid_endpoint(table, endpoint);
            if (ret != 0) {
                return ret;
            }
        }
    }

    return 0;
}

static int uvs_build_main_ue_eid_batches_from_node(
    const struct urma_topo_node *node,
    uvs_main_ue_eid_batch_table_t *table)
{
    uvs_main_ue_eid_topo_count_t count = {0};
    int ret;

    (void)memset(table, 0, sizeof(*table));
    ret = uvs_count_main_ue_eid_node(node, &count);
    if (ret != 0 || count.endpoint_num == 0) {
        return ret;
    }

    ret = uvs_main_ue_eid_batch_table_init(table, &count);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_collect_main_ue_eid_node(node, table);
    if (ret == 0 && table->eid_num != count.eid_num) {
        ret = -EFAULT;
    }
    if (ret != 0) {
        uvs_main_ue_eid_batch_table_uninit(table);
    }

    return ret;
}

static int uvs_insert_main_ue_eid_batches_inner(
    const uvs_main_ue_eid_batch_table_t *table)
{
    uint32_t batch_idx;
    int ret = 0;

    if (table == NULL) {
        TPSA_LOG_ERR("Invalid main ue eid batch table.\n");
        return -EINVAL;
    }
    if (table->batch_num == 0) {
        return 0;
    }

    for (batch_idx = 0; batch_idx < table->batch_num && ret == 0; batch_idx++) {
        ret = uvs_ubcore_ioctl_insert_main_ue_eid_batch(
            &table->batches[batch_idx]);
    }

    return ret;
}

int uvs_update_main_ue_eid_table_by_topo(const struct urma_topo_node *topo,
    uint32_t topo_num)
{
    uvs_main_ue_eid_batch_table_t table;
    uint32_t total_batch_num = 0;
    uint32_t total_eid_num = 0;
    uint32_t node_idx;
    int ret = 0;

    for (node_idx = 0; node_idx < topo_num; node_idx++) {
        ret = uvs_build_main_ue_eid_batches_from_node(&topo[node_idx],
                                                      &table);
        if (ret != 0) {
            return ret;
        }

        ret = uvs_insert_main_ue_eid_batches_inner(&table);
        if (ret != 0) {
            TPSA_LOG_ERR("failed to update main ue eid batch entries, ret = %d.\n",
                         ret);
            uvs_main_ue_eid_batch_table_uninit(&table);
            return ret;
        }
        if (total_batch_num > UINT32_MAX - table.batch_num ||
            total_eid_num > UINT32_MAX - table.eid_num) {
            uvs_main_ue_eid_batch_table_uninit(&table);
            return -EOVERFLOW;
        }
        total_batch_num += table.batch_num;
        total_eid_num += table.eid_num;
        uvs_main_ue_eid_batch_table_uninit(&table);
    }

    TPSA_LOG_INFO("successfully updated main ue eid entries by batch, "
                  "batch_num = %u, eid_num = %u.\n",
                  total_batch_num, total_eid_num);
    return 0;
}
