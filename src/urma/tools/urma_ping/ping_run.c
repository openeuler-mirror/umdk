/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping run implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "urma_api.h"
#include "urma_types.h"

#include "uvs_api.h"

#include "ping_log.h"
#include "ping_stat.h"

#include "ping_run.h"

const uint32_t PING_WK_JETTY_ID = 5;
const uint32_t PING_SEND_DEPTH = 1024;
const uint32_t PING_RECV_DEPTH = 1024;
const uint32_t EID_STRLEN = 128;
const uint32_t EID_MAX_VALUE = (1 << 30);

typedef struct ping_urma_resource {
    urma_context_t *ctx;
    void *buf;
    urma_target_seg_t *seg;
    urma_jfc_t *send_jfc;
    urma_jfc_t *recv_jfc;
    urma_jfr_t *jfr;
    urma_jetty_t *jetty;
    urma_target_jetty_t *tjetty;
} ping_urma_resource_t;

static void log_eid_verbose(uint8_t *eid)
{
    char print_str[EID_STRLEN];
    inet_ntop(AF_INET6, eid, print_str, EID_STRLEN);
    LOG_VERBOSE("%s\n", print_str);
}

static void primary_eid_to_main_primary_eid(urma_eid_t *primary_eid)
{
    int ret;
    urma_ping_ubcore_topo_map_t topo_map;

    ret = uvs_get_topo_info(&topo_map);
    if (ret != 0) {
        LOG_ERROR("Failed to get ubagg topo, ret:%d\n", ret);
        return;
    }

    bool find_entity_id = false;
    uint32_t target_entity_id;
    int target_node_id;
    
    for (int i = 0; i < (int)topo_map.node_num; i++) {
        for (int j = 0; j < DEV_NUM; j++) {
            for (int k = 0; k < IODIE_NUM; k++) {
                if (memcmp(topo_map.topo_infos[i].agg_devs[j].ues[k].primary_eid, primary_eid->raw, EID_LEN) == 0) {
                    target_entity_id = topo_map.topo_infos[i].agg_devs[j].ues[k].entity_id;
                    target_node_id = i;
                    find_entity_id = true;
                }
            }
        }
    }

    if (!find_entity_id) {
        LOG_ERROR("Failed to get entity id\n");
        return;
    }

    urma_eid_t empty_eid = {0};

    for (int j = 0; j < DEV_NUM; j++) {
        for (int k = 0; k < IODIE_NUM; k++) {
            if (topo_map.topo_infos[target_node_id].agg_devs[j].ues[k].entity_id == target_entity_id) {
                if (memcmp(topo_map.topo_infos[target_node_id].agg_devs[j].ues[k].primary_eid, empty_eid.raw, EID_LEN) == 0)
                    continue;
                if (memcmp(primary_eid->raw, topo_map.topo_infos[target_node_id].agg_devs[j].ues[k].primary_eid, EID_LEN) > 0) {
                    memcpy(primary_eid->raw, topo_map.topo_infos[target_node_id].agg_devs[j].ues[k].primary_eid, EID_LEN);
                }
            }
        }
    }
}

static bool is_primary_eid(urma_eid_t *eid, urma_ping_ubcore_topo_map_t *topo_map)
{
    for (int i = 0; i < (int)topo_map->node_num; i++) {
        for (int j = 0; j < DEV_NUM; j++) {
            for (int k = 0; k < IODIE_NUM; k++) {
                if (memcmp(eid->raw, topo_map->topo_infos[i].agg_devs[j].ues[k].primary_eid, EID_LEN) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

static uint32_t get_chip_id_by_primary_eid(urma_eid_t *eid, urma_ping_ubcore_topo_map_t *topo_map)
{
    for (int i = 0; i < (int)topo_map->node_num; i++) {
        for (int j = 0; j < DEV_NUM; j++) {
            for (int k = 0; k < IODIE_NUM; k++) {
                return topo_map->topo_infos[i].agg_devs[j].ues[k].chip_id;
            }
        }
    }

    LOG_ERROR("Failed to get chip id by primary eid.\n");
    return 0;
}

static bool get_primary_eid_and_chip_id_by_bonding(urma_eid_t *original_eid, urma_eid_t *primary_eid, uint32_t *chip_id)
{
    int ret;
    urma_ping_ubcore_topo_map_t topo_map;

    ret = uvs_get_topo_info(&topo_map);
    if (ret != 0) {
        LOG_ERROR("Failed to get ubagg topo, ret:%d\n", ret);
        return false;
    }

    if (is_primary_eid(original_eid, &topo_map)) {
        memcpy(primary_eid->raw, original_eid->raw, EID_LEN);
        (*chip_id) = get_chip_id_by_primary_eid(original_eid, &topo_map);
        LOG_VERBOSE("Input dest eid is primary eid: ");
        log_eid_verbose(primary_eid->raw);
        LOG_VERBOSE("Chip id = %u.\n", (*chip_id));
        return true;
    }

    LOG_VERBOSE("Dest Bonding eid: ");
    log_eid_verbose(original_eid->raw);

    for (int i = 0; i < (int)topo_map.node_num; i++) {
        for (int j = 0; j < DEV_NUM; j++) {
            if (memcmp(topo_map.topo_infos[i].agg_devs[j].agg_eid, original_eid->raw, EID_LEN) == 0) {
                memcpy(primary_eid->raw, topo_map.topo_infos[i].agg_devs[j].ues[0].primary_eid, EID_LEN);
                (*chip_id) = topo_map.topo_infos[i].agg_devs[j].ues[0].chip_id;
                LOG_VERBOSE("Successful find dest primary eid: ");
                log_eid_verbose(primary_eid->raw);
                LOG_VERBOSE("Chip id = %u.\n", (*chip_id));
                return true;
            }
        }
    }

    LOG_ERROR("Failed to find dest primary eid.\n");
    return false;
}

static bool get_source_eid_by_bonding_eid_and_chip_id(urma_eid_t *eid, uint32_t chip_id)
{
    int ret;
    urma_ping_ubcore_topo_map_t topo_map;

    ret = uvs_get_topo_info(&topo_map);
    if (ret != 0) {
        LOG_ERROR("Failed to get ubagg topo, ret:%d\n", ret);
        return false;
    }

    LOG_VERBOSE("Source Bonding eid: ");
    log_eid_verbose(eid->raw);

    for (int i = 0; i < (int)topo_map.node_num; i++) {
        for (int j = 0; j < DEV_NUM; j++) {
            if (memcmp(topo_map.topo_infos[i].agg_devs[j].agg_eid, eid->raw, EID_LEN) == 0) {
                for (int k = 0; k < IODIE_NUM; k++) {
                    if (topo_map.topo_infos[i].agg_devs[j].ues[k].chip_id == chip_id) {
                        memcpy(eid->raw, topo_map.topo_infos[i].agg_devs[j].ues[k].primary_eid, EID_LEN);
                        LOG_VERBOSE("Successful find source primary eid: ");
                        log_eid_verbose(eid->raw);
                        return true;
                    }
                }
            }
        }
    }

    LOG_ERROR("Failed to find source primary eid.\n");
    return false;
}

static bool if_device_has_eid(urma_device_t *dev)
{
    uint32_t eid_cnt = 0;
    urma_eid_info_t *eid_list = urma_get_eid_list(dev, &eid_cnt);
    if (eid_list != NULL) {
        urma_free_eid_list(eid_list);
        return true;
    }
    return false;
}

static urma_device_t *find_first_urma_device()
{
    int num_devices = 0;
    urma_device_t **devices = urma_get_device_list(&num_devices);
    urma_device_t *device_selected = NULL;

    for (int i = 0; i < num_devices; i++) {
        if (device_selected == NULL && devices[i]->type == URMA_TRANSPORT_UB &&
            strncmp(devices[i]->name, "bonding_dev_0", strlen("bonding_dev_0") + 1) == 0 &&
            if_device_has_eid(devices[i])) {
            device_selected = devices[i];
        }
    }

    for (int i = 0; i < num_devices; i++) {
        if (device_selected == NULL && devices[i]->type == URMA_TRANSPORT_UB &&
            strncmp(devices[i]->name, "bonding_dev", strlen("bonding_dev")) == 0 &&
            if_device_has_eid(devices[i])) {
            device_selected = devices[i];
        }
    }

    urma_free_device_list(devices);
    return device_selected;
}

static void urma_log_func(int level, char *message)
{
    LOG_VVERBOSE("%s", message);
}

static int init_urma_resource(ping_cfg_t *cfg, ping_urma_resource_t *res)
{
    int ret = 0;
    if ((ret = urma_register_log_func(urma_log_func)) != URMA_SUCCESS) {
        LOG_ERROR("Failed to register urma log func, ret:%d\n", ret);
        return ret;
    }

    urma_init_attr_t conf = {0};
    if ((ret = urma_init(&conf)) != URMA_SUCCESS) {
        LOG_ERROR("Failed to init urma, ret:%d\n", ret);
        return ret;
    }

    urma_device_t *dev = find_first_urma_device();
    if (dev == NULL) {
        LOG_ERROR("Failed to find first urma device.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }

    uint32_t eid_cnt = 1, chip_id = 0, source_eid_index = EID_MAX_VALUE;
    urma_eid_t source_eid, dest_eid;
    if (!get_primary_eid_and_chip_id_by_bonding(&(cfg->dest), &dest_eid, &chip_id)) {
        LOG_ERROR("Failed to dest primary eid.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }

    primary_eid_to_main_primary_eid(&dest_eid);

    LOG_VERBOSE("Successful find dest primary eid: ");
    log_eid_verbose(dest_eid.raw);

    urma_eid_info_t *eid_list = urma_get_eid_list(dev, &eid_cnt);
    if (eid_list == NULL) {
        LOG_ERROR("Failed to get eid list.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }
    if (eid_cnt != 1) {
        LOG_ERROR("More than one eid for bonding_dev.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }

    source_eid = eid_list[0].eid;
    if (!get_source_eid_by_bonding_eid_and_chip_id(&source_eid, chip_id)) {
        LOG_ERROR("Failed to source primary eid.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }

    urma_device_t *primary_dev = urma_get_device_by_eid(source_eid, URMA_TRANSPORT_UB);
    if (primary_dev == NULL) {
        LOG_ERROR("Failed to find primary urma device.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }
    LOG_VERBOSE("device = %s\n", primary_dev->name);

    eid_list = urma_get_eid_list(primary_dev, &eid_cnt);
    for (int i = 0; i < eid_cnt; i++) {
        if (memcmp(&source_eid, &(eid_list[i].eid), sizeof(urma_eid_t)) == 0) {
            source_eid_index = eid_list[i].eid_index;
            break;
        }
    }
    if (source_eid_index == EID_MAX_VALUE) {
        LOG_ERROR("Failed to find primary eid_index.\n");
        ret = -ENODEV;
        goto uninit_urma;
    }
    LOG_VERBOSE("Get primary eid_index = %d\n", (int)source_eid_index);

    urma_device_attr_t dev_attr = {0};
    if ((ret = urma_query_device(primary_dev, &dev_attr)) != URMA_SUCCESS) {
        LOG_ERROR("Failed to query urma device attr, ret:%d\n", ret);
        goto uninit_urma;
    }
    if (cfg->size > dev_attr.dev_cap.max_msg_size) {
        LOG_ERROR("Ping message size %u exceeds device max msg size %u.\n",
                  cfg->size, dev_attr.dev_cap.max_msg_size);
        ret = -EINVAL;
        goto uninit_urma;
    }

    res->ctx = urma_create_context(primary_dev, source_eid_index);
    if (res->ctx == NULL) {
        LOG_ERROR("Failed to create urma context.\n");
        ret = -EINVAL;
        goto uninit_urma;
    }

    res->buf = memalign(getpagesize(), cfg->size);
    if (res->buf == NULL) {
        LOG_ERROR("Failed to alloc memory for ping buffer.\n");
        ret = -ENOMEM;
        goto delete_context;
    }

    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)(uintptr_t)res->buf,
        .len = cfg->size,
        .flag.bs.access = URMA_ACCESS_LOCAL_ONLY,
    };
    res->seg = urma_register_seg(res->ctx, &seg_cfg);
    if (res->seg == NULL) {
        LOG_ERROR("Failed to register urma segment.\n");
        ret = -EINVAL;
        goto free_buf;
    }

    urma_jfc_cfg_t send_jfc_cfg = {
        .depth = PING_SEND_DEPTH,
    };
    res->send_jfc = urma_create_jfc(res->ctx, &send_jfc_cfg);
    if (res->send_jfc == NULL) {
        LOG_ERROR("Failed to create urma jfc for send.\n");
        ret = -EINVAL;
        goto unregister_seg;
    }

    urma_jfc_cfg_t recv_jfc_cfg = {
        .depth = PING_RECV_DEPTH,
    };
    res->recv_jfc = urma_create_jfc(res->ctx, &recv_jfc_cfg);
    if (res->recv_jfc == NULL) {
        LOG_ERROR("Failed to create urma jfc for recv.\n");
        ret = -EINVAL;
        goto delete_send_jfc;
    }

    urma_jfr_cfg_t jfr_cfg = {
        .depth = PING_RECV_DEPTH,
        .trans_mode = URMA_TM_RM,
        .max_sge = 1,
        .jfc = res->recv_jfc,
    };
    res->jfr = urma_create_jfr(res->ctx, &jfr_cfg);
    if (res->jfr == NULL) {
        LOG_ERROR("Failed to create urma jfr.\n");
        ret = -EINVAL;
        goto delete_recv_jfc;
    }

    urma_jetty_cfg_t jetty_cfg = {
        .flag.bs.share_jfr = 1,
        .jfs_cfg = {
            .depth = PING_SEND_DEPTH,
            .trans_mode = URMA_TM_RM,
            .priority = 6,
            .max_sge = 1,
            .rnr_retry = URMA_TYPICAL_RNR_RETRY,
            .err_timeout = URMA_TYPICAL_ERR_TIMEOUT,
            .jfc = res->send_jfc,
        },
        .shared.jfr = res->jfr,
    };
    res->jetty = urma_create_jetty(res->ctx, &jetty_cfg);
    if (res->jetty == NULL) {
        LOG_ERROR("Failed to create urma jetty.\n");
        ret = -EINVAL;
        goto delete_jfr;
    }

    urma_rjetty_t rjetty = {
        .jetty_id.eid = dest_eid,
        .jetty_id.id = PING_WK_JETTY_ID,
        .trans_mode = URMA_TM_RM,
        .type = URMA_JETTY,
        .tp_type = URMA_CTP,
    };
    urma_token_t token_value = {0};
    res->tjetty = urma_import_jetty(res->ctx, &rjetty, &token_value);
    if (res->tjetty == NULL) {
        LOG_ERROR("Failed to import target urma jetty.\n");
        ret = -EINVAL;
        goto delete_jetty;
    }

    return 0;

delete_jetty:
    urma_delete_jetty(res->jetty);
delete_jfr:
    urma_delete_jfr(res->jfr);
delete_recv_jfc:
    urma_delete_jfc(res->recv_jfc);
delete_send_jfc:
    urma_delete_jfc(res->send_jfc);
unregister_seg:
    urma_unregister_seg(res->seg);
free_buf:
    free(res->buf);
delete_context:
    urma_delete_context(res->ctx);
uninit_urma:
    urma_uninit();
    return ret;
}

static void uninit_urma_resource(ping_urma_resource_t *res)
{
    urma_unimport_jetty(res->tjetty);
    urma_delete_jetty(res->jetty);
    urma_delete_jfr(res->jfr);
    urma_unregister_seg(res->seg);
    free(res->buf);
    urma_delete_context(res->ctx);
    urma_uninit();
}

typedef struct ping_per_seq_info {
    uint32_t seq;
    double start_time;
    double end_time;
    double rtt;
} ping_per_seq_info_t;

static int fill_recv_wr(ping_cfg_t *cfg, ping_urma_resource_t *res)
{
    urma_sge_t sge = {
        .addr = (uint64_t)(uintptr_t)res->buf,
        .len = cfg->size,
        .tseg = res->seg,
    };

    urma_jfr_wr_t wr = {
        .src = {
            .sge = &sge,
            .num_sge = 1,
        },
    };
    urma_jfr_wr_t *bad_wr_placeholder = NULL;
    return urma_post_jetty_recv_wr(res->jetty, &wr, &bad_wr_placeholder);
}

static int send_ping_msg(ping_cfg_t *cfg, ping_urma_resource_t *res, ping_per_seq_info_t *seq_info)
{
    update_stat_on_send();
    seq_info->start_time = get_time_in_ms();

    urma_sge_t sge = {
        .addr = (uint64_t)(uintptr_t)res->buf,
        .len = cfg->size,
        .tseg = res->seg,
    };
    urma_jfs_wr_t wr = {
        .opcode = URMA_OPC_SEND_IMM,
        .flag.bs.complete_enable = 0,
        .tjetty = res->tjetty,
        .send = {
            .src = {
                .sge = &sge,
                .num_sge = 1,
            },
            .imm_data = seq_info->seq,
        },
    };
    urma_jfs_wr_t *badwr = NULL;
    int ret = urma_post_jetty_send_wr(res->jetty, &wr, &badwr);
    if (ret != 0) {
        LOG_ERROR("Failed to post jetty send wr, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

static int recv_ping_msg(ping_cfg_t *cfg, ping_urma_resource_t *res, ping_per_seq_info_t *seq_info)
{
    bool timed_out = false;
    urma_cr_t cr = {0};
    while (true) {
        int ret = urma_poll_jfc(res->recv_jfc, 1, &cr);

        seq_info->end_time = get_time_in_ms();
        seq_info->rtt = seq_info->end_time - seq_info->start_time;

        bool unmatched = (ret > 0 && cr.imm_data != seq_info->seq);
        bool received = (ret > 0 && cr.imm_data == seq_info->seq);
        timed_out = ((seq_info->rtt >= cfg->timeout * 1000) && (cfg->timeout != 0));

        if (unmatched) {
            LOG_VERBOSE("Unmatched reply received: expected seq=%d, got seq=%d\n",
                        seq_info->seq, cr.imm_data);
        }
        if (received || timed_out) {
            break;
        }
    }

    if (timed_out) {
        // timeout
        LOG_NORMAL("Request timeout for seq=%d\n", seq_info->seq);
    } else {
        int ret = fill_recv_wr(cfg, res);
        if (ret != 0) {
            LOG_ERROR("Failed to fill recv wr, ret:%d\n", ret);
            return ret;
        }

        if (cr.status == URMA_CR_SUCCESS) {
            // success
            update_stat_on_recv(seq_info->rtt);
            LOG_NORMAL("%d bytes from " EID_FMT ": seq=%d time=%.3f ms\n",
                       cfg->size, EID_ARGS(cfg->dest), seq_info->seq, seq_info->rtt);
        } else {
            // failure
            LOG_NORMAL("From " EID_FMT " seq=%d cr_status=%d\n",
                       EID_ARGS(cfg->dest), seq_info->seq, cr.status);
        }
    }

    return 0;
}

int start_ping(ping_cfg_t *cfg)
{
    verbose_set_level(cfg->verbose_level);

    int ret = 0;
    ping_urma_resource_t res = {0};

    if ((ret = init_urma_resource(cfg, &res)) != 0) {
        return ret;
    }

    if ((ret = fill_recv_wr(cfg, &res)) != 0) {
        LOG_ERROR("Failed to prepare recv wr, ret:%d\n", ret);
        return ret;
    }

    LOG_QUIET("URMA_PING " EID_FMT " %u bytes of data.\n", EID_ARGS(cfg->dest), cfg->size);
    LOG_VERBOSE("Count       : %u\n", cfg->count);
    LOG_VERBOSE("Interval(s) : %u\n", cfg->interval);
    LOG_VERBOSE("Size(bytes) : %u\n", cfg->size);
    LOG_VERBOSE("Deadline(s) : %u\n", cfg->deadline);
    LOG_VERBOSE("Timeout(s)  : %u\n", cfg->timeout);

    init_stat();

    double ping_start_time = get_time_in_ms();

    for (uint32_t i = 0; i < cfg->count; i++) {
        ping_per_seq_info_t seq_info = {
            .seq = i + 1,
        };

        ret = send_ping_msg(cfg, &res, &seq_info);
        if (ret != 0) {
            LOG_ERROR("Failed to send ping msg, ret:%d\n", ret);
            break;
        }

        ret = recv_ping_msg(cfg, &res, &seq_info);
        if (ret != 0) {
            LOG_ERROR("Failed to receive ping msg, ret:%d\n", ret);
            break;
        }

        if (i + 1 < cfg->count) {
            sleep(cfg->interval);
        }

        double time_elapsed = get_time_in_ms() - ping_start_time;

        LOG_VERBOSE("Time elapsed = %.3lfms\n", time_elapsed);
        if (cfg->deadline != 0 && time_elapsed > cfg->deadline * 1000.0) {
            LOG_ERROR("URMA_PING time limit exceeded.\n");
            break;
        }
    }

    if (false) {
        uninit_urma_resource(&res);
    }
    return ret;
}
