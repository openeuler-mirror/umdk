/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa ioctl implementation file
 * Author: Ji Lei
 * Create: 2023-7-3
 * Note:
 * History: 2023-7-3 tpsa ioctl implementation
 */
#include <stdint.h>
#include <errno.h>

#include "tpsa_log.h"
#include "tpsa_ioctl.h"

static int tpsa_ioctl_channel_init(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_channel_init_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CHANNEL_INIT;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_channel_init_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)strcpy(arg.in.userspace_in, cfg->cmd.channel_init);
    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    if (strlen(arg.out.kernel_out) == 0 || strcmp(arg.out.kernel_out, "Hello uvs!") != 0) {
        TPSA_LOG_ERR("ioctl res not right, res is %s", arg.out.kernel_out);
        return -1;
    }

    TPSA_LOG_INFO("chanel init success, res is %s", arg.out.kernel_out);
    return 0;
}

static int tpsa_ioctl_create_tpg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_create_tpg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CREATE_TPG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_create_tpg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.create_tpg.in.tpf;
    arg.in.tpg_cfg = cfg->cmd.create_tpg.in.tpg_cfg;
    arg.ta_data = cfg->cmd.create_tpg.ta_data;
    arg.udata = cfg->cmd.create_tpg.udata;
    arg.udrv_ext = cfg->cmd.create_tpg.udrv_ext;
    uint32_t i = 0;

    for (; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        arg.in.tp_cfg[i] = cfg->cmd.create_tpg.in.tp_cfg[i];
    }

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("create tpg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.create_tpg.out.tpgn = arg.out.tpgn;
    for (i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        cfg->cmd.create_tpg.out.tpn[i] = arg.out.tpn[i];
    }
    cfg->cmd.create_tpg.udata.out_len = arg.udata.out_len;
    cfg->cmd.create_tpg.udrv_ext.out_len = arg.udrv_ext.out_len;
    cfg->cmd.create_tpg.local_mtu = arg.local_mtu;

    TPSA_LOG_INFO("create tpg ioctl success");
    return 0;
}

static int tpsa_ioctl_create_vtp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_create_vtp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CREATE_VTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_create_vtp_t);
    hdr.args_addr = (uint64_t)&arg;

    uint32_t i = 0;

    for (; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        memcpy(&arg.in.rtr_attr[i], &cfg->cmd.create_vtp.in.rtr_attr[i], sizeof(tpsa_tp_attr_t));
        arg.in.rtr_mask[i] = cfg->cmd.create_vtp.in.rtr_mask[i];
    }
    arg.in.tpgn = cfg->cmd.create_vtp.in.tpgn;
    arg.in.tpf = cfg->cmd.create_vtp.in.tpf;
    arg.in.vtp = cfg->cmd.create_vtp.in.vtp;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("create vtp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.create_vtp.out.vtpn = arg.out.vtpn;

    TPSA_LOG_INFO("create vtp ioctl success");
    return 0;
}

static int tpsa_ioctl_modify_tpg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_modify_tpg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_MODIFY_TPG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_modify_tpg_t);
    hdr.args_addr = (uint64_t)&arg;

    uint32_t i = 0;

    for (; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        (void)memcpy(&arg.in.rtr_attr[i], &cfg->cmd.modify_tpg.in.rtr_attr[i], sizeof(tpsa_tp_attr_t));
        arg.in.rtr_mask[i] = cfg->cmd.modify_tpg.in.rtr_mask[i];
    }
    arg.in.tpgn = cfg->cmd.modify_tpg.in.tpgn;
    arg.in.tpf = cfg->cmd.modify_tpg.in.tpf;
    arg.ta_data = cfg->cmd.modify_tpg.ta_data;
    arg.udrv_ext = cfg->cmd.modify_tpg.udrv_ext;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("modify tpg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("modify tpg ioctl success");
    return 0;
}

static int tpsa_ioctl_create_target_tpg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_create_target_tpg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CREATE_TARGET_TPG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_create_target_tpg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpg_cfg = cfg->cmd.create_target_tpg.in.tpg_cfg;
    arg.in.tpf = cfg->cmd.create_target_tpg.in.tpf;
    arg.ta_data = cfg->cmd.create_target_tpg.ta_data;
    arg.udata = cfg->cmd.create_target_tpg.udata;
    arg.udrv_ext = cfg->cmd.create_target_tpg.udrv_ext;
    arg.peer_mtu = cfg->cmd.create_target_tpg.peer_mtu;

    uint32_t i = 0;
    for (; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        memcpy(&arg.in.tp_cfg[i], &cfg->cmd.create_target_tpg.in.tp_cfg[i], sizeof(tpsa_cmd_tp_cfg_t));
        memcpy(&arg.in.rtr_attr[i], &cfg->cmd.create_target_tpg.in.rtr_attr[i], sizeof(tpsa_tp_attr_t));
        arg.in.rtr_mask[i] = cfg->cmd.create_target_tpg.in.rtr_mask[i];
    }

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("create target tpg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.create_target_tpg.out.tpgn = arg.out.tpgn;

    for (i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        cfg->cmd.create_target_tpg.out.tpn[i] = arg.out.tpn[i];
    }
    cfg->cmd.create_target_tpg.local_mtu = arg.local_mtu;
    cfg->cmd.create_target_tpg.udata.out_len = arg.udata.out_len;
    cfg->cmd.create_target_tpg.udrv_ext.out_len = arg.udrv_ext.out_len;

    TPSA_LOG_INFO("create target tpgn: %d ioctl success", arg.out.tpgn);
    return 0;
}

static int tpsa_ioctl_modify_target_tpg(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_modify_target_tpg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_MODIFY_TARGET_TPG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_modify_target_tpg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.modify_target_tpg.in.tpf;
    arg.in.tpgn = cfg->cmd.modify_target_tpg.in.tpgn;
    arg.ta_data = cfg->cmd.modify_target_tpg.ta_data;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("modify target tpg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("modify target tpg ioctl success");
    return 0;
}

static int tpsa_ioctl_destroy_vtp(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_destroy_vtp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_DESTROY_VTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_destroy_vtp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.destroy_vtp.in.tpf;
    arg.in.mode = cfg->cmd.destroy_vtp.in.mode;
    arg.in.local_eid = cfg->cmd.destroy_vtp.in.local_eid;
    arg.in.peer_eid = cfg->cmd.destroy_vtp.in.peer_eid;
    arg.in.peer_jetty = cfg->cmd.destroy_vtp.in.peer_jetty;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("destroy vtp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("destroy vtp ioctl success");
    return 0;
}

static int tpsa_ioctl_destroy_tpg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_destroy_tpg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_DESTROY_TPG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_destroy_tpg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.destroy_tpg.in.tpf;
    arg.in.tpgn = cfg->cmd.destroy_tpg.in.tpgn;
    arg.ta_data = cfg->cmd.destroy_tpg.ta_data;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("destroy tpg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }
    cfg->cmd.destroy_tpg.out.destroyed_tp_cnt = arg.out.destroyed_tp_cnt;
    TPSA_LOG_INFO("destroy tpg ioctl success");
    return 0;
}

static int tpsa_ioctl_op_sip(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg, uint32_t commands)
{
    int ret;
    urma_cmd_hdr_t hdr;
    tpsa_cmd_op_sip_t arg = {0};

    hdr.command = (uint32_t)commands;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_op_sip_t);
    hdr.args_addr = (uint64_t)&arg;
    arg.in.parm = cfg->cmd.op_sip.in.parm;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("update sip ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("update sip ioctl success");
    return ret;
}

static int tpsa_ioctl_add_sip(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    return tpsa_ioctl_op_sip(ubcore_fd, cfg, TPSA_CMD_ADD_SIP);
}

static int tpsa_ioctl_del_sip(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    return tpsa_ioctl_op_sip(ubcore_fd, cfg, TPSA_CMD_DEL_SIP);
}

static int tpsa_ioctl_map_vtp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_map_vtp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_MAP_VTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_map_vtp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.map_vtp.in.tpf;
    arg.in.vtp = cfg->cmd.map_vtp.in.vtp;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("map_vtp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.map_vtp.out.vtpn = arg.out.vtpn;

    TPSA_LOG_INFO("map_vtp ioctl success");
    return 0;
}

static int tpsa_ioctl_create_utp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_create_utp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CREATE_UTP;
    hdr.args_len = sizeof(tpsa_cmd_create_utp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.create_utp.in.tpf;
    arg.in.utp_cfg = cfg->cmd.create_utp.in.utp_cfg;
    arg.in.vtp = cfg->cmd.create_utp.in.vtp;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("create_utp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.create_utp.out.idx = arg.out.idx;
    cfg->cmd.create_utp.out.vtpn = arg.out.vtpn;

    TPSA_LOG_INFO("create_utp ioctl success");
    return 0;
}

static int tpsa_ioctl_destroy_utp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_destroy_utp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_DESTROY_UTP;
    hdr.args_len = sizeof(tpsa_cmd_destroy_utp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.destroy_utp.in.tpf;
    arg.in.utp_idx = cfg->cmd.destroy_utp.in.utp_idx;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("destroy_utp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("destroy_utp ioctl success");
    return 0;
}

static int tpsa_ioctl_create_ctp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_create_ctp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CREATE_CTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_create_ctp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.create_ctp.in.tpf;
    arg.in.ctp_cfg = cfg->cmd.create_ctp.in.ctp_cfg;
    arg.in.vtp = cfg->cmd.create_ctp.in.vtp;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("create ctp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.create_ctp.out.idx = arg.out.idx;
    cfg->cmd.create_ctp.out.vtpn = arg.out.vtpn;
    TPSA_LOG_INFO("create ctp ioctl success");
    return 0;
}

static int tpsa_ioctl_destroy_ctp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_destroy_ctp_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_DESTROY_CTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_destroy_ctp_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.destroy_ctp.in.tpf;
    arg.in.ctp_idx = cfg->cmd.destroy_ctp.in.ctp_idx;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("destroy ctp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("destroy ctp ioctl success");
    return 0;
}

static int tpsa_ioctl_change_tpg_to_error(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_change_tpg_to_error_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CHANGE_TPG_TO_ERROR;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_change_tpg_to_error_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpf = cfg->cmd.change_tpg_to_error.in.tpf;
    arg.in.tpgn = cfg->cmd.change_tpg_to_error.in.tpgn;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("change tpg to error ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("change tpg to error ioctl success");
    return 0;
}
static int tpsa_ioctl_restore_tp_op(int ubcore_fd, tpsa_ioctl_cfg_t *cfg, uint32_t command)
{
    tpsa_cmd_restore_tp_error_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)command;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_restore_tp_error_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpgn = cfg->cmd.restore_tp_error.in.tpgn;
    arg.in.tpn = cfg->cmd.restore_tp_error.in.tpn;
    arg.in.data_udp_start = cfg->cmd.restore_tp_error.in.data_udp_start;
    arg.in.ack_udp_start = cfg->cmd.restore_tp_error.in.ack_udp_start;
    arg.in.rx_psn = cfg->cmd.restore_tp_error.in.rx_psn;
    arg.in.tx_psn = cfg->cmd.restore_tp_error.in.tx_psn;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("restore tp op ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    return 0;
}

static int tpsa_ioctl_restore_tp_error_rsp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    return tpsa_ioctl_restore_tp_op(ubcore_fd, cfg, TPSA_CMD_RESTORE_TP_ERROR_RSP);
}

static int tpsa_ioctl_restore_target_tp_error_req(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    return tpsa_ioctl_restore_tp_op(ubcore_fd, cfg, TPSA_CMD_RESTORE_TARGET_TP_ERROR_REQ);
}

static int tpsa_ioctl_restore_target_tp_error_ack(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    return tpsa_ioctl_restore_tp_op(ubcore_fd, cfg, TPSA_CMD_RESTORE_TARGET_TP_ERROR_ACK);
}

static int tpsa_ioctl_restore_tp_suspend(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_restore_tp_suspend_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_RESTORE_TP_SUSPEND;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_restore_tp_suspend_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpgn = cfg->cmd.restore_tp_suspend.in.tpgn;
    arg.in.tpn = cfg->cmd.restore_tp_suspend.in.tpn;
    arg.in.data_udp_start = cfg->cmd.restore_tp_suspend.in.data_udp_start;
    arg.in.ack_udp_start = cfg->cmd.restore_tp_suspend.in.ack_udp_start;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("restore tp suspend ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("restore tp suspend ioctl success");
    return 0;
}

static int tpsa_ioctl_get_dev_feature(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_get_dev_feature_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_GET_DEV_FEATURE;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_get_dev_feature_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)strcpy(arg.in.dev_name, cfg->cmd.get_dev_feature.in.dev_name);

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("get dev feature ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.get_dev_feature.out.feature.value = arg.out.feature.value;

    TPSA_LOG_INFO("get dev feature ioctl success");
    return 0;
}

static int tpsa_ioctl_change_tp_to_error(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_change_tp_to_error_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CHANGE_TP_TO_ERROR;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_change_tp_to_error_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.tpgn = cfg->cmd.change_tp_to_error.in.tpgn;
    arg.in.tpn = cfg->cmd.change_tp_to_error.in.tpn;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("change tp to error ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("change tp to error ioctl success");
    return 0;
}

static int tpsa_ioctl_config_state(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_config_function_migrate_state_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_CONFIG_FUNCTION_MIGRATE_STATE;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_config_function_migrate_state_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.fe_idx = cfg->cmd.config_state.in.fe_idx;
    arg.in.tpf = cfg->cmd.config_state.in.tpf;
    arg.in.config_cnt = cfg->cmd.config_state.in.config_cnt;
    arg.in.state = cfg->cmd.config_state.in.state;

    uint32_t i = 0;
    for (; i < arg.in.config_cnt; i++) {
        (void)memcpy(&arg.in.config[i], &cfg->cmd.config_state.in.config[i],
            sizeof(tpsa_ueid_cfg_t));
    }

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("config function migrate state ioctl failed,\
                     ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    cfg->cmd.config_state.out.cnt = arg.out.cnt;

    TPSA_LOG_INFO("config function migrate state ioctl success");
    return 0;
}

static int tpsa_ioctl_set_global_cfg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_set_global_cfg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_SET_GLOBAL_CFG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_set_global_cfg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.set_cfg = cfg->cmd.global_cfg.in.set_cfg;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("set global cfg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("change tp to error ioctl success");
    return 0;
}

static int tpsa_ioctl_set_vport_cfg(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_set_vport_cfg_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_SET_VPORT_CFG;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_set_vport_cfg_t);
    hdr.args_addr = (uint64_t)&arg;

    arg.in.set_cfg = cfg->cmd.vport_cfg.in.set_cfg;

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("set vport cfg ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("set vport cfg ioctl success");
    return 0;
}

static int tpsa_ioctl_modify_vtp(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_modify_vtp_t *arg;
    urma_cmd_hdr_t hdr;
    int ret;
    arg = calloc(1, sizeof(tpsa_cmd_modify_vtp_t));
    if (arg == NULL) {
        TPSA_LOG_ERR("Fail to alloc modify vtp arg");
        return -1;
    }

    hdr.command = (uint32_t)TPSA_CMD_MODIFY_VTP;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_modify_vtp_t);
    hdr.args_addr = (uint64_t)arg;

    arg->in.tpf = cfg->cmd.modify_vtp.in.tpf;
    arg->in.cfg_cnt = cfg->cmd.modify_vtp.in.cfg_cnt;

    uint32_t i = 0;
    for (; i < arg->in.cfg_cnt; i++) {
        (void)memcpy(&arg->in.vtp[i], &cfg->cmd.modify_vtp.in.vtp[i], sizeof(tpsa_vtp_cfg_t));
    }

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("modify vtp ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
        free(arg);
        return ret;
    }

    TPSA_LOG_INFO("modify vtp ioctl success");
    free(arg);
    return 0;
}

static int tpsa_ioctl_get_dev_info(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    tpsa_cmd_get_dev_info_t arg = {0};
    urma_cmd_hdr_t hdr;
    int ret;

    hdr.command = (uint32_t)TPSA_CMD_GET_DEV_INFO;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_get_dev_info_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)strcpy(arg.in.target_tpf_name,
        cfg->cmd.get_dev_info.in.target_tpf_name);

    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("get dev info ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret,
            errno, hdr.command);
        return ret;
    }

    cfg->cmd.get_dev_info.out.port_is_active = arg.out.port_is_active;

    TPSA_LOG_INFO("get dev info ioctl success with target tpf name %s",
        cfg->cmd.get_dev_info.in.target_tpf_name);
    return 0;
}

int tpsa_ioctl(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    int ret = -1;

    switch (cfg->cmd_type) {
        case TPSA_CMD_CHANNEL_INIT:
            ret = tpsa_ioctl_channel_init(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CREATE_TPG:
            ret = tpsa_ioctl_create_tpg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CREATE_VTP:
            ret = tpsa_ioctl_create_vtp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_MODIFY_TPG:
            ret = tpsa_ioctl_modify_tpg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CREATE_TARGET_TPG:
            ret = tpsa_ioctl_create_target_tpg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_MODIFY_TARGET_TPG:
            ret = tpsa_ioctl_modify_target_tpg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_DESTROY_VTP:
            ret = tpsa_ioctl_destroy_vtp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_DESTROY_TPG:
            ret = tpsa_ioctl_destroy_tpg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_ADD_SIP:
            ret = tpsa_ioctl_add_sip(ubcore_fd, cfg);
            break;
        case TPSA_CMD_DEL_SIP:
            ret = tpsa_ioctl_del_sip(ubcore_fd, cfg);
            break;
        case TPSA_CMD_MAP_VTP:
            ret = tpsa_ioctl_map_vtp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CREATE_UTP:
            ret = tpsa_ioctl_create_utp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_DESTROY_UTP:
            ret = tpsa_ioctl_destroy_utp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_RESTORE_TP_ERROR_RSP:
            ret = tpsa_ioctl_restore_tp_error_rsp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_RESTORE_TARGET_TP_ERROR_REQ:
            ret = tpsa_ioctl_restore_target_tp_error_req(ubcore_fd, cfg);
            break;
        case TPSA_CMD_RESTORE_TARGET_TP_ERROR_ACK:
            ret = tpsa_ioctl_restore_target_tp_error_ack(ubcore_fd, cfg);
            break;
        case TPSA_CMD_RESTORE_TP_SUSPEND:
            ret = tpsa_ioctl_restore_tp_suspend(ubcore_fd, cfg);
            break;
        case TPSA_CMD_GET_DEV_FEATURE:
            ret = tpsa_ioctl_get_dev_feature(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CHANGE_TP_TO_ERROR:
            ret = tpsa_ioctl_change_tp_to_error(ubcore_fd, cfg);
            break;
        case TPSA_CMD_SET_GLOBAL_CFG:
            ret = tpsa_ioctl_set_global_cfg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CONFIG_FUNCTION_MIGRATE_STATE:
            ret = tpsa_ioctl_config_state(ubcore_fd, cfg);
            break;
        case TPSA_CMD_SET_VPORT_CFG:
            ret = tpsa_ioctl_set_vport_cfg(ubcore_fd, cfg);
            break;
        case TPSA_CMD_MODIFY_VTP:
            ret = tpsa_ioctl_modify_vtp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_GET_DEV_INFO:
            ret = tpsa_ioctl_get_dev_info(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CREATE_CTP:
            ret = tpsa_ioctl_create_ctp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_DESTROY_CTP:
            ret = tpsa_ioctl_destroy_ctp(ubcore_fd, cfg);
            break;
        case TPSA_CMD_CHANGE_TPG_TO_ERROR:
            ret = tpsa_ioctl_change_tpg_to_error(ubcore_fd, cfg);
            break;
        default:
            TPSA_LOG_ERR("unsupport cmd type: %d", cfg->cmd_type);
            break;
    }

    return ret;
}

int tpsa_ioctl_init(tpsa_ioctl_ctx_t *ioctl_context)
{
    int dev_fd = open("/dev/ubcore", O_RDWR);
    if (dev_fd == -1) {
        TPSA_LOG_ERR("Failed to open dev_fd err: %s.\n", ub_strerror(errno));
        return -1;
    }

    ioctl_context->ubcore_fd = dev_fd;

    tpsa_ioctl_cfg_t cfg = {
        .cmd_type = TPSA_CMD_CHANNEL_INIT,
        .cmd = {
            .channel_init = "Hello ubcore!",
        },
    };
    int ret = tpsa_ioctl(ioctl_context->ubcore_fd, &cfg);
    return ret;
}

void tpsa_ioctl_uninit(tpsa_ioctl_ctx_t *ioctl_context)
{
    (void)close(ioctl_context->ubcore_fd);
    ioctl_context->ubcore_fd = -1;
}

static inline bool uvs_is_nic_loopback(tpsa_net_addr_t *sip, tpsa_net_addr_t *dip)
{
    return (memcmp(sip, dip, sizeof(tpsa_net_addr_t)) == 0);
}

void tpsa_ioctl_cmd_create_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                               tpsa_net_addr_t *sip, vport_param_t *vport_param, tpsa_net_addr_t *dip)
{
    tpsa_cmd_tpf_t tpf = {0};

    tpf.trans_type = URMA_TRANSPORT_UB;
    (void)memcpy(&tpf.netaddr, sip, sizeof(tpsa_net_addr_t));

    urma_eid_t null_eid = {
        .in6.interface_id = 0,
        .in6.subnet_prefix = 0,
    };

    tpsa_tpg_cfg_t tpg_cfg = {
        .local_eid = null_eid,
        .peer_eid = null_eid,
        .tp_cnt = cparam->trans_mode == TPSA_TP_RC ? TPSA_MIN_TP_NUM : vport_param->tp_cnt,
        .trans_mode = cparam->trans_mode,
        .dscp = vport_param->tp_cfg.dscp,
        .cc_alg = TPSA_TP_CC_LDCP,
        .cc_pattern_idx = vport_param->tp_cfg.cc_pattern_idx,
    };

    /* TODO: lookup vport table to fill tp_flag */
    tpsa_tp_cfg_flag_t tp_flag = {
        .bs.target = TPSA_INITIATOR,
        .bs.loopback = (vport_param->tp_cfg.loop_back && uvs_is_nic_loopback(sip, dip)),
        .bs.ack_resp = vport_param->tp_cfg.ack_resp,
        .bs.dca_enable = vport_param->tp_cfg.tp_mod_flag.bs.dca_enable,
        .bs.bonding = vport_param->tp_cfg.bonding,
    };

    tpsa_cmd_tp_cfg_t tp_cfg = {
        .flag = tp_flag,
        .trans_mode = cparam->trans_mode,
        .fe_idx = cparam->fe_idx,
        .retry_num = vport_param->tp_cfg.retry_num,
        .retry_factor = vport_param->tp_cfg.retry_factor,
        .ack_timeout = vport_param->tp_cfg.ack_timeout,
        .dscp = vport_param->tp_cfg.dscp,
        .oor_cnt = vport_param->tp_cfg.oor_cnt,
    };

    if (cparam->trans_mode == TPSA_TP_RM) {
        tp_cfg.local.local_eid = cparam->local_eid;
        tp_cfg.peer.peer_eid = cparam->peer_eid;
    } else {
        tp_cfg.local.local_jetty.eid = cparam->local_eid;
        tp_cfg.local.local_jetty.id = cparam->local_jetty;
        tp_cfg.peer.peer_jetty.eid = cparam->peer_eid;
        tp_cfg.peer.peer_jetty.id = cparam->peer_jetty;
    }

    cfg->cmd_type = TPSA_CMD_CREATE_TPG;
    cfg->cmd.create_tpg.in.tpf = tpf;
    cfg->cmd.create_tpg.in.tpg_cfg = tpg_cfg;
    cfg->cmd.create_tpg.ta_data = cparam->ta_data;
    cfg->cmd.create_tpg.udata.in_addr = (uint64_t)cparam->udrv_data;
    cfg->cmd.create_tpg.udata.in_len = cparam->udrv_in_len;
    cfg->cmd.create_tpg.udata.out_addr = (uint64_t)(cparam->udrv_data + cparam->udrv_in_len);
    cfg->cmd.create_tpg.udata.out_len = cparam->udrv_out_len;
    cfg->cmd.create_tpg.udrv_ext.out_addr = (uint64_t)(cparam->udrv_data + cparam->udrv_in_len + cparam->udrv_out_len);
    if ((cparam->udrv_in_len + cparam->udrv_out_len) <= TPSA_UDRV_DATA_LEN) {
        cfg->cmd.create_tpg.udrv_ext.out_len = TPSA_UDRV_DATA_LEN - (cparam->udrv_in_len + cparam->udrv_out_len);
    } else {
        cfg->cmd.create_tpg.udrv_ext.out_len = 0;
    }

    uint32_t i = 0;
    for (; i < tpg_cfg.tp_cnt; i++) {
        cfg->cmd.create_tpg.in.tp_cfg[i] = tp_cfg;

        if (i == 0) {
            cfg->cmd.create_target_tpg.in.tp_cfg[i].flag.bs.ack_resp = 1;
        }
    }
}

static inline uvs_mtu_t tpsa_mtu_min(uvs_mtu_t a, uvs_mtu_t b)
{
    return (a < b ? a : b);
}

static inline uint8_t tpsa_mn_min(uint8_t a, uint8_t b)
{
    return (a < b ? a : b);
}

static inline bool tpsa_check_cc_intersections(tpsa_tp_cc_entry_t *target_cc_arr, tpsa_tp_cc_entry_t *local_cc_arr)
{
    if (target_cc_arr->cc_priority == local_cc_arr->cc_priority &&  target_cc_arr->alg == local_cc_arr->alg) {
        return true;
    }
    return false;
}

static inline bool tpsa_update_cc_algo(urma_tp_cc_alg_t nego_alg, urma_tp_cc_alg_t new_alg)
{
    return (uint8_t) new_alg > (uint8_t) nego_alg ? true : false; //
}

static void tpsa_negotiate_two_sides(tpsa_tp_cc_entry_t *target_cc_arr, tpsa_tp_cc_entry_t *local_cc_arr, bool *flag,
                                     urma_tp_cc_alg_t *alg, uint8_t *cc_pattern_idx, uint8_t *priority)
{
    uint8_t prio_tmp;
    if (tpsa_check_cc_intersections(target_cc_arr, local_cc_arr)) {
        prio_tmp = target_cc_arr->cc_priority;
        /* pick the one with higher priority and then better algorithm */
        if (prio_tmp <= *priority && ((prio_tmp < *priority) || tpsa_update_cc_algo(*alg, local_cc_arr->alg))) {
            *priority =  prio_tmp;
            *alg = local_cc_arr->alg;
            *cc_pattern_idx = local_cc_arr->cc_pattern_idx;
            *flag = true;
        }
    }
}
int tpsa_negotiate_optimal_cc_alg(uint32_t target_cc_cnt, tpsa_tp_cc_entry_t *target_cc_arr, bool target_cc_en,
                                  uint32_t local_cc_cnt, tpsa_tp_cc_entry_t *local_cc_arr, bool local_cc_en,
                                  urma_tp_cc_alg_t *alg, uint8_t *cc_pattern_idx)
{
    uint8_t priority = UINT8_MAX;
    bool flag = false;
    uint32_t i;
    uint32_t j;

    if (target_cc_cnt == 0) {
        TPSA_LOG_WARN("cc info array size is 0 in target");
        return -1;
    }

    if (local_cc_cnt == 0) {
        TPSA_LOG_WARN("cc info array size is 0 in local");
        return -1;
    }

    if (!target_cc_en) {
        TPSA_LOG_WARN("cc is disabled in target");
        return -1;
    }

    if (!local_cc_en) {
        TPSA_LOG_WARN("cc is disabled in local");
        return -1;
    }

    *alg = TPSA_TP_CC_NONE;
    *cc_pattern_idx = 0;

    /*
        When the local side config, local get its own cc union(there's only one priority but maybe several algorithms)
        When the local side doesn't config, it will be whole cc info table(can be several priorities and algorithms)
    */
    for (i = 0; i < target_cc_cnt; i++) {
        for (j = 0; j < local_cc_cnt; j++) {
            tpsa_negotiate_two_sides(&target_cc_arr[i], &local_cc_arr[j], &flag, alg, cc_pattern_idx, &priority);
        }
    }

    if (!flag) {
        TPSA_LOG_WARN("failed to negotiate cc algorithm!");
        return -1;
    }

    return 0;
}

static urma_tp_cc_alg_t tpsa_ib_negotiate_optimal_cc_alg(uint16_t local_congestion_alg,
    uint16_t peer_local_congestion_alg)
{
    int i;

    for (i = 0; i <= URMA_TP_CC_NUM; i++) {
        if ((0x1 << (uint32_t)i) & local_congestion_alg & peer_local_congestion_alg) {
            return i;
        }
    }
    return URMA_TP_CC_NONE;
}

void tpsa_ioctl_cmd_create_target_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_sock_msg_t *msg,
                                      tpsa_init_tpg_cmd_param_t *param)
{
    tpsa_create_req_t *req = &msg->content.req;
    urma_tp_cc_alg_t cc_alg = URMA_TP_CC_NONE;
    uint8_t cc_pattern_idx = 0;
    bool cc_en = true;

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = param->sip,
    };

    urma_eid_t null_eid = {
        .in6.interface_id = 0,
        .in6.subnet_prefix = 0,
    };

    tpsa_tpg_cfg_t tpg_cfg = {
        .local_eid = null_eid,
        .peer_eid = null_eid,
        .tp_cnt = req->tpg_cfg.tp_cnt,
        .trans_mode = req->tpg_cfg.trans_mode,
        .dscp = req->tpg_cfg.dscp,
        .cc_alg = TPSA_TP_CC_LDCP,
        .cc_pattern_idx = req->tpg_cfg.cc_pattern_idx,
    };

    tpsa_tp_attr_mask_t tp_attr_mask = {
        .value = 0xffffffff,
    }; /* Need to fix */

    tpsa_tp_ext_t tp_ext = {
        .addr = 0,
        .len = 0,
    };

    cfg->cmd_type = TPSA_CMD_CREATE_TARGET_TPG;
    cfg->cmd.create_target_tpg.in.tpf = tpf;
    cfg->cmd.create_target_tpg.in.tpg_cfg = tpg_cfg;

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        tpsa_negotiate_optimal_cc_alg(param->cc_array_cnt, param->cc_result_array,
        param->tp_cfg.tp_mod_flag.bs.cc_en, req->cc_array_cnt, req->cc_result_array,
        req->cc_en, &cc_alg, &cc_pattern_idx) != 0) {
        param->tp_cfg.tp_mod_flag.bs.cc_en = false;
        cc_en = false;
        cc_alg = TPSA_TP_CC_NONE;
        cc_pattern_idx = 0;
        TPSA_LOG_WARN("Failed to negotiate cc algorithm");
    }
    if (req->ta_data.trans_type == TPSA_TRANSPORT_IB) {
        cc_alg = tpsa_ib_negotiate_optimal_cc_alg(param->tp_cfg.cc_alg, req->tp_param[0].local_tp_cfg.cc_alg);
        cc_en = (bool)(param->tp_cfg.tp_mod_flag.bs.cc_en & req->tp_param[0].local_tp_cfg.tp_mod_flag.bs.cc_en);
    }

    cfg->cmd.create_target_tpg.in.tpg_cfg.cc_pattern_idx = cc_pattern_idx;
    cfg->cmd.create_target_tpg.in.tpg_cfg.cc_alg = cc_alg;
    cfg->cmd.create_target_tpg.ta_data = req->ta_data;
    cfg->cmd.create_target_tpg.peer_mtu = req->tp_param[0].local_mtu;
    cfg->cmd.create_target_tpg.udata.in_addr = (uint64_t)req->udrv_data;
    cfg->cmd.create_target_tpg.udata.in_len = req->udrv_in_len;
    cfg->cmd.create_target_tpg.udata.out_addr = 0;
    cfg->cmd.create_target_tpg.udata.out_len = 0;
    cfg->cmd.create_target_tpg.udrv_ext.in_addr = (uint64_t)(req->udrv_data + req->udrv_in_len + req->udrv_out_len);
    cfg->cmd.create_target_tpg.udrv_ext.in_len = req->udrv_ext_len;
    cfg->cmd.create_target_tpg.udrv_ext.out_addr = (uint64_t)(req->udrv_data + req->udrv_in_len + req->udrv_out_len);
    cfg->cmd.create_target_tpg.udrv_ext.out_len = req->udrv_ext_len;

    uint32_t i = 0;
    for (; i < req->tpg_cfg.tp_cnt; i++) {
        tpsa_tp_cfg_flag_t tp_flag = {
            .bs.target = TPSA_TARGET,
            .bs.loopback = (req->tp_param[i].local_tp_cfg.loop_back && uvs_is_nic_loopback(&param->sip, &param->dip)),
            .bs.ack_resp = req->tp_param[i].local_tp_cfg.ack_resp,
            .bs.dca_enable = param->tp_cfg.tp_mod_flag.bs.dca_enable,
            .bs.bonding = req->tp_param[i].local_tp_cfg.bonding,
        };

        tpsa_cmd_tp_cfg_t tp_cfg = {
            .flag = tp_flag,
            .trans_mode = req->tpg_cfg.trans_mode,
            .retry_num = req->tp_param[i].local_tp_cfg.retry_num,
            .retry_factor = req->tp_param[i].local_tp_cfg.retry_factor,
            .ack_timeout = req->tp_param[i].local_tp_cfg.ack_timeout,
            .dscp = req->tp_param[i].local_tp_cfg.dscp,
            .oor_cnt = req->tp_param[i].local_tp_cfg.oor_cnt,
            .fe_idx = param->fe_idx,
        };

        if (req->tpg_cfg.trans_mode == TPSA_TP_RM) {
            tp_cfg.local.local_eid = msg->peer_eid;
            tp_cfg.peer.peer_eid = msg->local_eid;
        } else {
            tp_cfg.local.local_jetty.eid = msg->peer_eid;
            tp_cfg.local.local_jetty.id = msg->peer_jetty;
            tp_cfg.peer.peer_jetty.eid = msg->local_eid;
            tp_cfg.peer.peer_jetty.id = msg->local_jetty;
        }

        cfg->cmd.create_target_tpg.in.tp_cfg[i] = tp_cfg;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].flag = req->tp_param[i].local_tp_cfg.tp_mod_flag;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].flag.value = req->tp_param[i].local_tp_cfg.tp_mod_flag.value &
            param->tp_cfg.tp_mod_flag.value;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].flag.bs.cc_alg = cc_alg;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].flag.bs.cc_en = cc_en;

        req->tp_param[i].remote_tp_cfg = param->tp_cfg;
        req->tp_param[i].remote_tp_cfg.tp_mod_flag.bs.cc_en = cc_en;
        req->tp_param[i].remote_tp_cfg.tp_mod_flag.bs.cc_alg = cc_alg;
        req->tp_param[i].remote_tp_cfg.cc_pattern_idx = cc_pattern_idx;

        /* should fill in target side param */
        cfg->cmd.create_target_tpg.in.rtr_attr[i].cc_pattern_idx = cc_pattern_idx;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].local_net_addr_idx = param->sip_idx;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].peer_net_addr = param->dip;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].state = req->tp_param[i].state;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].tx_psn = req->tp_param[i].rx_psn;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].rx_psn = 0; /* Need to fix */
        cfg->cmd.create_target_tpg.in.rtr_attr[i].mtu = tpsa_mtu_min(req->tp_param[i].local_mtu,
            param->mtu);
        cfg->cmd.create_target_tpg.in.rtr_attr[i].peer_tpn = req->tp_param[i].local_tpn;

        cfg->cmd.create_target_tpg.in.rtr_attr[i].peer_ext = tp_ext;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].oos_cnt = req->tp_param[i].local_tp_cfg.oos_cnt;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].data_udp_start = req->tp_param[i].local_tp_cfg.data_udp_start;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].ack_udp_start = req->tp_param[i].local_tp_cfg.ack_udp_start;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].udp_range = req->tp_param[i].local_tp_cfg.udp_range;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].hop_limit = req->tp_param[i].local_tp_cfg.hop_limit;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].flow_label = req->tp_param[i].local_tp_cfg.flow_label;
        req->tp_param[i].remote_tp_cfg.port = param->tp_cfg.port; /* modify remote portid */
        cfg->cmd.create_target_tpg.in.rtr_attr[i].port = req->tp_param[i].remote_tp_cfg.port;
        cfg->cmd.create_target_tpg.in.rtr_attr[i].mn = tpsa_mn_min(req->tp_param[i].local_tp_cfg.mn,
            param->tp_cfg.mn);

        cfg->cmd.create_target_tpg.in.rtr_mask[i] = tp_attr_mask;
        if (i == 0) {
            cfg->cmd.create_target_tpg.in.tp_cfg[i].flag.bs.ack_resp = 1;
        }
    }
}

void tpsa_ioctl_cmd_modify_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_sock_msg_t *msg, tpsa_net_addr_t *sip)
{
    tpsa_create_resp_t *resp = &msg->content.resp;
    urma_tp_cc_alg_t cc_alg = URMA_TP_CC_NONE;
    uint8_t cc_pattern_idx = 0;
    bool cc_en = true;

    tpsa_tp_attr_mask_t mask = {
        .value = 0xffffffff,
    }; /* Need to fix */

    tpsa_tp_ext_t tp_ext = {
        .addr = 0,
        .len = 0,
    };

    if (resp->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        tpsa_negotiate_optimal_cc_alg(resp->local_cc_cnt, resp->local_cc_arr, resp->local_cc_en,
        resp->target_cc_cnt, resp->target_cc_arr, resp->target_cc_en,
        &cc_alg, &cc_pattern_idx) != 0) {
        cc_en = false;
        cc_alg = URMA_TP_CC_NONE;
        cc_pattern_idx = 0;
        TPSA_LOG_WARN("Failed to negotiate cc algorithm");
    }
    if (resp->ta_data.trans_type == TPSA_TRANSPORT_IB) {
        cc_alg = tpsa_ib_negotiate_optimal_cc_alg(resp->tp_param[0].local_tp_cfg.cc_alg,
            resp->tp_param[0].remote_tp_cfg.cc_alg);
        cc_en = (bool)(resp->tp_param[0].local_tp_cfg.tp_mod_flag.bs.cc_en &
            resp->tp_param[0].remote_tp_cfg.tp_mod_flag.bs.cc_en);
    }

    cfg->cmd.modify_tpg.ta_data = resp->ta_data;
    cfg->cmd.modify_tpg.udrv_ext.in_addr = (uint64_t)(resp->udrv_data + resp->udrv_in_len + resp->udrv_out_len);
    cfg->cmd.modify_tpg.udrv_ext.in_len = resp->udrv_ext_len;
    cfg->cmd.modify_tpg.udrv_ext.out_addr = 0;
    cfg->cmd.modify_tpg.udrv_ext.out_len = 0;

    /* should fill in local side param */
    uint32_t i = 0;
    for (; i < resp->tpg_cfg.tp_cnt; i++) {
        cfg->cmd.modify_tpg.in.rtr_attr[i].flag.value = resp->tp_param[i].local_tp_cfg.tp_mod_flag.value &
            resp->tp_param[i].remote_tp_cfg.tp_mod_flag.value;
        cfg->cmd.modify_tpg.in.rtr_attr[i].flag.bs.cc_alg = cc_alg;
        cfg->cmd.modify_tpg.in.rtr_attr[i].flag.bs.cc_en = cc_en;
        cfg->cmd.modify_tpg.in.rtr_attr[i].cc_pattern_idx = cc_pattern_idx;
        cfg->cmd.modify_tpg.in.rtr_attr[i].local_net_addr_idx = resp->tp_param[i].local_net_addr_idx;
        cfg->cmd.modify_tpg.in.rtr_attr[i].peer_net_addr = resp->tp_param[i].peer_net_addr;
        cfg->cmd.modify_tpg.in.rtr_attr[i].state = resp->tp_param[i].state;
        cfg->cmd.modify_tpg.in.rtr_attr[i].tx_psn = resp->tp_param[i].tx_psn;
        cfg->cmd.modify_tpg.in.rtr_attr[i].rx_psn = resp->tp_param[i].rx_psn;
        cfg->cmd.modify_tpg.in.rtr_attr[i].mtu = tpsa_mtu_min(resp->tp_param[i].local_mtu, resp->tp_param[i].peer_mtu);
        cfg->cmd.modify_tpg.in.rtr_attr[i].peer_tpn = resp->tp_param[i].peer_tpn;
        cfg->cmd.modify_tpg.in.rtr_attr[i].cc_pattern_idx = cc_pattern_idx;
        cfg->cmd.modify_tpg.in.rtr_attr[i].peer_ext = tp_ext;
        cfg->cmd.modify_tpg.in.rtr_attr[i].oos_cnt = resp->tp_param[i].local_tp_cfg.oos_cnt;
        cfg->cmd.modify_tpg.in.rtr_attr[i].data_udp_start = resp->tp_param[i].local_tp_cfg.data_udp_start;
        cfg->cmd.modify_tpg.in.rtr_attr[i].ack_udp_start = resp->tp_param[i].local_tp_cfg.ack_udp_start;
        cfg->cmd.modify_tpg.in.rtr_attr[i].udp_range = resp->tp_param[i].local_tp_cfg.udp_range;
        cfg->cmd.modify_tpg.in.rtr_attr[i].hop_limit = resp->tp_param[i].local_tp_cfg.hop_limit;
        cfg->cmd.modify_tpg.in.rtr_attr[i].flow_label = resp->tp_param[i].local_tp_cfg.flow_label;
        cfg->cmd.modify_tpg.in.rtr_attr[i].port = resp->tp_param[i].local_tp_cfg.port;
        cfg->cmd.modify_tpg.in.rtr_attr[i].mn = tpsa_mn_min(resp->tp_param[i].local_tp_cfg.mn,
                                                            resp->tp_param[i].remote_tp_cfg.mn);

        cfg->cmd.modify_tpg.in.rtr_mask[i] = mask;
    }

    TPSA_LOG_INFO("cfg->cmd.modify_tpg.in.rtr_attr[i].port = %u", resp->tp_param[i].local_tp_cfg.port);

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_MODIFY_TPG;
    cfg->cmd.modify_tpg.in.tpf = tpf;
    cfg->cmd.modify_tpg.in.tpgn = msg->local_tpgn;
}

void tpsa_ioctl_cmd_get_dev_info(tpsa_ioctl_cfg_t *cfg, char *target_tpf_name)
{
    cfg->cmd_type = TPSA_CMD_GET_DEV_INFO;
    (void)strcpy(cfg->cmd.get_dev_info.in.target_tpf_name,
        target_tpf_name);
}

void tpsa_ioctl_cmd_map_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                            uint32_t number, tpsa_net_addr_t *sip)
{
    tpsa_vtp_cfg_flag_t vtp_flag = {
        .bs.clan_tp = 0,
        .bs.migrate = cparam->liveMigrate ? 1 : 0,
        .bs.reserve = 0,
    };

    tpsa_vtp_cfg_t vtp_cfg = {
        .fe_idx = cparam->fe_idx,
        .vtpn = cparam->vtpn,
        .local_jetty = cparam->local_jetty,
        .local_eid = cparam->local_eid,
        .peer_eid = cparam->peer_eid,
        .peer_jetty = cparam->peer_jetty,
        .flag = vtp_flag,
        .trans_mode = cparam->trans_mode,
        .number = {.value = number},
    };

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_MAP_VTP;
    cfg->cmd.map_vtp.in.tpf = tpf;
    cfg->cmd.map_vtp.in.vtp = vtp_cfg;
}

void tpsa_ioctl_cmd_create_lb_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                                  tpsa_cmd_create_tpg_t *cmd, tpsa_init_vtp_cmd_param_t *param)
{
    tpsa_tp_attr_mask_t mask = {
        .value = 0xffffffff,
    }; /* Need to fix */

    tpsa_tp_ext_t tp_ext = {
        .addr = 0,
        .len = 0,
    };

    uint32_t i = 0;
    uint32_t tp_cnt = cparam->trans_mode == TPSA_TP_RC ? TPSA_MIN_TP_NUM : param->tp_cnt;
    urma_tp_cc_alg_t cc_alg = URMA_TP_CC_NONE;
    uint8_t cc_pattern_idx = 0;
    bool cc_en = true;

    if (tpsa_negotiate_optimal_cc_alg(param->cc_array_cnt, param->cc_result_array,
        param->local_tp_cfg.tp_mod_flag.bs.cc_en, param->cc_array_cnt, param->cc_result_array,
        param->local_tp_cfg.tp_mod_flag.bs.cc_en, &cc_alg, &cc_pattern_idx) != 0) {
        param->local_tp_cfg.tp_mod_flag.bs.cc_en = false;
        cc_en = false;
        cc_alg = TPSA_TP_CC_NONE;
        cc_pattern_idx = 0;
        TPSA_LOG_WARN("Failed to negotiate cc algorithm");
    }

    for (; i < tp_cnt; i++) {
        cfg->cmd.create_vtp.in.rtr_attr[i].flag = param->local_tp_cfg.tp_mod_flag;
        cfg->cmd.create_vtp.in.rtr_attr[i].flag.bs.cc_en = cc_en;
        cfg->cmd.create_vtp.in.rtr_attr[i].flag.bs.cc_alg = cc_alg;
        cfg->cmd.create_vtp.in.rtr_attr[i].local_net_addr_idx = param->local_net_addr_idx;
        cfg->cmd.create_vtp.in.rtr_attr[i].peer_net_addr = param->sip;
        cfg->cmd.create_vtp.in.rtr_attr[i].state = TPSA_TP_STATE_RTR;
        cfg->cmd.create_vtp.in.rtr_attr[i].tx_psn = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].rx_psn = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].mtu = param->mtu;
        cfg->cmd.create_vtp.in.rtr_attr[i].peer_tpn = cmd->out.tpn[i];

        cfg->cmd.create_vtp.in.rtr_attr[i].cc_pattern_idx = cc_pattern_idx;
        cfg->cmd.create_vtp.in.rtr_attr[i].peer_ext = tp_ext;
        cfg->cmd.create_vtp.in.rtr_attr[i].oos_cnt = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].data_udp_start = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].ack_udp_start = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].udp_range = param->udp_range;
        cfg->cmd.create_vtp.in.rtr_attr[i].hop_limit = 0;
        cfg->cmd.create_vtp.in.rtr_attr[i].flow_label = param->flow_label;
        cfg->cmd.create_vtp.in.rtr_attr[i].port = cparam->port_id;
        cfg->cmd.create_vtp.in.rtr_attr[i].mn = 0;

        cfg->cmd.create_vtp.in.rtr_mask[i] = mask;
    }

    tpsa_vtp_cfg_flag_t vtp_flag = {
        .bs.clan_tp = 0,
        .bs.migrate = cparam->liveMigrate ? 1 : 0,
        .bs.reserve = 0,
    };

    tpsa_vtp_cfg_t vtp_cfg = {
        .fe_idx = cparam->fe_idx,
        .vtpn = cparam->vtpn,
        .local_jetty = cparam->local_jetty,
        .local_eid = cparam->local_eid,
        .peer_eid = cparam->peer_eid,
        .peer_jetty = cparam->peer_jetty,
        .flag = vtp_flag,
        .trans_mode = cparam->trans_mode,
        .number = {
            .tpgn = cmd->out.tpgn,
        },
    };

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = param->sip,
    };

    cfg->cmd_type = TPSA_CMD_CREATE_VTP;
    cfg->cmd.create_vtp.in.tpf = tpf;
    cfg->cmd.create_vtp.in.tpgn = cmd->out.tpgn;
    cfg->cmd.create_vtp.in.vtp = vtp_cfg;
}

void tpsa_ioctl_cmd_destroy_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_net_addr_t *sip, uint32_t tpgn,
    struct tpsa_ta_data *ta_data)
{
    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_DESTROY_TPG;
    cfg->cmd.destroy_tpg.in.tpf = tpf;
    cfg->cmd.destroy_tpg.in.tpgn = tpgn;
    if (ta_data != NULL) {
        cfg->cmd.destroy_tpg.ta_data = *ta_data;
    }
}

void tpsa_ioctl_cmd_destroy_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_net_addr_t *sip, urma_transport_mode_t mode,
                                urma_eid_t local_eid, urma_eid_t peer_eid, uint32_t peer_jetty)
{
    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_DESTROY_VTP;
    cfg->cmd.destroy_vtp.in.tpf = tpf;
    cfg->cmd.destroy_vtp.in.mode = mode;
    cfg->cmd.destroy_vtp.in.local_eid = local_eid;
    cfg->cmd.destroy_vtp.in.peer_eid = peer_eid;
    cfg->cmd.destroy_vtp.in.peer_jetty = peer_jetty;
}

void tpsa_ioctl_cmd_create_utp(tpsa_ioctl_cfg_t *cfg, vport_param_t *vport_param,
                               tpsa_create_param_t *cparam, utp_table_key_t *key)
{
    tpsa_vtp_cfg_flag_t vtp_flag = {
        .bs.clan_tp = 0,
        .bs.migrate = cparam->liveMigrate ? 1 : 0,
        .bs.reserve = 0,
    };

    tpsa_vtp_cfg_t vtp_cfg = {
        .fe_idx = cparam->fe_idx,
        .vtpn = cparam->vtpn,
        .local_jetty = cparam->local_jetty,
        .local_eid = cparam->local_eid,
        .peer_eid = cparam->peer_eid,
        .peer_jetty = cparam->peer_jetty,
        .flag = vtp_flag,
        .trans_mode = cparam->trans_mode,
        .number = {.value = 0},
    };

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = key->sip,
    };

    tpsa_utp_cfg_flag_t utp_flag = {
        .bs.loopback = (vport_param->tp_cfg.loop_back && uvs_is_nic_loopback(&key->sip, &key->dip)),
        .bs.spray_en = vport_param->tp_cfg.tp_mod_flag.bs.spray_en,
    };

    tpsa_utp_cfg_t utp_cfg = {
        /* transaction layer attributes */
        .flag = utp_flag,
        .udp_start = 0,
        .udp_range = 1,
        .local_net_addr_idx = vport_param->sip_idx,
        .peer_net_addr = key->dip,
        .dscp = vport_param->tp_cfg.dscp,
        .flow_label = vport_param->tp_cfg.flow_label,
        .hop_limit = vport_param->tp_cfg.hop_limit,
        .port_id = cparam->port_id,
    };

    utp_cfg.mtu = cparam->mtu;
    cfg->cmd_type = TPSA_CMD_CREATE_UTP;
    cfg->cmd.create_utp.in.tpf = tpf;
    cfg->cmd.create_utp.in.utp_cfg = utp_cfg;
    cfg->cmd.create_utp.in.vtp = vtp_cfg;
}

void tpsa_ioctl_cmd_destroy_utp(tpsa_ioctl_cfg_t *cfg, utp_table_key_t *key,
                                uint32_t utp_idx)
{
    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = key->sip,
    };

    cfg->cmd_type = TPSA_CMD_DESTROY_UTP;
    cfg->cmd.destroy_utp.in.tpf = tpf;
    cfg->cmd.destroy_utp.in.utp_idx = utp_idx;
}

void tpsa_ioctl_cmd_create_ctp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                               ctp_table_key_t *key, tpsa_net_addr_t *sip, uint32_t cna_len)
{
    tpsa_vtp_cfg_flag_t vtp_flag = {
        .bs.clan_tp = 1,
        .bs.migrate = cparam->liveMigrate ? 1 : 0,
        .bs.reserve = 0,
    };

    tpsa_vtp_cfg_t vtp_cfg = {
        .fe_idx = cparam->fe_idx,
        .vtpn = cparam->vtpn,
        .local_jetty = cparam->local_jetty,
        .local_eid = cparam->local_eid,
        .peer_eid = cparam->peer_eid,
        .peer_jetty = cparam->peer_jetty,
        .flag = vtp_flag,
        .trans_mode = cparam->trans_mode,
        .number = {.value = 0},
    };

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    tpsa_ctp_cfg_t ctp_cfg = {
        .peer_net_addr = key->dip,
        .cna_len = cna_len,
    };

    cfg->cmd_type = TPSA_CMD_CREATE_CTP;
    cfg->cmd.create_ctp.in.tpf = tpf;
    cfg->cmd.create_ctp.in.ctp_cfg = ctp_cfg;
    cfg->cmd.create_ctp.in.vtp = vtp_cfg;
}

void tpsa_ioctl_cmd_destroy_ctp(tpsa_ioctl_cfg_t *cfg, ctp_table_key_t *key,
                                tpsa_net_addr_t *sip, uint32_t ctp_idx)
{
    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_DESTROY_CTP;
    cfg->cmd.destroy_ctp.in.tpf = tpf;
    cfg->cmd.destroy_ctp.in.ctp_idx = ctp_idx;
}

void tpsa_ioctl_cmd_change_tpg_to_error(tpsa_ioctl_cfg_t *cfg, tpsa_net_addr_t *sip, uint32_t tpgn)
{
    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    cfg->cmd_type = TPSA_CMD_CHANGE_TPG_TO_ERROR;
    cfg->cmd.change_tpg_to_error.in.tpf = tpf;
    cfg->cmd.change_tpg_to_error.in.tpgn = tpgn;
}

void tpsa_ioctl_cmd_config_state(tpsa_ioctl_cfg_t *cfg, vport_table_entry_t *vport_entry,
                                 tpsa_cmd_tpf_t *tpf, tpsa_mig_state_t state, uint32_t begin_idx)
{
    cfg->cmd_type = TPSA_CMD_CONFIG_FUNCTION_MIGRATE_STATE;

    /* TODO: check whether ueid has been configed to driver */
    uint32_t i = 0;
    for (; ((i + begin_idx) < vport_entry->ueid_max_cnt) && (i < TPSA_MAX_EID_CONFIG_CNT); i++) {
        cfg->cmd.config_state.in.config[i].eid = vport_entry->ueid[(i + begin_idx)].eid;
        cfg->cmd.config_state.in.config[i].upi = vport_entry->ueid[(i + begin_idx)].upi;
        cfg->cmd.config_state.in.config[i].eid_index = (i + begin_idx);
    }

    cfg->cmd.config_state.in.tpf = *tpf;
    cfg->cmd.config_state.in.config_cnt = i;
    cfg->cmd.config_state.in.state = state;
}

int uvs_ioctl_cmd_set_global_cfg(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_global_cfg_t *global_cfg)
{
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create ioctl cfg");
        return -1;
    }

    cfg->cmd_type = TPSA_CMD_SET_GLOBAL_CFG;
    cfg->cmd.global_cfg.in.set_cfg.mask.bs.suspend_period = global_cfg->mask.bs.suspend_period;
    cfg->cmd.global_cfg.in.set_cfg.mask.bs.suspend_cnt = global_cfg->mask.bs.suspend_cnt;
    cfg->cmd.global_cfg.in.set_cfg.suspend_period = global_cfg->suspend_period;
    cfg->cmd.global_cfg.in.set_cfg.suspend_cnt = global_cfg->suspend_cnt;

    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to ubcore");
        free(cfg);
        return -1;
    }
    free(cfg);
    return 0;
}

int uvs_ioctl_cmd_set_vport_cfg(tpsa_ioctl_ctx_t *ioctl_ctx,
    vport_table_entry_t *add_entry, tpsa_global_cfg_t *global_cfg)
{
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create ioctl cfg");
        return -1;
    }

    cfg->cmd_type = TPSA_CMD_SET_VPORT_CFG;
    (void)memcpy(cfg->cmd.vport_cfg.in.set_cfg.dev_name,
        add_entry->key.dev_name, TPSA_MAX_DEV_NAME);
    cfg->cmd.vport_cfg.in.set_cfg.fe_idx = add_entry->key.fe_idx;

    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.pattern = add_entry->mask.bs.pattern;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.virtualization = add_entry->mask.bs.virtualization;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.min_jetty_cnt = add_entry->mask.bs.min_jetty_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.max_jetty_cnt = add_entry->mask.bs.max_jetty_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.min_jfr_cnt = add_entry->mask.bs.min_jfr_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.max_jfr_cnt = add_entry->mask.bs.max_jfr_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.mask.bs.slice = global_cfg->mask.bs.slice;
    cfg->cmd.vport_cfg.in.set_cfg.pattern = add_entry->pattern;
    cfg->cmd.vport_cfg.in.set_cfg.virtualization = add_entry->virtualization;
    cfg->cmd.vport_cfg.in.set_cfg.min_jetty_cnt = add_entry->min_jetty_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.max_jetty_cnt = add_entry->max_jetty_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.min_jfr_cnt = add_entry->min_jfr_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.max_jfr_cnt = add_entry->max_jfr_cnt;
    cfg->cmd.vport_cfg.in.set_cfg.slice = global_cfg->slice;

    if (cfg->cmd.vport_cfg.in.set_cfg.mask.value == 0) {
        free(cfg);
        return 0;
    }

    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to ubcore");
        free(cfg);
        return -1;
    }
    free(cfg);
    return 0;
}

int uvs_ioctl_cmd_modify_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_vtp_cfg_t *vtp_cfg,
                             tpsa_net_addr_t *sip, uint32_t vice_tpgn)
{
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to allocl modify vtp ioctl request");
        return -1;
    }

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    /* check whether we need to modify multiple vtp at one time */
    cfg->cmd_type = TPSA_CMD_MODIFY_VTP;
    cfg->cmd.modify_vtp.in.cfg_cnt = 1;
    cfg->cmd.modify_vtp.in.tpf = tpf;
    (void)memcpy(&cfg->cmd.modify_vtp.in.vtp[0], vtp_cfg, sizeof(tpsa_vtp_cfg_t));

    cfg->cmd.modify_vtp.in.vtp[0].number.value = vice_tpgn;

    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp");
        free(cfg);
        return -1;
    }
    TPSA_LOG_INFO("Finish modify vtp: %u\n", vtp_cfg->vtpn);

    free(cfg);

    return 0;
}