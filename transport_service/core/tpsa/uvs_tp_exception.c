/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs tp exception
 * Author: Yu Hua
 * Create: 2023-08-29
 * Note:
 * History: 2023-08-29 uvs tp exception
 */

#include <errno.h>
#include "ub_get_clock.h"
#include "ub_hash.h"
#include "tpsa_tbl_manage.h"
#include "uvs_tp_manage.h"
#include "uvs_tp_exception.h"

static uint64_t g_uvs_clock_per_second;

/* ioctl operations */
static int uvs_ioctl_cmd_restore_target_tp_error_req(tpsa_ioctl_ctx_t *ioctl_ctx, tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_RESTORE_TARGET_TP_ERROR_REQ;
    cfg->cmd.restore_tp_error.in.tpgn = entry->tpgn;
    cfg->cmd.restore_tp_error.in.tpn = entry->tpn;
    cfg->cmd.restore_tp_error.in.data_udp_start = next_port(entry->data_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.ack_udp_start = next_port(entry->ack_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.rx_psn = entry->rx_psn;
    cfg->cmd.restore_tp_error.in.tx_psn = entry->tx_psn;
    cfg->cmd.restore_tp_error.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.restore_tp_error.in.tpf.trans_type = TPSA_TRANSPORT_UB;

    int ret = tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to restore target tp error req");
    } else {
        TPSA_LOG_INFO("Success to ioctl to restore target tp error req");
    }

    free(cfg);
    return ret;
}

static int uvs_ioctl_cmd_restore_tp_error_resp(tpsa_ioctl_ctx_t *ioctl_ctx, tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_RESTORE_TP_ERROR_RSP;
    cfg->cmd.restore_tp_error.in.tpgn = entry->tpgn;
    cfg->cmd.restore_tp_error.in.tpn = entry->tpn;
    cfg->cmd.restore_tp_error.in.data_udp_start = next_port(entry->data_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.ack_udp_start = next_port(entry->ack_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.rx_psn = entry->rx_psn;
    cfg->cmd.restore_tp_error.in.tx_psn = entry->tx_psn;
    cfg->cmd.restore_tp_error.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.restore_tp_error.in.tpf.trans_type = TPSA_TRANSPORT_UB;
    int ret = tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to restore tp error resp");
    } else {
        TPSA_LOG_INFO("Success to ioctl to restore tp error resp");
    }

    free(cfg);
    return ret;
}

static int uvs_ioctl_cmd_restore_target_tp_error_ack(tpsa_ioctl_ctx_t *ioctl_ctx, tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_RESTORE_TARGET_TP_ERROR_ACK;
    cfg->cmd.restore_tp_error.in.tpgn = entry->tpgn;
    cfg->cmd.restore_tp_error.in.tpn = entry->tpn;
    cfg->cmd.restore_tp_error.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.restore_tp_error.in.tpf.trans_type = TPSA_TRANSPORT_UB;

    int ret = tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to restore target tp error ack");
    } else {
        TPSA_LOG_INFO("Success to ioctl to restore target tp error ack");
    }

    free(cfg);
    return ret;
}

static int uvs_ioctl_cmd_restore_lb_tp_error(tpsa_ioctl_ctx_t *ioctl_ctx, tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_RESTORE_TP_ERROR_RSP;
    cfg->cmd.restore_tp_error.in.tpgn = entry->tpgn;
    cfg->cmd.restore_tp_error.in.tpn = entry->tpn;
    cfg->cmd.restore_tp_error.in.data_udp_start = next_port(entry->data_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.ack_udp_start = next_port(entry->ack_udp_start, entry->tpn);
    cfg->cmd.restore_tp_error.in.tx_psn = entry->tx_psn;
    cfg->cmd.restore_tp_error.in.rx_psn = cfg->cmd.restore_tp_error.in.tx_psn;
    cfg->cmd.restore_tp_error.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.restore_tp_error.in.tpf.trans_type = TPSA_TRANSPORT_UB;
    int ret = tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to restore lb tp error");
    } else {
        TPSA_LOG_INFO("Success to ioctl to restore lb tp error");
    }

    free(cfg);
    return ret;
}

static int uvs_ioctl_cmd_change_tp_to_error(tpsa_ioctl_ctx_t *ioctl_ctx,
    tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_CHANGE_TP_TO_ERROR;
    cfg->cmd.change_tp_to_error.in.tpf.trans_type = TPSA_TRANSPORT_UB;
    cfg->cmd.change_tp_to_error.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.change_tp_to_error.in.tpgn = entry->tpgn;
    cfg->cmd.change_tp_to_error.in.tpn = entry->tpn;

    int ret = tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to change tp to error");
    } else {
        TPSA_LOG_INFO("Success to ioctl to change tp to error");
    }

    free(cfg);
    return ret;
}

static int uvs_ioctl_cmd_restore_tp_suspend(tpsa_ioctl_ctx_t *ctx, tpsa_nl_tp_suspend_req_t *suspend_req,
                                            tp_state_table_entry_t *entry)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    cfg->cmd_type = TPSA_CMD_RESTORE_TP_SUSPEND;
    cfg->cmd.restore_tp_suspend.in.tpf.trans_type = TPSA_TRANSPORT_UB;
    cfg->cmd.restore_tp_suspend.in.tpf.netaddr = entry->key.sip;
    cfg->cmd.restore_tp_suspend.in.tpgn = entry->tpgn;
    cfg->cmd.restore_tp_suspend.in.tpn = entry->tpn;
    cfg->cmd.restore_tp_suspend.in.data_udp_start = (uint16_t)ub_hash_add(suspend_req->data_udp_start, entry->tpn);
    cfg->cmd.restore_tp_suspend.in.ack_udp_start = (uint16_t)ub_hash_add(suspend_req->ack_udp_start, entry->tpn);

    int ret = tpsa_ioctl(ctx->ubcore_fd, cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to restore tp suspend");
    } else {
        TPSA_LOG_INFO("Success to ioctl to restore tp suspend");
    }

    free(cfg);
    return ret;
}

/* socket operations */
static int uvs_sock_restore_tp_error_req_to_peer(tpsa_sock_ctx_t *sock_ctx, tpsa_nl_tp_error_req_t *error_req,
                                                 tp_state_table_entry_t *entry)
{
    tpsa_sock_msg_t *req_msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req_msg == NULL) {
        return -ENOMEM;
    }

    req_msg->msg_type = TPSA_TP_ERROR_REQ;
    req_msg->content.tp_err_msg.nl_tp_err_req = *error_req;
    req_msg->content.tp_err_msg.dip = entry->dip;
    int ret = tpsa_sock_send_msg(sock_ctx, req_msg, sizeof(tpsa_sock_msg_t), entry->peer_tpsa_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send socket tp error req\n");
    } else {
        TPSA_LOG_INFO("Success to send socket tp error req\n");
    }

    free(req_msg);
    return ret;
}

static int uvs_sock_restore_tp_error_resp_to_peer(tpsa_sock_ctx_t *sock_ctx, tp_state_table_entry_t *entry)
{
    tpsa_sock_msg_t *resp_msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (resp_msg == NULL) {
        return -ENOMEM;
    }

    resp_msg->msg_type = TPSA_TP_ERROR_RESP;
    resp_msg->content.tp_err_msg.nl_tp_err_req.peer_tpn = entry->peer_tpn;
    resp_msg->content.tp_err_msg.nl_tp_err_req.tx_psn = entry->tx_psn - 1;
    resp_msg->content.tp_err_msg.dip = entry->dip;
    int ret = tpsa_sock_send_msg(sock_ctx, resp_msg, sizeof(tpsa_sock_msg_t), entry->peer_tpsa_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send socket tp error resp\n");
    } else {
        TPSA_LOG_INFO("Success to send socket tp error resp\n");
    }

    free(resp_msg);
    return ret;
}

static int uvs_sock_restore_tp_error_ack_to_peer(tpsa_sock_ctx_t *sock_ctx, tp_state_table_entry_t *entry)
{
    tpsa_sock_msg_t *ack_msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (ack_msg == NULL) {
        return -ENOMEM;
    }

    ack_msg->msg_type = TPSA_TP_ERROR_ACK;
    ack_msg->content.tp_err_msg.nl_tp_err_req.peer_tpn = entry->peer_tpn;
    ack_msg->content.tp_err_msg.dip = entry->dip;
    int ret = tpsa_sock_send_msg(sock_ctx, ack_msg, sizeof(tpsa_sock_msg_t), entry->peer_tpsa_eid);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send socket tp error ack\n");
    } else {
        TPSA_LOG_INFO("Success to send socket tp error ack\n");
    }

    free(ack_msg);
    return ret;
}

/* common */
void uvs_tp_exception_init(void)
{
    g_uvs_clock_per_second = (uint64_t)(get_cpu_mhz(false) * TPSA_SUSPEND2ERROR_PERIOD_US);
}

void uvs_set_sus2err_period(uint32_t sus2err_period)
{
    g_uvs_clock_per_second = (uint64_t)(get_cpu_mhz(false) * sus2err_period);
    TPSA_LOG_WARN("sus2err_period change to %u us\n", sus2err_period);
}

void uvs_tp_exception_uninit(void)
{
    g_uvs_clock_per_second = 0;
}

static tpsa_tp_state_t uvs_handle_nl_suspend_need_to_err(tp_state_table_entry_t *entry)
{
    entry->timestamp[entry->suspend_cnt] = get_cycles();
    entry->suspend_cnt++;

    if (entry->suspend_cnt == TPSA_SUSPEND2ERROR_CNT) {
        uint64_t cycles_delta = entry->timestamp[TPSA_SUSPEND2ERROR_CNT - 1] - entry->timestamp[0];
        if (cycles_delta >= g_uvs_clock_per_second) {
            entry->suspend_cnt--;
            (void)memmove(entry->timestamp, entry->timestamp + 1, entry->suspend_cnt * sizeof(uint64_t));
        } else {
            TPSA_LOG_WARN("Suspend happend %u in %2f now change to err\n", entry->suspend_cnt,
                (double)cycles_delta / g_uvs_clock_per_second);
            (void)memset(entry->timestamp, 0, sizeof(entry->timestamp));
            entry->suspend_cnt = 0;
            return TPSA_TP_STATE_ERR;
        }
    }

    return TPSA_TP_STATE_SUSPENDED;
}

/* handle netlink */
static int nl_tp_error_req_handle_entry(tpsa_sock_ctx_t *sock_ctx, tpsa_ioctl_ctx_t *ioctl_ctx,
                                        tpsa_nl_tp_error_req_t *error_req, tp_state_table_entry_t *entry,
                                        bool isLoopback)
{
    switch (entry->tp_exc_state) {
        case INITIATOR_TP_STATE_RESET:
            /* Repeated reporting of tp error by netlink or overwritten
            by a tp error socket request from the peer end */
            TPSA_LOG_WARN("Repeated reporting of tp error, current tp error request is ignored\n");
            break;
        case INITIATOR_TP_STATE_RTS:
            /* Tp is already restored from suspended */
        case INITIATOR_TP_STATE_SUSPENDED:
            /* failed to restore from tp suspend last time; */
        case INITIATOR_TP_STATE_ERR:
            TPSA_LOG_DEBUG("INITIATOR_TP_STATE_ERR event\n");
            /* Initiator first time handle netlink tp error, do the following things:
            1. notify the peer this tp error event:
                (a) loopback: by netlink;
                (b) non-loopback: by socket;
            2. update tp state entry, following fields need to be explained:
                (a) (non-loopback)tp_exc_state = INITIATOR_TP_STATE_RESET, ubcore already modified tp state to RESET;
                    (loopback)tp_exc_state = INITIATOR_TP_STATE_RTS, loopback does not need to change tp to error; */
            if (isLoopback) {
                if (uvs_ioctl_cmd_restore_lb_tp_error(ioctl_ctx, entry) != 0) {
                    TPSA_LOG_ERR("Failed to restore lb tp error req in worker\n");
                    return -1;
                }

                entry->tp_exc_state = INITIATOR_TP_STATE_RTS;
            } else {
                if (uvs_sock_restore_tp_error_req_to_peer(sock_ctx, error_req, entry) != 0) {
                    TPSA_LOG_ERR("Failed to report tp error to peer\n");
                    return -1;
                }

                entry->tp_exc_state = INITIATOR_TP_STATE_RESET;
            }

            break;
        case TARGET_TP_STATE_ERR:
            /* Tp state has been modified by socket message from peer manually(error->reset), do the following things:
            1. continue to modify tp state(reset->rtr), following fields need to be explained:
                (a) rx_psn = entry->rx_psn, recorded by socket message;
                (b) tx_psn = entry->tx_psn, carried up from current netlink message(error_req->tx_psn + 1);
            2. modify state to TPSA_TP_STATE_RTR;
            3. send resp to peer; */
            TPSA_LOG_DEBUG("TARGET_TP_STATE_ERR event\n");
            if (uvs_ioctl_cmd_restore_target_tp_error_req(ioctl_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to restore target tp error\n");
                return -1;
            }

            entry->tp_exc_state = TARGET_TP_STATE_RTR;

            if (uvs_sock_restore_tp_error_resp_to_peer(sock_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to send tp error resp to peer\n");
                return -1;
            }
            break;
        case TARGET_TP_STATE_RTR:
            /* Tp is already in error state, ignore this netlink message */
            TPSA_LOG_WARN("tpn %u already in error state triggered by peer, ignore it\n", entry->tpn);
            return -1;
        default:
            TPSA_LOG_WARN("Unexpected tp state: %d\n", (int)entry->tp_exc_state);
            return -1;
    }

    return 0;
}

static bool uvs_handle_destroy_tpg(tpsa_nl_tp_error_req_t *error_req, tpsa_net_addr_t *sip,
                                   tpsa_table_t *table_ctx, tpsa_ioctl_ctx_t *ioctl_ctx)
{
    tpg_state_table_key_t tpg_key = {0};

    tpg_key.tpgn = error_req->tpgn;
    tpg_key.sip = *sip;

    tpg_state_table_entry_t *tpg_entry = tpg_state_table_lookup(&table_ctx->tpg_state_table, &tpg_key);
    if (tpg_entry != NULL && (tpg_entry->tpg_exc_state == INITIATOR_TPG_STATE_DEL ||
        tpg_entry->tpg_exc_state == TARGET_TPG_STATE_DEL)) {
        tpg_entry->tp_flush_cnt--;

        tp_state_table_key_t tp_state_key = {
            .tpn = error_req->tpn,
            .sip = *sip
        };

        (void)tp_state_table_remove(&table_ctx->tp_state_table, &tp_state_key);
        TPSA_LOG_INFO("tpg %u, tp %u flush done recv in uvs, %u remaining tp need flush, total %u", tpg_entry->tpgn,
            error_req->tpn, tpg_entry->tp_flush_cnt, tpg_entry->tp_cnt);
        if (tpg_entry->tp_flush_cnt == 0) {
            TPSA_LOG_ERR("tpg %u already in reset, delete it", error_req->tpgn);
            tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
            if (cfg == NULL) {
                return true;
            }
            tpsa_ioctl_cmd_destroy_tpg(cfg, sip, error_req->tpgn, NULL);
            if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
                TPSA_LOG_ERR("Fail to ioctl to destroy tpg in worker");
                free(cfg);
                return true;
            }

            (void)tpg_state_table_remove(&table_ctx->tpg_state_table, &tpg_key);

            TPSA_LOG_INFO("Finish IOCTL to destroy tpg %u when\n", error_req->tpgn);
            free(cfg);
        }
        return true;
    }
    return false;
}

int uvs_handle_nl_tp_error_req(tpsa_table_t *table_ctx, tpsa_sock_ctx_t *sock_ctx, tpsa_ioctl_ctx_t *ioctl_ctx,
                               tpsa_nl_msg_t *msg)
{
    tpsa_nl_tp_error_req_t *error_req = (tpsa_nl_tp_error_req_t *)(void *)msg->payload;
    sip_table_entry_t sip_entry = {0};
    tp_state_table_key_t key = {0};
    bool isLoopback = false;

    tpsa_lookup_sip_table(error_req->sip_idx, &sip_entry, &table_ctx->sip_table);

    if (uvs_handle_destroy_tpg(error_req, &sip_entry.addr, table_ctx, ioctl_ctx)) {
        return 0;
    }

    key.tpn = error_req->tpn;
    key.sip = sip_entry.addr;
    tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
    if (entry == NULL) {
        return -ENXIO;
    }

    if (entry->tp_exc_state == TP_STATE_INIT) {
        entry->tp_exc_state = INITIATOR_TP_STATE_ERR;
        TPSA_LOG_DEBUG("report err event first time");
    }

    entry->tpgn = error_req->tpgn;
    entry->tpn = error_req->tpn;
    entry->tx_psn = error_req->tx_psn + 1;
    entry->peer_tpn = error_req->peer_tpn;
    entry->data_udp_start = error_req->data_udp_start;
    entry->ack_udp_start = error_req->ack_udp_start;

    uvs_end_point_t local = { sip_entry.addr, error_req->peer_eid, error_req->local_jetty_id };
    uvs_end_point_t peer = { entry->dip, error_req->local_eid, error_req->peer_jetty_id };
    isLoopback = uvs_is_loopback(error_req->trans_mode, &local, &peer);
    if (nl_tp_error_req_handle_entry(sock_ctx, ioctl_ctx, error_req, entry, isLoopback) != 0) {
        TPSA_LOG_ERR("Failed to handle netlink tp error req tp state table entry\n");
        return -1;
    }

    /* If tp state == INITIATOR_TP_STATE_RTS, means tp is already restored under loopback scenario */
    if (entry->tp_exc_state == INITIATOR_TP_STATE_RTS &&
        tp_state_table_remove(&table_ctx->tp_state_table, &entry->key) != 0) {
        TPSA_LOG_ERR("Failed to remove tp state table entry\n");
        return -1;
    }

    return 0;
}

static int nl_tp_suspend_req_handle_entry(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_nl_tp_suspend_req_t *suspend_req,
                                          tp_state_table_entry_t *entry)
{
    switch (entry->tp_exc_state) {
        case INITIATOR_TP_STATE_RTS:
            /* Tp is already restored from suspended */
            TPSA_LOG_DEBUG("INITIATOR_TP_STATE_RTS state");
        case INITIATOR_TP_STATE_SUSPENDED:
            /* two different scenarios:
            1. tp first time suspend;
            2. failed to restore from tp suspend last time;
            Here to check whether to restore tp from suspend to rts or to error */
            TPSA_LOG_DEBUG("INITIATOR_TP_STATE_SUSPENDED state");
            if (uvs_handle_nl_suspend_need_to_err(entry) == TPSA_TP_STATE_SUSPENDED) {
                TPSA_LOG_DEBUG("INITIATOR_TP_STATE_SUSPENDED state restore tp suspend");
                if (uvs_ioctl_cmd_restore_tp_suspend(ioctl_ctx, suspend_req, entry) != 0) {
                    TPSA_LOG_ERR("Fail to restore tp suspend");
                    return -1;
                }

                entry->tp_exc_state = INITIATOR_TP_STATE_RTS;
            } else {
                TPSA_LOG_DEBUG("INITIATOR_TP_STATE_SUSPENDED state change tp to err");
                if (uvs_ioctl_cmd_change_tp_to_error(ioctl_ctx, entry) != 0) {
                    TPSA_LOG_ERR("Fail to modify tp state from suspend to error");
                    return -1;
                }

                entry->tp_exc_state = INITIATOR_TP_STATE_ERR;
            }
            break;
        case INITIATOR_TP_STATE_RESET:
        case INITIATOR_TP_STATE_ERR:
        case TARGET_TP_STATE_RTR:
        case TARGET_TP_STATE_ERR:
            /* Tp is already in error state, ignore this netlink message */
            TPSA_LOG_WARN("tpn %u already in error state, ignore it\n", entry->tpn);
            return -1;
        default:
            TPSA_LOG_WARN("Unexpected tp state: %d\n", (int)entry->tp_exc_state);
            return -1;
    }

    return 0;
}

int uvs_handle_nl_tp_suspend_req(tpsa_table_t *table_ctx, tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_tp_suspend_req_t *suspend_req = (tpsa_nl_tp_suspend_req_t *)(void *)msg->payload;
    sip_table_entry_t sip_entry = {0};
    tp_state_table_key_t key = {0};

    tpsa_lookup_sip_table(suspend_req->sip_idx, &sip_entry, &table_ctx->sip_table);
    key.tpn = suspend_req->tpn;
    key.sip = sip_entry.addr;

    tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
    if (entry == NULL) {
        return -ENXIO;
    }

    if (entry->tp_exc_state == TP_STATE_INIT) {
        entry->tp_exc_state = INITIATOR_TP_STATE_SUSPENDED;
        TPSA_LOG_DEBUG("report suspend event first time");
    }

    entry->tpgn = suspend_req->tpgn;
    entry->tpn = suspend_req->tpn;

    return nl_tp_suspend_req_handle_entry(ioctl_ctx, suspend_req, entry);
}

/* handle socket */
static int sock_restore_target_tp_error_req_handle_entry(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_sock_ctx_t *sock_ctx,
                                                         tpsa_sock_msg_t *msg, tp_state_table_entry_t *entry)
{
    tp_state_table_key_t key = {0};

    switch (entry->tp_exc_state) {
        case INITIATOR_TP_STATE_RTS:
            /* tp first time changes to error triggered by peer or tp is already restored from suspended */
            TPSA_LOG_DEBUG("socket INITIATOR_TP_STATE_RTS\n");
        case INITIATOR_TP_STATE_SUSPENDED:
            /* failed to restore from tp suspend last time;
            If the target end is not in the process of processing the tp error, do the following things:
            1. ioctl to change tp state into error;
            2. update tp state entry, following fields need to be explained:
                (a) tp_exc_state = TARGET_TP_STATE_ERR, to indicate tpsa worker is changing tp state to error; */
            TPSA_LOG_DEBUG("socket INITIATOR_TP_STATE_SUSPENDED\n");
            if (uvs_ioctl_cmd_change_tp_to_error(ioctl_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to change target tp to error\n");
                return -1;
            }

            entry->tp_exc_state = TARGET_TP_STATE_ERR;
            break;
        case INITIATOR_TP_STATE_RESET:
            TPSA_LOG_DEBUG("socket INITIATOR_TP_STATE_RESET\n");
            /* Tp error is triggered at both ends. Only one side needs to continue to handle this tp error */
            key.tpn = entry->peer_tpn;
            key.sip = entry->dip;
            if (memcmp(&entry->key, &key, sizeof(tp_state_table_key_t)) > 0) {
                TPSA_LOG_INFO("Tp error is triggered at both ends, ignore this req at this end. tpn %u\n", entry->tpn);
                return 0;
            }
            TPSA_LOG_INFO("Tp error is triggered at both ends, process this req at this end. tpn %u\n", entry->tpn);
            /* If the target end is in the process of processing the tp error(tp state has been modified
            by device(error->reset)), continue to do the following things:
            1. continue to modify tp state(reset->rtr), following fields need to be explained:
                (a) rx_psn = entry->rx_psn, recorded by socket message;
                (b) tx_psn = entry->tx_psn, carried up from current netlink message(error_req->tx_psn + 1);
            2. modify state to TPSA_TP_STATE_RTR;
            3. send resp to peer; */
            if (uvs_ioctl_cmd_restore_target_tp_error_req(ioctl_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to restore target tp error\n");
                return -1;
            }

            entry->tp_exc_state = TARGET_TP_STATE_RTR;

            if (uvs_sock_restore_tp_error_resp_to_peer(sock_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to send tp error resp to peer\n");
                return -1;
            }
            break;
        case INITIATOR_TP_STATE_ERR:
            TPSA_LOG_DEBUG("socket INITIATOR_TP_STATE_ERR\n");
            /* Tp is modified from suspend to error, continue to do the following things:
            1. modify state to TPSA_TP_STATE_RTR; */
            entry->tp_exc_state = TARGET_TP_STATE_ERR;
            break;
        case TARGET_TP_STATE_RTR:
        case TARGET_TP_STATE_ERR:
            /* Tp is already in error state, ignore this netlink message */
            TPSA_LOG_WARN("tpn %u already in error state, ignore it\n", entry->tpn);
            break;
        default:
            TPSA_LOG_WARN("Unexpected tp state: %d\n", (int)entry->tp_exc_state);
            return -1;
    }

    return 0;
}

int uvs_handle_sock_restore_tp_error_req(tpsa_table_t *table_ctx, tpsa_sock_ctx_t *sock_ctx,
                                         tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_sock_msg_t *msg)
{
    tpsa_nl_tp_error_req_t *error_req = (tpsa_nl_tp_error_req_t *)(void *)&msg->content.tp_err_msg.nl_tp_err_req;
    tpsa_tpg_status_t status;
    tpsa_tpg_info_t tpg;

    tp_state_table_key_t key = {0};
    key.tpn = error_req->peer_tpn;
    key.sip = msg->content.tp_err_msg.dip;
    tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
    if (entry == NULL) {
        TPSA_LOG_ERR("tpn %d eid = " EID_FMT " not exist", key.tpn, EID_ARGS(key.sip.eid));
        return -1;
    }

    tpsa_tpg_table_index_t tpg_idx;
    tpg_idx.dip = entry->dip;
    tpg_idx.local_eid = error_req->peer_eid;
    tpg_idx.peer_eid = error_req->local_eid;
    tpg_idx.ljetty_id = error_req->peer_jetty_id;
    tpg_idx.djetty_id = error_req->local_jetty_id;
    tpg_idx.isLoopback = false;

    status = tpsa_lookup_tpg_table(&tpg_idx, error_req->trans_mode, table_ctx, &tpg);
    if (status != TPSA_TPG_LOOKUP_EXIST) {
        TPSA_LOG_ERR("Wrong tpg number find when dealing with socket tp error req");
        return -1;
    }

    if (entry->tp_exc_state == TP_STATE_INIT) {
        entry->tp_exc_state = INITIATOR_TP_STATE_RTS;
    }

    entry->tpgn = tpg.tpgn;
    entry->tpn = error_req->peer_tpn;
    entry->rx_psn = error_req->tx_psn + 1;
    entry->peer_tpn = error_req->tpn;

    return sock_restore_target_tp_error_req_handle_entry(ioctl_ctx, sock_ctx, msg, entry);
}

int uvs_handle_sock_restore_tp_error_resp(tpsa_table_t *table_ctx, tpsa_sock_ctx_t *sock_ctx,
                                          tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_sock_msg_t *msg)
{
    tpsa_nl_tp_error_req_t *error_req = (tpsa_nl_tp_error_req_t *)(void *)&msg->content.tp_err_msg.nl_tp_err_req;
    tp_state_table_key_t key = {0};
    key.tpn = error_req->peer_tpn;
    key.sip = msg->content.tp_err_msg.dip;
    tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
    if (entry != NULL) {
        if (entry->tp_exc_state == INITIATOR_TP_STATE_RESET) {
            /* socket message returns to initiator, tp state has been modified by device(error->reset),
            do the following things:
            1. update entry->rx_psn = error_req->tx_psn + 1;
            2. continue to modify tp state(reset->rtr->rts) by following configures:
                (a) rx_psn = entry->rx_psn, carried from current socket message(error_req->tx_psn + 1);
                (b) tx_psn = entry->tx_psn, recorded by netlink message;
            3. send ack to peer;
            4. remove entry; */
            entry->rx_psn = error_req->tx_psn + 1;

            if (uvs_ioctl_cmd_restore_tp_error_resp(ioctl_ctx, entry) != 0) {
                TPSA_LOG_ERR("Fail to ioctl to restore tp error in worker\n");
                return -1;
            }

            if (uvs_sock_restore_tp_error_ack_to_peer(sock_ctx, entry) != 0) {
                TPSA_LOG_ERR("Failed to send tp error ack to peer\n");
                return -1;
            }

            if (tp_state_table_remove(&table_ctx->tp_state_table, &key) != 0) {
                TPSA_LOG_ERR("Failed to remove tp state table entry\n");
                return -1;
            }
        } else {
            /* todonext: other tp states will not be handled, logs are printed currently. */
            TPSA_LOG_WARN("Unexpected tp state: %d\n", (int)entry->tp_exc_state);
            return -1;
        }
    } else {
        /* no entry is found in the local tp state table */
        TPSA_LOG_WARN("Failed to handle restore tp error response, can not find tp state entry, tpn: %u\n",
                      error_req->peer_tpn);
        return -1;
    }

    return 0;
}

int uvs_handle_sock_restore_tp_error_ack(tpsa_table_t *table_ctx, tpsa_ioctl_ctx_t *ioctl_ctx,
                                         tpsa_sock_msg_t *msg)
{
    tpsa_nl_tp_error_req_t *error_req = (tpsa_nl_tp_error_req_t *)(void *)&msg->content.tp_err_msg.nl_tp_err_req;
    tp_state_table_key_t key = {0};
    key.tpn = error_req->peer_tpn;
    key.sip = msg->content.tp_err_msg.dip;
    tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
    if (entry != NULL) {
        if (entry->tp_exc_state == TARGET_TP_STATE_RTR) {
            /* socket message returns to target, tp state is rtr right now, do the following things:
            1. continue to modify tp state(rtr->rts);
            2. remove entry; */
            if (uvs_ioctl_cmd_restore_target_tp_error_ack(ioctl_ctx, entry) != 0) {
                TPSA_LOG_ERR("Fail to ioctl to restore target tp error in worker\n");
                return -1;
            }

            if (tp_state_table_remove(&table_ctx->tp_state_table, &key) != 0) {
                TPSA_LOG_ERR("Failed to remove tp state table entry\n");
                return -1;
            }
        } else {
            /* todonext: other tp states will not be handled, logs are printed currently. */
            TPSA_LOG_WARN("Unexpected tp state: %d\n", (int)entry->tp_exc_state);
            return -1;
        }
    } else {
        /* no entry is found in the local tp state table */
        TPSA_LOG_WARN("Failed to handle restore tp error response, can not find tp state entry, tpn: %u\n",
                      error_req->peer_tpn);
        return -1;
    }

    return 0;
}