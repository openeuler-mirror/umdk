/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: Liburma interface open to provier
 * Author: Qian Guoxin
 * Create: 2021-07-31
 * Note:
 * History: 2021-07-31 create file
 */

#ifndef URMA_PROVIDER_H
#define URMA_PROVIDER_H

#include <sys/types.h>

#include "urma_api.h"

#define URMA_SYSFS_DEV_FLAG_DRIVER_CREATED (0x1)

typedef struct urma_match_entry {
    uint16_t vendor_id;
    uint16_t device_id;
} urma_match_entry_t;

typedef struct urma_udrv {
    uint64_t in_addr;
    uint32_t in_len;
    uint64_t out_addr;
    uint32_t out_len;
} urma_udrv_t;

typedef struct urma_ops {
    /* OPs name */
    const char *name;

    /* Jetty OPs */
    urma_jfc_t *(*create_jfc)(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg);
    urma_status_t (*modify_jfc)(urma_jfc_t *jfc, urma_jfc_attr_t *attr);
    urma_status_t (*delete_jfc)(urma_jfc_t *jfc);
    urma_status_t (*delete_jfc_batch)(urma_jfc_t **jfc, int jfc_num, urma_jfc_t **bad_jfc);
    urma_jfs_t *(*create_jfs)(urma_context_t *ctx, urma_jfs_cfg_t *jfs);
    urma_status_t (*modify_jfs)(urma_jfs_t *jfs, urma_jfs_attr_t *attr);
    urma_status_t (*query_jfs)(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr);
    int (*flush_jfs)(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr);
    urma_status_t (*delete_jfs)(urma_jfs_t *jfs);
    urma_status_t (*delete_jfs_batch)(urma_jfs_t **jfs_arr, int jfs_num, urma_jfs_t **bad_jfs);
    urma_jfr_t *(*create_jfr)(urma_context_t *ctx, urma_jfr_cfg_t *jfr);
    urma_status_t (*modify_jfr)(urma_jfr_t *jfr, urma_jfr_attr_t *attr);
    urma_status_t (*query_jfr)(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr);
    urma_status_t (*delete_jfr)(urma_jfr_t *jfr);
    urma_status_t (*delete_jfr_batch)(urma_jfr_t **jfr_arr, int jfr_num, urma_jfr_t **bad_jfr);
    urma_target_jetty_t *(*import_jfr)(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token);
    urma_status_t (*unimport_jfr)(urma_target_jetty_t *target_jfr);
    urma_status_t (*advise_jfr)(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);
    urma_status_t (*unadvise_jfr)(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);
    urma_status_t (*advise_jfr_async)(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, urma_advise_async_cb_func cb_fun,
                                      void *cb_arg);
    urma_jetty_t *(*create_jetty)(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);
    urma_status_t (*modify_jetty)(urma_jetty_t *jetty, urma_jetty_attr_t *jetty_attr);
    urma_status_t (*query_jetty)(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr);
    int (*flush_jetty)(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);
    urma_status_t (*delete_jetty)(urma_jetty_t *jetty);
    urma_status_t (*delete_jetty_batch)(urma_jetty_t **jetty_arr, int jetty_num, urma_jetty_t **bad_jetty);
    urma_target_jetty_t *(*import_jetty)(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *rjetty_token);
    urma_status_t (*unimport_jetty)(urma_target_jetty_t *target_jetty);
    urma_status_t (*advise_jetty)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
    urma_status_t (*unadvise_jetty)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
    urma_status_t (*advise_jetty_async)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                                        urma_advise_async_cb_func cb_fun, void *cb_arg);
    urma_status_t (*bind_jetty)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
    urma_status_t (*unbind_jetty)(urma_jetty_t *jetty);
    urma_jetty_grp_t *(*create_jetty_grp)(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg);
    urma_status_t (*delete_jetty_grp)(urma_jetty_grp_t *jetty_grp);
    urma_jfce_t *(*create_jfce)(urma_context_t *ctx);
    urma_status_t (*delete_jfce)(urma_jfce_t *jfce);
    /**
     * Get tpn of current jetty
     * @param[in] jetty: the jetty pointer created before
     * Return: 0 or positive as correct tpn; negative as get tpn failure
     */
    int (*get_tpn)(urma_jetty_t *jetty);
    int (*modify_tp)(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg, urma_tp_attr_t *attr,
                     urma_tp_attr_mask_t mask);
    /* Control plane OPs */
    urma_status_t (*get_tp_list)(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt,
                                 urma_tp_info_t *tp_list);
    urma_status_t (*set_tp_attr)(const urma_context_t *ctx, const uint64_t tp_handle, const uint8_t tp_attr_cnt,
                                 const uint32_t tp_attr_bitmap, const urma_tp_attr_value_t *tp_attr);
    urma_status_t (*get_tp_attr)(const urma_context_t *ctx, const uint64_t tp_handle, uint8_t *tp_attr_cnt,
                                 uint32_t *tp_attr_bitmap, urma_tp_attr_value_t *tp_attr);
    urma_target_jetty_t *(*import_jetty_ex)(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value,
                                            urma_active_tp_cfg_t *active_tp_cfg);
    urma_target_jetty_t *(*import_jfr_ex)(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value,
                                          urma_active_tp_cfg_t *active_tp_cfg);
    urma_status_t (*bind_jetty_ex)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                                   urma_active_tp_cfg_t *active_tp_cfg);

    /* Segment OPs */
    urma_token_id_t *(*alloc_token_id)(urma_context_t *ctx);
    urma_token_id_t *(*alloc_token_id_ex)(urma_context_t *ctx, urma_token_id_flag_t flag);
    urma_status_t (*free_token_id)(urma_token_id_t *token_id);
    urma_target_seg_t *(*register_seg)(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg);
    urma_status_t (*unregister_seg)(urma_target_seg_t *target_seg);
    urma_target_seg_t *(*import_seg)(urma_context_t *ctx, urma_seg_t *seg, urma_token_t *token, uint64_t addr,
                                     urma_import_seg_flag_t flag);
    urma_status_t (*unimport_seg)(urma_target_seg_t *target_seg);

    /* Events OPs */
    urma_status_t (*get_async_event)(urma_context_t *ctx, urma_async_event_t *event);
    void (*ack_async_event)(urma_async_event_t *event);

    /* Other OPs */
    int (*user_ctl)(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

    /* Dataplane OPs */
    urma_status_t (*post_jfs_wr)(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
    urma_status_t (*post_jfr_wr)(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
    urma_status_t (*post_jetty_send_wr)(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
    urma_status_t (*post_jetty_recv_wr)(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
    int (*poll_jfc)(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
    urma_status_t (*rearm_jfc)(urma_jfc_t *jfc, bool solicited_only);
    int (*wait_jfc)(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);
    void (*ack_jfc)(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

    /* Jetty async OPs */
    urma_target_jetty_t *(*import_jetty_async)(urma_notifier_t *notifier, const urma_rjetty_t *rjetty,
                                               const urma_token_t *token_value, uint64_t user_ctx, int timeout);
    urma_status_t (*unimport_jetty_async)(urma_target_jetty_t *target_jetty);

    urma_status_t (*bind_jetty_async)(urma_notifier_t *notifier, urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                                      uint64_t user_ctx, int timeout);
    urma_status_t (*unbind_jetty_async)(urma_jetty_t *jetty);

    urma_notifier_t *(*create_notifier)(urma_context_t *ctx);
    urma_status_t (*delete_notifier)(urma_notifier_t *notifier);
    int (*wait_notify)(urma_notifier_t *notifier, uint32_t cnt, urma_notify_t *notify, int timeout);
    void (*ack_notify)(uint32_t cnt, urma_notify_t *notify);
} urma_ops_t;

typedef struct urma_provider_attr {
    uint32_t version; /* compatible with abi verison of kernel driver */
    urma_transport_type_t transport_type;
} urma_provider_attr_t;

typedef struct urma_provider_ops {
    const char *name;
    urma_provider_attr_t attr;
    urma_match_entry_t *match_table;
    urma_status_t (*init)(urma_init_attr_t *conf);
    urma_status_t (*uninit)(void);
    /* Device OPs */
    urma_status_t (*query_device)(urma_device_t *dev, urma_device_attr_t *dev_attr);
    urma_context_t *(*create_context)(urma_device_t *dev, uint32_t eid_index, int dev_fd);
    urma_status_t (*delete_context)(urma_context_t *ctx);
    urma_status_t (*get_uasid)(uint32_t *uasid); /* obsolete */
} urma_provider_ops_t;

typedef struct urma_import_tseg_cfg {
    urma_ubva_t ubva;
    uint64_t len;
    urma_seg_attr_t attr;
    uint32_t token_id;
    urma_token_t *token;
    urma_import_seg_flag_t flag;
    uint64_t mva;
} urma_import_tseg_cfg_t;

typedef struct urma_tjfr_cfg {
    urma_jfr_id_t jfr_id;
    urma_import_jetty_flag_t flag;
    urma_token_t *token;
    urma_transport_mode_t trans_mode;
    urma_tp_type_t tp_type;
} urma_tjfr_cfg_t;

typedef struct urma_tjetty_cfg {
    urma_jetty_id_t jetty_id;
    urma_import_jetty_flag_t flag;
    urma_token_t *token;
    urma_transport_mode_t trans_mode;
    urma_jetty_grp_policy_t policy;
    urma_target_type_t type;
    urma_tp_type_t tp_type;
} urma_tjetty_cfg_t;

typedef struct urma_context_cfg {
    struct urma_device *dev;
    struct urma_ops *ops;
    uint32_t eid_index;
    int dev_fd;
    uint32_t uasid;
} urma_context_cfg_t;

#ifndef URMA_CMD_UDRV_PRIV
#define URMA_CMD_UDRV_PRIV
typedef struct urma_cmd_udrv_priv {
    uint64_t in_addr;
    uint32_t in_len;
    uint64_t out_addr;
    uint32_t out_len;
} urma_cmd_udrv_priv_t;
#endif

typedef struct urma_post_and_ret_db_in {
    bool is_jetty;
    union {
        urma_jfs_t *jfs;
        urma_jetty_t *jetty;
    };
    urma_jfs_wr_t *wr;
} urma_post_and_ret_db_in_t;

typedef struct urma_post_and_ret_db_out {
    urma_jfs_wr_t **bad_wr;
    uint64_t db_addr;
    uint64_t db_data;
} urma_post_and_ret_db_out_t;

int urma_register_provider_ops(urma_provider_ops_t *provider_ops);
int urma_unregister_provider_ops(urma_provider_ops_t *provider_ops);
ssize_t urma_read_sysfs_file(const char *dir, const char *file, char *buf, size_t size);

int urma_cmd_create_context(urma_context_t *ctx, urma_context_cfg_t *cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_context(urma_context_t *ctx);

/* Return jfce fd */
int urma_cmd_create_jfce(urma_context_t *ctx);

int urma_cmd_create_jfc(urma_context_t *ctx, urma_jfc_t *jfc, urma_jfc_cfg_t *cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jfc(urma_jfc_t *jfc);
int urma_cmd_delete_jfc_batch(urma_jfc_t **jfc_arr, int jfc_num, urma_jfc_t **bad_jfc);

/* Return number of events on success, -1 on error */
int urma_cmd_wait_jfc(int jfce_fd, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);
void urma_cmd_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

int urma_cmd_create_jfs(urma_context_t *ctx, urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr);
int urma_cmd_delete_jfs(urma_jfs_t *jfs);
int urma_cmd_delete_jfs_batch(urma_jfs_t **jfs_arr, int jfs_num, urma_jfs_t **bad_jfs);

int urma_cmd_create_jfr(urma_context_t *ctx, urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr);
int urma_cmd_delete_jfr(urma_jfr_t *jfr);
int urma_cmd_delete_jfr_batch(urma_jfr_t **jfr_arr, int jfr_num, urma_jfr_t **bad_jfr);

int urma_cmd_import_jfr(urma_context_t *ctx, urma_target_jetty_t *tjfr, urma_tjfr_cfg_t *cfg,
                        urma_cmd_udrv_priv_t *udata);
int urma_cmd_import_jfr_ex(urma_context_t *ctx, urma_target_jetty_t *tjfr, urma_tjfr_cfg_t *cfg,
                           urma_import_jfr_ex_cfg_t *ex_cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_jfr(urma_target_jetty_t *tjfr);

/* Advise cmds */
int urma_cmd_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);

int urma_cmd_create_jetty(urma_context_t *ctx, urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr);
int urma_cmd_delete_jetty(urma_jetty_t *jetty);
int urma_cmd_delete_jetty_batch(urma_jetty_t **jetty_arr, int jetty_num, urma_jetty_t **bad_jetty);

int urma_cmd_import_jetty(urma_context_t *ctx, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                          urma_cmd_udrv_priv_t *udata);
int urma_cmd_import_jetty_ex(urma_context_t *ctx, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                             urma_import_jetty_ex_cfg_t *ex_cfg, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_jetty(urma_target_jetty_t *tjetty);

int urma_cmd_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

int urma_cmd_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_cmd_udrv_priv_t *udata);
int urma_cmd_bind_jetty_ex(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_bind_jetty_ex_cfg_t *ex_cfg,
                           urma_cmd_udrv_priv_t *udata);
int urma_cmd_unbind_jetty(urma_jetty_t *jetty);

int urma_cmd_create_jetty_grp(urma_context_t *ctx, urma_jetty_grp_t *jetty_grp, urma_jetty_grp_cfg_t *cfg,
                              urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jetty_grp(urma_jetty_grp_t *jetty_grp);

int urma_cmd_alloc_token_id(urma_context_t *ctx, urma_token_id_t *token_id, urma_cmd_udrv_priv_t *udata);
int urma_cmd_alloc_token_id_ex(urma_context_t *ctx, urma_token_id_t *token_id, urma_token_id_flag_t flag,
                               urma_cmd_udrv_priv_t *udata);
int urma_cmd_free_token_id(urma_token_id_t *token_id);

int urma_cmd_register_seg(urma_context_t *ctx, urma_target_seg_t *tseg, urma_seg_cfg_t *cfg,
                          urma_cmd_udrv_priv_t *udata);
int urma_cmd_unregister_seg(urma_target_seg_t *tseg);

int urma_cmd_import_seg(urma_context_t *ctx, urma_target_seg_t *tseg, urma_import_tseg_cfg_t *cfg,
                        urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_seg(urma_target_seg_t *tseg);

urma_status_t urma_cmd_get_async_event(urma_context_t *ctx, urma_async_event_t *event);
void urma_cmd_ack_async_event(urma_async_event_t *event);

/* Return user control res, for 0 on success, others on error */
int urma_cmd_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out, urma_udrv_t *udrv_data);
int urma_cmd_get_eid_list(int dev_fd, uint32_t max_eid_cnt, urma_eid_info_t *eid_list, uint32_t *eid_cnt);
int urma_cmd_get_net_addr_list(urma_context_t *ctx, uint32_t max_netaddr_cnt, urma_net_addr_info_t *net_addr_info,
                               uint32_t *cnt);
int urma_cmd_modify_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg, urma_tp_attr_t *attr,
                       urma_tp_attr_mask_t mask);
struct urma_sysfs_dev;
int urma_cmd_query_device_attr(int dev_fd, struct urma_sysfs_dev *sysfs_dev);
int urma_register_sysfs_dev(struct urma_sysfs_dev *dev);

int urma_cmd_import_jetty_async(urma_notifier_t *notifier, urma_target_jetty_t *tjetty, urma_tjetty_cfg_t *cfg,
                                uint64_t user_ctx, int timeout, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_jetty_async(urma_target_jetty_t *tjetty);

int urma_cmd_bind_jetty_async(urma_notifier_t *notifier, urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                              uint64_t user_ctx, int timeout, urma_cmd_udrv_priv_t *udata);
int urma_cmd_unbind_jetty_async(urma_jetty_t *jetty);

int urma_cmd_create_notifier(urma_context_t *ctx);
int urma_cmd_wait_notify(urma_notifier_t *notifier, uint32_t cnt, urma_notify_t *notify, int timeout);

int urma_cmd_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt, urma_tp_info_t *tp_list,
                         urma_cmd_udrv_priv_t *udata);
int urma_cmd_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, const uint8_t tp_attr_cnt,
                         const uint32_t tp_attr_bitmap, const urma_tp_attr_value_t *tp_attr,
                         urma_cmd_udrv_priv_t *udata);
int urma_cmd_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, uint8_t *tp_attr_cnt,
                         uint32_t *tp_attr_bitmap, urma_tp_attr_value_t *tp_attr, urma_cmd_udrv_priv_t *udata);
int urma_cmd_exchange_tp_info(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint64_t local_tp_handle, uint32_t tx_psn,
                              uint64_t *peer_tp_handle, uint32_t *rx_psn);

#endif
