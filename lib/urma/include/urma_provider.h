/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
    urma_jfc_t *(*create_jfc)(urma_context_t *ctx, const urma_jfc_cfg_t *jfc_cfg);
    urma_status_t (*modify_jfc)(urma_jfc_t *jfc, const urma_jfc_attr_t *attr);
    urma_status_t (*delete_jfc)(urma_jfc_t *jfc);
    urma_jfs_t *(*create_jfs)(urma_context_t *ctx, const urma_jfs_cfg_t *jfs);
    urma_status_t (*delete_jfs)(urma_jfs_t *jfs);
    urma_jfr_t *(*create_jfr)(urma_context_t *ctx, const urma_jfr_cfg_t *jfr);
    urma_status_t (*modify_jfr)(urma_jfr_t *jfr, const urma_jfr_attr_t *attr);
    urma_status_t (*delete_jfr)(urma_jfr_t *jfr);
    urma_target_jetty_t *(*import_jfr)(urma_context_t *ctx, const urma_rjfr_t *rjfr, const urma_key_t *key);
    urma_status_t (*unimport_jfr)(urma_target_jetty_t *target_jfr, bool force);
    urma_status_t (*advise_jfr)(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr);
    urma_status_t (*unadvise_jfr)(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, bool force);
    urma_status_t (*advise_jfr_async)(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr,
        urma_advise_async_cb_func cb_fun, void *cb_arg);
    urma_jetty_t *(*create_jetty)(urma_context_t *ctx, const urma_jetty_cfg_t *jetty_cfg);
    urma_status_t (*modify_jetty)(urma_jetty_t *jetty, const urma_jetty_attr_t *jetty_attr);
    urma_status_t (*delete_jetty)(urma_jetty_t *jetty);
    urma_target_jetty_t *(*import_jetty)(urma_context_t *ctx, const urma_rjetty_t *rjetty,
        const urma_key_t *rjetty_key);
    urma_status_t (*unimport_jetty)(urma_target_jetty_t *target_jetty, bool force);
    urma_status_t (*advise_jetty)(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty);
    urma_status_t (*unadvise_jetty)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, bool force);
    urma_status_t (*advise_jetty_async)(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty,
        urma_advise_async_cb_func cb_fun, void *cb_arg);
    urma_status_t (*bind_jetty)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
    urma_status_t (*unbind_jetty)(urma_jetty_t *jetty, bool force);
    urma_jfce_t *(*create_jfce)(urma_context_t *ctx);
    urma_status_t (*delete_jfce)(urma_jfce_t *jfce);

    /* Segment OPs */
    urma_key_id_t *(*alloc_key_id)(urma_context_t *ctx);
    urma_status_t (*free_key_id)(urma_key_id_t *key_id);
    urma_target_seg_t *(*register_seg)(urma_context_t *ctx, const urma_seg_cfg_t *seg_cfg);
    urma_status_t (*unregister_seg)(urma_target_seg_t *target_seg, bool force);
    urma_target_seg_t *(*import_seg)(urma_context_t *ctx, const urma_seg_t *seg,
        const urma_key_t *key,  uint64_t addr, urma_import_seg_flag_t flag);
    urma_status_t (*unimport_seg)(urma_target_seg_t *target_seg, bool force);

    /* Events OPs */
    urma_status_t (*get_async_event)(const urma_context_t *ctx, urma_async_event_t *event);
    void (*ack_async_event)(urma_async_event_t *event);
    urma_status_t (*reg_async_event_cb)(const urma_async_event_cb *cb);

    /* UKey OPs */
    urma_status_t (*get_ukey_param)(urma_dukey_param_t *dukey_param);

    /* Other OPs */
    int (*user_ctl)(const urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

    /* Dataplane OPs */
    urma_status_t (*post_jfs_wr)(const urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
    urma_status_t (*post_jfr_wr)(const urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
    urma_status_t (*post_jetty_send_wr)(const urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
    urma_status_t (*post_jetty_recv_wr)(const urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
    int (*poll_jfc)(const urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
    urma_status_t (*rearm_jfc)(urma_jfc_t *jfc, bool solicited_only);
    int (*wait_jfc)(const urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
        urma_jfc_t *jfc[]);
    void (*ack_jfc)(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);
} urma_ops_t;

typedef struct urma_provider_attr {
    uint32_t version; /* compatible with abi verison of kernel driver */
    urma_transport_type_t transport_type;
} urma_provider_attr_t;

typedef struct urma_provider_ops {
    const char *name;
    urma_provider_attr_t attr;
    const urma_match_entry_t *match_table;
    urma_status_t (*init)(const urma_init_attr_t *conf);
    urma_status_t (*uninit)(void);
    /* Device OPs */
    urma_status_t (*query_device)(const urma_device_t *dev, urma_device_attr_t *dev_attr);
    urma_context_t *(*create_context)(urma_device_t *dev, int dev_fd, uint32_t uasid);
    urma_status_t (*delete_context)(urma_context_t *ctx);
    urma_status_t (*get_uasid)(uint32_t *uasid); /* obsolete */
} urma_provider_ops_t;

typedef struct urma_import_tseg_cfg {
    urma_ubva_t ubva;
    uint64_t len;
    urma_seg_attr_t attr;
    uint32_t key_id;
    const urma_key_t *key;
    urma_import_seg_flag_t flag;
    uint64_t mva;
} urma_import_tseg_cfg_t;

typedef struct urma_tjfr_cfg {
    urma_jfr_id_t jfr_id;
    const urma_key_t *key;
    urma_transport_mode_t trans_mode;
} urma_tjfr_cfg_t;

typedef struct urma_tjetty_cfg {
    urma_jetty_id_t jetty_id;
    const urma_key_t *key;
    urma_transport_mode_t trans_mode;
} urma_tjetty_cfg_t;

typedef struct urma_context_cfg {
    struct urma_device *dev;
    struct urma_ops *ops;
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
        const urma_jfs_t *jfs;
        const urma_jetty_t *jetty;
    };
    urma_jfs_wr_t *wr;
} urma_post_and_ret_db_in_t;

typedef struct urma_post_and_ret_db_out {
    urma_jfs_wr_t **bad_wr;
    uint64_t db_addr;
    uint64_t db_data;
} urma_post_and_ret_db_out_t;

int urma_register_provider_ops(urma_provider_ops_t *provider_ops);
int urma_unregister_provider_ops(const urma_provider_ops_t *provider_ops);
ssize_t urma_read_sysfs_file(const char *dir, const char *file, char *buf, size_t size);

int urma_cmd_set_uasid(int ubcore_fd, uint64_t token, uint32_t in_uasid, uint32_t *out_uasid);
int urma_cmd_put_uasid(int ubcore_fd, uint32_t in_uasid);

int urma_cmd_create_context(urma_context_t *ctx, const urma_context_cfg_t *cfg, const urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_context(urma_context_t *ctx);

int urma_cmd_alloc_key_id(urma_context_t *ctx, urma_key_id_t *key_id, const urma_cmd_udrv_priv_t *udata);
int urma_cmd_free_key_id(urma_key_id_t *key_id);

int urma_cmd_register_seg(urma_context_t *ctx, urma_target_seg_t *tseg, const urma_seg_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unregister_seg(urma_target_seg_t *tseg);

int urma_cmd_import_seg(urma_context_t *ctx, urma_target_seg_t *tseg, const urma_import_tseg_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_seg(urma_target_seg_t *tseg);

int urma_cmd_create_jfs(urma_context_t *ctx, urma_jfs_t *jfs, const urma_jfs_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jfs(urma_jfs_t *jfs);

int urma_cmd_create_jfr(urma_context_t *ctx, urma_jfr_t *jfr, const urma_jfr_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jfr(urma_jfr_t *jfr, const urma_jfr_attr_t *attr,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jfr(urma_jfr_t *jfr);

int urma_cmd_create_jfc(urma_context_t *ctx, urma_jfc_t *jfc, const urma_jfc_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jfc(urma_jfc_t *jfc, const urma_jfc_attr_t *attr,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jfc(urma_jfc_t *jfc);

/* Return jfce fd */
int urma_cmd_create_jfce(const urma_context_t *ctx);

int urma_cmd_import_jfr(urma_context_t *ctx, urma_target_jetty_t *tjfr, const urma_tjfr_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_jfr(urma_target_jetty_t *tjfr);

int urma_cmd_create_jetty(urma_context_t *ctx, urma_jetty_t *jetty, const urma_jetty_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_modify_jetty(urma_jetty_t *jetty, const urma_jetty_attr_t *attr, const urma_cmd_udrv_priv_t *udata);
int urma_cmd_delete_jetty(urma_jetty_t *jetty);

int urma_cmd_import_jetty(urma_context_t *ctx, urma_target_jetty_t *tjetty, const urma_tjetty_cfg_t *cfg,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unimport_jetty(urma_target_jetty_t *tjetty);

/* Advise cmds */
int urma_cmd_advise_jfr(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr, const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);

int urma_cmd_advise_jetty(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty,
    const urma_cmd_udrv_priv_t *udata);
int urma_cmd_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

int urma_cmd_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
    const urma_cmd_udrv_priv_t *udata);

int urma_cmd_unbind_jetty(urma_jetty_t *jetty);

/* Return number of events on success, -1 on error */
int urma_cmd_wait_jfc(int jfce_fd, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);
void urma_cmd_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

urma_status_t urma_cmd_get_async_event(const urma_context_t *ctx, urma_async_event_t *event);
void urma_cmd_ack_async_event(urma_async_event_t *event);

/* Return user control res, for 0 on success, others on error */
int urma_cmd_user_ctl(const urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out,
    urma_udrv_t *udrv_data);

#endif