/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa header of netaddr and routing
 * Author: Yan Fangfang
 * Create: 2022-12-12
 * Note:
 * History:
 */
#ifndef TPSA_NET_H
#define TPSA_NET_H

#include <pthread.h>
#include "ub_hmap.h"
#include "tpsa_nl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_MAX_NETADDR_CNT 8

typedef struct tpsa_underlay_info {
    uvs_net_addr_t peer_uvs_ip; /* peer tps server address */
    urma_eid_t eid; /* underlay eid */
    tpsa_multipath_tp_cfg_t cfg; /* rc and rm modes, support for multiple path configuration parameters */
    uint32_t netaddr_cnt;
    uvs_net_addr_info_t netaddr[0];
} tpsa_underlay_info_t;

typedef struct tpsa_netaddr_entry {
    struct ub_hmap_node node;
    urma_eid_t eid; /* key */
    tpsa_underlay_info_t underlay; /* data */
} tpsa_netaddr_entry_t;

typedef struct tpsa_netaddr_tbl {
    struct ub_hmap hmap;
    pthread_rwlock_t rwlock;
} tpsa_netaddr_tbl_t;

int str_to_net_addr(const char *buf, uvs_net_addr_t *net_addr);
/* Lookup underlay info with local or remote eid */
tpsa_netaddr_entry_t *tpsa_lookup_underlay_info(urma_eid_t *eid);

/* Lookup both local and remote underlay info with lock once */
int tpsa_get_underlay_info(urma_eid_t *local_eid, urma_eid_t *remote_eid,
    tpsa_netaddr_entry_t **local_underlay, tpsa_netaddr_entry_t **remote_underlay);

/* Mapping from eid to underlay info */
int tpsa_add_underlay_info(urma_eid_t *eid, tpsa_underlay_info_t *underlay);

int tpsa_net_init(void);
void tpsa_net_uninit(void);

#ifdef __cplusplus
}
#endif

#endif