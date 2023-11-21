/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa implementation of netaddr and routing
 * Author: Yan Fangfang
 * Create: 2022-12-12
 * Note:
 * History:
 */

#include <arpa/inet.h>
#include <errno.h>

#include "ub_hash.h"
#include "tpsa_log.h"
#include "tpsa_net.h"

#define IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define EID_STR_MIN_LEN 3
#define TPSA_NETADDR_TBL_SIZE 10240
static tpsa_netaddr_tbl_t g_netaddr_tbl; /* Lookup netaddr with eid */

static tpsa_netaddr_entry_t *tpsa_lookup_map_entry_with_hash(tpsa_netaddr_tbl_t *tbl, urma_eid_t *eid, uint32_t hash)
{
    tpsa_netaddr_entry_t *cur;
    tpsa_netaddr_entry_t *target = NULL;

    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &tbl->hmap) {
        if (memcmp(&cur->eid, eid, sizeof(urma_eid_t)) == 0) {
            target = cur;
            break;
        }
    }

    return target;
}

static inline tpsa_netaddr_entry_t *tpsa_lookup_map_entry_nolock(tpsa_netaddr_tbl_t *tbl, urma_eid_t *eid)
{
    return tpsa_lookup_map_entry_with_hash(tbl, eid, ub_hash_bytes(eid, sizeof(urma_eid_t), 0));
}

static tpsa_netaddr_entry_t *tpsa_alloc_map_entry(const urma_eid_t *eid, tpsa_underlay_info_t *underlay)
{
    size_t len = underlay->netaddr_cnt * sizeof(tpsa_net_addr_t);
    tpsa_netaddr_entry_t *entry = calloc(1, sizeof(tpsa_netaddr_entry_t) + len);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa netaddr entry");
        return NULL;
    }
    entry->eid = *eid;
    len += sizeof(tpsa_underlay_info_t);
    (void)memcpy(&entry->underlay, underlay, len);
    return entry;
}

tpsa_netaddr_entry_t *tpsa_lookup_underlay_info(urma_eid_t *eid)
{
    if (eid == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }
    tpsa_netaddr_entry_t *underlay;
    tpsa_netaddr_tbl_t *tbl = &g_netaddr_tbl;

    (void)pthread_rwlock_rdlock(&tbl->rwlock);
    underlay = tpsa_lookup_map_entry_nolock(tbl, eid);
    (void)pthread_rwlock_unlock(&tbl->rwlock);
    return underlay;
}

int tpsa_get_underlay_info(urma_eid_t *local_eid, urma_eid_t *remote_eid,
    tpsa_netaddr_entry_t **local_underlay, tpsa_netaddr_entry_t **remote_underlay)
{
    if (local_eid == NULL || remote_eid == NULL || local_underlay == NULL || remote_underlay == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }
    tpsa_netaddr_tbl_t *tbl = &g_netaddr_tbl;

    (void)pthread_rwlock_rdlock(&tbl->rwlock);
    *local_underlay = tpsa_lookup_map_entry_nolock(tbl, local_eid);
    if (*local_underlay == NULL) {
        (void)pthread_rwlock_unlock(&tbl->rwlock);
        return -1;
    }
    *remote_underlay = tpsa_lookup_map_entry_nolock(tbl, remote_eid);
    (void)pthread_rwlock_unlock(&tbl->rwlock);
    return (*remote_underlay == NULL ? -1 : 0);
}

int tpsa_add_underlay_info(urma_eid_t *eid, tpsa_underlay_info_t *underlay)
{
    if (eid == NULL || underlay == NULL || underlay->netaddr_cnt == 0 ||
        underlay->netaddr_cnt > TPSA_MAX_NETADDR_CNT) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    tpsa_netaddr_tbl_t *tbl = &g_netaddr_tbl;
    uint32_t hash = ub_hash_bytes(eid, sizeof(urma_eid_t), 0);
    tpsa_netaddr_entry_t *entry = tpsa_alloc_map_entry(eid, underlay);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa netaddr entry");
        return -1;
    }

    (void)pthread_rwlock_wrlock(&tbl->rwlock);
    /* Do not add if the map entry already exists */
    if (tpsa_lookup_map_entry_with_hash(tbl, eid, hash) != NULL) {
        (void)pthread_rwlock_unlock(&tbl->rwlock);
        free(entry);
        return 0;
    }
    ub_hmap_insert(&tbl->hmap, &entry->node, hash);
    (void)pthread_rwlock_unlock(&tbl->rwlock);

    /* Add map entry from underlay eid to underlay netaddr and peer tps as well */
    if (memcmp(eid, &underlay->eid, sizeof(urma_eid_t)) != 0) {
        (void)tpsa_add_underlay_info(&underlay->eid, underlay);
    }
    return 0;
}

static inline void ipv4_map_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int str_to_eid(const char *buf, urma_eid_t *eid)
{
    uint32_t ipv4;

    if (buf == NULL || strlen(buf) <= EID_STR_MIN_LEN || eid == NULL) {
        TPSA_LOG_ERR("Invalid argument");
        return -EINVAL;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        ipv4_map_to_eid(be32toh(ipv4), eid);
        return 0;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) <= 0) {
        TPSA_LOG_ERR("Eid format error: %s, errno:%u.", buf, errno);
        return -EINVAL;
    }
    return 0;
}

static int tpsa_init_netaddr_tbl(tpsa_netaddr_tbl_t *tbl)
{
    if (ub_hmap_init(&tbl->hmap, TPSA_NETADDR_TBL_SIZE) != 0) {
        TPSA_LOG_ERR("hmap init failed.\n");
        return -1;
    }
    (void)pthread_rwlock_init(&tbl->rwlock, NULL);
    return 0;
}

static void tpsa_uninit_netaddr_tbl(tpsa_netaddr_tbl_t *tbl)
{
    tpsa_netaddr_entry_t *cur, *next;

    (void)pthread_rwlock_wrlock(&tbl->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &tbl->hmap) {
        ub_hmap_remove(&tbl->hmap, &cur->node);
        free(cur);
    }
    (void)pthread_rwlock_unlock(&tbl->rwlock);
    ub_hmap_destroy(&tbl->hmap);
    (void)pthread_rwlock_destroy(&tbl->rwlock);
}

int tpsa_net_init(void)
{
    return tpsa_init_netaddr_tbl(&g_netaddr_tbl);
}

void tpsa_net_uninit(void)
{
    tpsa_uninit_netaddr_tbl(&g_netaddr_tbl);
}