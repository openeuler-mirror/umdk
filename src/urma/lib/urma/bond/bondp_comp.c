/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Implementation of Bonding Component
 * Author: Ma Chuan
 * Create: 2025-02-12
 * Note:
 * History: 2025-02-12  Create file
 */
#include "urma_log.h"
#include "urma_api.h"
#include "urma_cmd.h"
#include "urma_provider.h"
#include "bondp_comp.h"

// table ops no lock, caller needs to ensure concurrency safety
bdp_vjfce_info_t *bdp_vjfce_info_table_lookup(bondp_hash_table_t *tbl, int key)
{
    bdp_vjfce_info_t *target = NULL;
    HMAP_FIND_INNER(&tbl->hmap, &key, sizeof(key), target);
    return target;
}

int bdp_vjfce_info_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, NULL, NULL, NULL);
}

int bdp_vjfce_info_table_add(bondp_hash_table_t *tbl, bdp_vjfce_info_t *node)
{
    if (bdp_vjfce_info_table_lookup(tbl, node->key) != NULL) {
        URMA_LOG_ERR("exist node in map.\n");
        return -EEXIST;
    }

    bdp_vjfce_info_t *tmp = calloc(1, sizeof(bdp_vjfce_info_t));
    if (tmp == NULL) {
        return -ENOMEM;
    }
    tmp->key = node->key;
    tmp->p_jfce = node->p_jfce;

    HMAP_INSERT_INNER(&tbl->hmap, tmp, &tmp->key, sizeof(tmp->key));
    URMA_LOG_DEBUG("Success add entry, fd:%d.\n", node->key);

    return 0;
}

void bdp_vjfce_info_table_del(bondp_hash_table_t *tbl, int key)
{
    bdp_vjfce_info_t *target = bdp_vjfce_info_table_lookup(tbl, key);
    if (target == NULL) {
        return;
    }

    ub_hmap_remove(&tbl->hmap, &target->node);
    URMA_LOG_DEBUG("Success del entry, fd:%d.\n", key);
    free(target);
}

void bdp_vjfce_info_table_close_fd(bondp_comp_t *bdp_comp)
{
    int ret = URMA_SUCCESS;
    bondp_hash_table_t *tbl = (bondp_hash_table_t *)bdp_comp->comp_ctx;
    if (!tbl) {
        return;
    }
    bdp_vjfce_info_t *next = NULL;
    bdp_vjfce_info_t *cur = NULL;
    struct epoll_event ev = {0};
    HMAP_FOR_EACH_SAFE(cur, next, node, &tbl->hmap) {
        // ensure the fd of pjfce is valid before this epoll_ctl
        ret = epoll_ctl(bdp_comp->v_jfce.fd, EPOLL_CTL_DEL, cur->key, &ev);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_WARN("non-zero return value of EPOLL_CTL_DEL, ret = %d.\n", ret);
        }
    }

    close(bdp_comp->v_jfce.fd);
}

void bdp_vjfce_info_table_destroy(bondp_hash_table_t *tbl)
{
    bdp_vjfce_info_t *cur = NULL;
    bdp_vjfce_info_t *next = NULL;
    (void)pthread_rwlock_wrlock(&tbl->lock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &tbl->hmap) {
        ub_hmap_remove(&tbl->hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&tbl->hmap);
    (void)pthread_rwlock_unlock(&tbl->lock);
    (void)pthread_rwlock_destroy(&tbl->lock);
}

int bondp_insert_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce)
{
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = p_jfce->fd;
    if (epoll_ctl(v_jfce->fd, EPOLL_CTL_ADD, p_jfce->fd, &ev) != 0) {
        URMA_LOG_ERR("Fail to add fd:%d to epoll fd:%d.\n", p_jfce->fd, v_jfce->fd);
        return URMA_FAIL;
    }
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(v_jfce, bondp_comp_t, base);
    bdp_vjfce_info_t info = {
        .key = p_jfce->fd,
        .p_jfce = p_jfce,
    };
    bondp_hash_table_t *v_jfce_table = (bondp_hash_table_t *)bdp_comp->comp_ctx;
    (void)pthread_rwlock_wrlock(&v_jfce_table->lock);
    int ret = bdp_vjfce_info_table_add((bondp_hash_table_t *)bdp_comp->comp_ctx, &info);
    (void)pthread_rwlock_unlock(&v_jfce_table->lock);
    return ret;
}

void bondp_remove_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce)
{
    struct epoll_event ev = {0};
    if (epoll_ctl(v_jfce->fd, EPOLL_CTL_DEL, p_jfce->fd, &ev) != 0) {
        URMA_LOG_ERR("Fail to del fd:%d to epoll fd:%d.\n", p_jfce->fd, v_jfce->fd);
    }
    bondp_comp_t *bdp_comp = CONTAINER_OF_FIELD(v_jfce, bondp_comp_t, base);
    bondp_hash_table_t *v_jfce_table = (bondp_hash_table_t *)bdp_comp->comp_ctx;

    (void)pthread_rwlock_wrlock(&v_jfce_table->lock);
    bdp_vjfce_info_table_del((bondp_hash_table_t *)bdp_comp->comp_ctx, p_jfce->fd);
    (void)pthread_rwlock_unlock(&v_jfce_table->lock);
}
