/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: obmem impl realization
 * Create: 2025-9-11
 * Note:
 * History: 2025-9-11
 */

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "libobmm.h"
#include "umq_errno.h"
#include "umq_vlog.h"
#include "obmem_common.h"

#define MAX_NAME_LEN            64U
#define ADDR_MASK_4MB           (uint64_t)0x400000
#define OBMM_DEV_NAME_PREFIX    "/dev/obmm_shmdev"

struct ub_mem_priv_data {
    uint16_t one_pth : 1;
    uint16_t wr_delay_comp : 1;
    uint16_t reduce_delay_comp : 1;
    uint16_t cmo_delay_comp : 1;
    uint16_t so : 1;
    uint16_t ad_tr_ochip : 1;
    uint16_t cacheable_flag : 1;
    uint16_t mar_id : 3;
    uint16_t rsv0 : 6;
};

void *obmem_export_memory(obmem_export_memory_param_t *export_param, uint64_t *handle, obmem_export_info_t *exp)
{
    size_t size[OBMM_MAX_LOCAL_NUMA_NODES] = {0};
    void *ptr = NULL;
    mem_id memid = 0;
    int fd = 0;
    char dev_info[MAX_NAME_LEN] = {0};
    int ret = -1;
    uint32_t open_flag = 0;

    if (export_param->len == 0) {
        UMQ_VLOG_ERR("invalid input parameters, len=0\n");
        return NULL;
    }

    if ((export_param->len & (ADDR_MASK_4MB - 1)) != 0) {
        UMQ_VLOG_ERR("invalid input parameters, len[%lu byte] is not an integer multiple of unit size[%lu byte]\n",
            export_param->len, ADDR_MASK_4MB);
        return NULL;
    }

    if ((handle == NULL) || (exp == NULL)) {
        UMQ_VLOG_ERR("invalid input parameters, handle %s NULL, exp %s NULL\n", handle == NULL ? "is" : "not",
                     exp == NULL ? "is" : "not");
        return NULL;
    }

    size[0] = export_param->len; // Specify size of the memory
    struct obmm_mem_desc export_info = {0};
    (void)memcpy(export_info.deid, export_param->deid, OBMM_EID_LEN);
    memid = obmm_export(size, OBMM_EXPORT_FLAG_ALLOW_MMAP, &export_info);
    if (memid == OBMM_INVALID_MEMID) {
        UMQ_VLOG_ERR("[obmem_export_memory] fail to export obmm\n");
        return NULL;
    }

    (void)sprintf(dev_info, "%s%lu", OBMM_DEV_NAME_PREFIX, memid);
    open_flag = export_param->cacheable ? O_RDWR : O_RDWR | O_SYNC;
    fd = open(dev_info, open_flag);
    if (fd < 0) {
        UMQ_VLOG_ERR("[obmem_export_memory] fail to open obmem_export_memory, fd=%d\n", fd);
        goto UNEXPORT_OBMM;
    }

    ptr = mmap(NULL, export_param->len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        (void)close(fd);
        UMQ_VLOG_ERR("mmap failed, len: %lu errno: %d\n", export_param->len, errno);
        goto UNEXPORT_OBMM;
    }

    (void)close(fd);
    *handle = memid;
    exp->token_id = export_info.tokenid;
    exp->uba = export_info.addr;
    exp->size = export_info.length;

    return ptr;

UNEXPORT_OBMM:
    ret = obmm_unexport(memid, 0);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("release_share_memory failed, ret=%d\n", ret);
    } else {
        UMQ_VLOG_INFO("release_share_memory successful\n");
    }
    return NULL;
}

int obmem_release_export_memory(uint64_t handle, void *ptr, uint64_t len)
{
    int ret = UMQ_SUCCESS;
    unsigned long flags = 0;
    ret = munmap(ptr, len);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("munmap failed, ret=%d\n", ret);
    }

    ret = obmm_unexport(handle, flags);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("release_share_memory failed, ret=%d\n", ret);
    } else {
        UMQ_VLOG_INFO("release_share_memory successful\n");
    }

    return ret;
}

void *obmem_import_memory(obmem_import_memory_param_t *import_param, obmem_export_info_t *exp, uint64_t *handle)
{
    UMQ_VLOG_INFO("Enter obmem_import_memory\n");
    void *ptr = NULL;
    mem_id memid = 0;
    unsigned long flags = OBMM_IMPORT_FLAG_ALLOW_MMAP;
    int base_dist = 0;
    int numa = -1;
    int fd = 0;
    char dev_info[MAX_NAME_LEN] = {0};
    struct obmm_mem_desc *desc = NULL;
    uint32_t open_flag = 0;
    int ret = -1;

    if ((exp == NULL) || (handle == NULL)) {
        UMQ_VLOG_ERR("invalid input parameters, handle %s NULL, exp %s NULL\n", handle == NULL ? "is" : "not",
                     exp == NULL ? "is" : "not");
        return NULL;
    }

    if (import_param->import_cna == import_param->export_cna) {
        UMQ_VLOG_ERR("invalid input parameters, import_cna==export_cna(%d)\n", import_param->import_cna);
        return NULL;
    }

    uint32_t alloc_size = sizeof(struct obmm_mem_desc) + sizeof(struct ub_mem_priv_data);
    desc = (struct obmm_mem_desc *)calloc(1, alloc_size);
    if (desc == NULL) {
        UMQ_VLOG_ERR("calloc failed\n");
        return NULL;
    }
    desc->addr = exp->uba;
    desc->length = exp->size;
    desc->tokenid = exp->token_id;
    desc->scna = import_param->import_cna;
    desc->dcna = import_param->export_cna;
    desc->priv_len = sizeof(struct ub_mem_priv_data);
    (void)memcpy(desc->seid, import_param->seid, OBMM_EID_LEN);
    (void)memcpy(desc->deid, import_param->deid, OBMM_EID_LEN);

    struct ub_mem_priv_data *priv = (struct ub_mem_priv_data *)(desc->priv);
    priv->cacheable_flag = 1;
    priv->ad_tr_ochip = 1;

    memid = obmm_import(desc, flags, base_dist, &numa);
    if (memid == OBMM_INVALID_MEMID) {
        UMQ_VLOG_ERR("[obmem_import_memory] fail to import obmm\n");
        return NULL;
    }

    (void)sprintf(dev_info, "%s%lu", OBMM_DEV_NAME_PREFIX, memid);
    open_flag = import_param->cacheable ? O_RDWR : O_RDWR | O_SYNC;
    fd = open(dev_info, open_flag);
    if (fd < 0) {
        UMQ_VLOG_ERR("[obmem_import_memory] fail to open obmem_import_memory, fd=%d\n", fd);
        goto UNIMPORT_OBMM;
    }

    ptr = mmap(NULL, desc->length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        (void)close(fd);
        UMQ_VLOG_ERR("mmap failed, len: %lu errno: %d\n", desc->length, errno);
        goto UNIMPORT_OBMM;
    }

    *handle = memid;

    (void)close(fd);
    free(desc);
    return ptr;

UNIMPORT_OBMM:
    ret = obmm_unimport(*handle, 0);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("release_share_memory failed, ret=%d\n", ret);
    } else {
        UMQ_VLOG_INFO("release_share_memory successful\n");
    }
    return NULL;
}

int obmem_release_import_memory(uint64_t handle, void *ptr, uint64_t len)
{
    int ret = UMQ_SUCCESS;
    unsigned long flags = 0;
    ret = munmap(ptr, len);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("munmap failed, ret=%d\n", ret);
    }

    ret = obmm_unimport(handle, flags);
    if (ret != UMQ_SUCCESS) {
        UMQ_VLOG_ERR("withdraw_share_memory failed, ret=%d\n", ret);
    } else {
        UMQ_VLOG_DEBUG("withdraw_share_memory successful\n");
    }

    return ret;
}