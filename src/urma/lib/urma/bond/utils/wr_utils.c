/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider WR utils implementation
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21
 */
#include <stdlib.h>
#include "urma_log.h"
#include "wr_utils.h"
/**
 * Not responsible for memory allocation of `sge`
 * Do not copy the user_tseg field, as this capability is not supported on the new generation.
 * However, we should provide a warning for this.
 */
static int deepcopy_sge(urma_sge_t *dst, const urma_sge_t *src)
{
    if (dst == NULL || src == NULL) {
        URMA_LOG_ERR("Invalid sge pointer, dst or src is NULL.\n");
        return -1;
    }
    if (src->user_tseg != NULL) {
        URMA_LOG_WARN("Does not support deep copy of the user_tseg field.\n");
    }
    *dst = *src;
    dst->user_tseg = NULL;
    return 0;
}

static void delete_copied_sge(urma_sge_t *sge)
{
    if (sge == NULL) {
        return;
    }
    free(sge);
}
/**
 * Does not handle `sg` memory allocation but may allocate space for internal `sge`.
 */
static int deepcopy_sg(urma_sg_t *dst, const urma_sg_t *src, bool add_hdr)
{
    if (dst == NULL || src == NULL) {
        URMA_LOG_ERR("Invalid sg pointer, dst or src is NULL.\n");
        return -1;
    }
    int num_sge = add_hdr ? (src->num_sge + 1) : src->num_sge;
    int sge_copy_offset = add_hdr ? 1 : 0;
    if (num_sge < 0) {
        URMA_LOG_ERR("Invalid num_sge: %d\n", num_sge);
        return -1;
    } else if (num_sge == 0) {
        dst->sge = NULL;
        dst->num_sge = 0;
        return 0;
    }
    dst->sge = (urma_sge_t *)malloc(num_sge * sizeof(urma_sge_t));
    if (dst->sge == NULL) {
        URMA_LOG_ERR("Failed to alloc dst sge\n");
        return -1;
    }
    for (int i = 0; i < src->num_sge; ++i) {
        if (deepcopy_sge(&dst->sge[sge_copy_offset + i], &src->sge[i])) {
            free(dst->sge);
            dst->sge = NULL;
            return -1;
        }
    }
    dst->num_sge = num_sge;
    return 0;
}
/**
 * The sg is not an allocated pointer; it is a part of the WR, so we do not need to release this pointer.
 * We only need to release the sge that has been copied within it.
 */
static inline void delete_copied_sg(urma_sg_t *sg)
{
    if (sg == NULL) {
        return;
    }
    if (sg->sge) {
        free(sg->sge);
        sg->sge = NULL;
    }
}

static int deepcopy_cas_wr(urma_cas_wr_t *new_wr_cas, const urma_cas_wr_t *old_wr_cas)
{
    new_wr_cas->dst = (urma_sge_t *)malloc(sizeof(urma_sge_t));
    if (new_wr_cas->dst == NULL) {
        URMA_LOG_ERR("Failed to alloc new_wr_cas->dst\n");
        return -1;
    }
    if (deepcopy_sge(new_wr_cas->dst, old_wr_cas->dst)) {
        URMA_LOG_ERR("Failed to deepcopy dst sge\n");
        goto FREE_DST;
    }

    new_wr_cas->src = (urma_sge_t *)malloc(sizeof(urma_sge_t));
    if (new_wr_cas->src == NULL) {
        URMA_LOG_ERR("Failed to alloc new_wr_cas->src\n");
        goto FREE_DST;
    }
    if (deepcopy_sge(new_wr_cas->src, old_wr_cas->src)) {
        URMA_LOG_ERR("Failed to copy src sge\n");
        goto FREE_SRC;
    }

    new_wr_cas->cmp_data = old_wr_cas->cmp_data;
    new_wr_cas->swap_data = old_wr_cas->swap_data;
    return 0;
FREE_SRC:
    free(new_wr_cas->src);
    new_wr_cas->src = NULL;
FREE_DST:
    free(new_wr_cas->dst);
    new_wr_cas->dst = NULL;
    return -1;
}

static int deepcopy_faa_wr(urma_faa_wr_t *new_wr_faa, const urma_faa_wr_t *old_wr_faa)
{
    new_wr_faa->dst = (urma_sge_t *)malloc(sizeof(urma_sge_t));
    if (new_wr_faa->dst == NULL) {
        URMA_LOG_ERR("Failed to alloc new_wr_faa->dst\n");
        return -1;
    }
    if (deepcopy_sge(new_wr_faa->dst, old_wr_faa->dst)) {
        URMA_LOG_ERR("Failed to deepcopy dst sge\n");
        goto FREE_DST;
    }
    
    new_wr_faa->src = (urma_sge_t *)malloc(sizeof(urma_sge_t));
    if (new_wr_faa->src == NULL) {
        URMA_LOG_ERR("Failed to alloc new_wr_faa->src\n");
        goto FREE_DST;
    }
    if (deepcopy_sge(new_wr_faa->src, old_wr_faa->src)) {
        URMA_LOG_ERR("Failed to deepcopy src sge\n");
        goto FREE_SRC;
    }
    
    new_wr_faa->operand = old_wr_faa->operand;
    return 0;
FREE_SRC:
    free(new_wr_faa->src);
    new_wr_faa->src = NULL;
FREE_DST:
    free(new_wr_faa->dst);
    new_wr_faa->dst = NULL;
    return -1;
}

// Doesn't deepcopy next pointer and tjetty
// Next pointer will be set to NULL
// tjetty will be the same as the input
static urma_jfs_wr_t *deepcopy_jfs_wr_node(const urma_jfs_wr_t *wr, bool add_hdr)
{
    urma_jfs_wr_t *new_wr = (urma_jfs_wr_t *)malloc(sizeof(urma_jfs_wr_t));
    if (new_wr == NULL) {
        URMA_LOG_ERR("Malloc wr failed\n");
        return NULL;
    }
    *new_wr = *wr;
    new_wr->next = NULL;
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            if (deepcopy_sg(&new_wr->send.src, &wr->send.src, add_hdr)) {
                URMA_LOG_ERR("Deepcopy sg failed\n");
                goto FREE_NEW_WR;
            }
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            if (deepcopy_sg(&new_wr->rw.src, &wr->rw.src, add_hdr)) {
                URMA_LOG_ERR("Deepcopy src sg failed\n");
                goto FREE_NEW_WR;
            }
            if (deepcopy_sg(&new_wr->rw.dst, &wr->rw.dst, add_hdr)) {
                URMA_LOG_ERR("Deepcopy dst sg failed\n");
                delete_copied_sg(&new_wr->rw.src);
                goto FREE_NEW_WR;
            }
            break;
        case URMA_OPC_CAS:
            if (deepcopy_cas_wr(&new_wr->cas, &wr->cas)) {
                URMA_LOG_ERR("Deepcopy cas failed\n");
                goto FREE_NEW_WR;
            }
            break;
        case URMA_OPC_FADD:
            if (deepcopy_faa_wr(&new_wr->faa, &wr->faa)) {
                URMA_LOG_ERR("Deepcopy faa failed\n");
                goto FREE_NEW_WR;
            }
            break;
        default:
            URMA_LOG_ERR("Not support opcode %d\n", wr->opcode);
            goto FREE_NEW_WR;
    }
    return new_wr;
FREE_NEW_WR:
    free(new_wr);
    return NULL;
}

static int delete_copied_jfs_wr_node(urma_jfs_wr_t *wr)
{
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            delete_copied_sg(&wr->send.src);
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            delete_copied_sg(&wr->rw.dst);
            delete_copied_sg(&wr->rw.src);
            break;
        case URMA_OPC_CAS:
            delete_copied_sge(wr->cas.src);
            delete_copied_sge(wr->cas.dst);
            break;
        case URMA_OPC_FADD:
            delete_copied_sge(wr->faa.src);
            delete_copied_sge(wr->faa.dst);
            break;
        default:
            URMA_LOG_ERR("Not support opcode %d\n", wr->opcode);
            return -1;
    }
    free(wr);
    return 0;
}

static urma_jfs_wr_t *deepcopy_jfs_wr_inner(const urma_jfs_wr_t *wr, bool add_hdr)
{
    const urma_jfs_wr_t *current;
    urma_jfs_wr_t *new_current;
    urma_jfs_wr_t *new_wr_head;
    urma_jfs_wr_t *new_wr;

    if (wr == NULL) {
        URMA_LOG_ERR("Invalid jfs wr to deepcopy\n");
        return NULL;
    }
    new_wr_head = deepcopy_jfs_wr_node(wr, add_hdr);
    if (new_wr_head == NULL) {
        return NULL;
    }
    current = wr->next;
    new_current = new_wr_head;
    while (current != NULL) {
        new_wr = deepcopy_jfs_wr_node(current, add_hdr);
        if (new_wr == NULL) {
            URMA_LOG_ERR("Failed to copy in wr->next");
            delete_copied_jfs_wr(new_wr_head);
            return NULL;
        }
        new_current->next = new_wr;
        new_current = new_wr;
        current = current->next;
    }
    return new_wr_head;
}

urma_jfs_wr_t *deepcopy_jfs_wr(const urma_jfs_wr_t *wr)
{
    return deepcopy_jfs_wr_inner(wr, false);
}

urma_jfs_wr_t *deepcopy_jfs_wr_and_add_hdr_sge(const urma_jfs_wr_t *wr)
{
    return deepcopy_jfs_wr_inner(wr, true);
}

int delete_copied_jfs_wr(urma_jfs_wr_t *wr)
{
    urma_jfs_wr_t *current;
    urma_jfs_wr_t *next;

    if (wr == NULL) {
        URMA_LOG_ERR("Invalid jfs wr to delete\n");
        return -1;
    }
    current = wr;
    while (current != NULL) {
        next = current->next;
        if (delete_copied_jfs_wr_node(current)) {
            return -1;
        }
        current = next;
    }
    return 0;
}
// Doesn't deepcopy next pointer
// Next pointer will be set to NULL
static urma_jfr_wr_t *deepcopy_jfr_wr_node(const urma_jfr_wr_t *wr, bool add_hdr)
{
    urma_jfr_wr_t *new_wr = (urma_jfr_wr_t *)malloc(sizeof(urma_jfr_wr_t));
    if (new_wr == NULL) {
        URMA_LOG_ERR("Malloc wr failed\n");
        return NULL;
    }
    new_wr->user_ctx = wr->user_ctx;
    new_wr->next = NULL;
    if (deepcopy_sg(&new_wr->src, &wr->src, add_hdr)) {
        URMA_LOG_ERR("Deepcopy sg failed\n");
        free(new_wr);
        return NULL;
    }
    return new_wr;
}

void delete_copied_jfr_wr_node(urma_jfr_wr_t * wr)
{
    if (wr == NULL) {
        URMA_LOG_ERR("Invalid jfr wr to delete\n");
        return;
    }
    delete_copied_sg(&wr->src);
    free(wr);
}

static urma_jfr_wr_t *deepcopy_jfr_wr_inner(const urma_jfr_wr_t *wr, bool add_hdr)
{
    const urma_jfr_wr_t *current;
    urma_jfr_wr_t *new_current;
    urma_jfr_wr_t *new_wr_head;
    urma_jfr_wr_t *new_wr;

    if (wr == NULL) {
        URMA_LOG_ERR("Invalid jfr wr to deepcopy\n");
        return NULL;
    }
    new_wr_head = deepcopy_jfr_wr_node(wr, add_hdr);
    if (new_wr_head == NULL) {
        return NULL;
    }
    current = wr->next;
    new_current = new_wr_head;
    while (current != NULL) {
        new_wr = deepcopy_jfr_wr_node(current, add_hdr);
        if (new_wr == NULL) {
            URMA_LOG_ERR("Failed to copy in wr->next");
            delete_copied_jfr_wr(new_wr_head);
            return NULL;
        }
        new_current->next = new_wr;
        new_current = new_wr;
        current = current->next;
    }
    return new_wr_head;
}

urma_jfr_wr_t *deepcopy_jfr_wr(const urma_jfr_wr_t *wr)
{
    return deepcopy_jfr_wr_inner(wr, false);
}

urma_jfr_wr_t *deepcopy_jfr_wr_and_add_hdr_sge(const urma_jfr_wr_t *wr)
{
    return deepcopy_jfr_wr_inner(wr, true);
}

int delete_copied_jfr_wr(urma_jfr_wr_t * wr)
{
    urma_jfr_wr_t *current;
    urma_jfr_wr_t *next;

    if (wr == NULL) {
        URMA_LOG_ERR("Invalid jfr wr to delete\n");
        return -1;
    }
    current = wr;
    while (current != NULL) {
        next = current->next;
        delete_copied_jfr_wr_node(current);
        current = next;
    }
    return 0;
}