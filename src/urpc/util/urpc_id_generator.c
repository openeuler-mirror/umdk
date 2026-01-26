/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc id generator
 */
#include "urpc_framework_errno.h"
#include "urpc_dbuf_stat.h"
#include "urpc_id_generator.h"

static void set_id_generator_ops(urpc_id_generator_t *generator, urpc_id_generator_type_e type);

int urpc_id_generator_init(urpc_id_generator_t *generator, urpc_id_generator_type_e type, unsigned size)
{
    set_id_generator_ops(generator, type);
    if (generator->init == NULL) {
        return -1;
    }
    return generator->init(generator, size);
}

void urpc_id_generator_uninit(urpc_id_generator_t *generator)
{
    if (generator->uninit == NULL) {
        return;
    }
    generator->uninit(generator);
}

int urpc_id_generator_alloc(urpc_id_generator_t *generator, unsigned int min, uint32_t *id)
{
    if (generator->alloc == NULL) {
        return -1;
    }
    return generator->alloc(generator, min, id);
}

void urpc_id_generator_free(urpc_id_generator_t *generator, uint32_t id)
{
    if (generator->free == NULL) {
        return;
    }
    generator->free(generator, id);
}

// bitmap id generator
typedef struct urpc_bitmap_id_generator {
    urpc_bitmap_t bitmap;
    unsigned cur;
    unsigned total;
    pthread_spinlock_t lock;
} urpc_bitmap_id_generator_t;

int urpc_bitmap_id_generator_init(urpc_id_generator_t *gen, unsigned size)
{
    gen->private_data = urpc_dbuf_calloc(URPC_DBUF_TYPE_UTIL, 1, sizeof(urpc_bitmap_id_generator_t));
    if (gen->private_data == NULL) {
        return -URPC_ERR_ENOMEM;
    }
    urpc_bitmap_id_generator_t *generator = (urpc_bitmap_id_generator_t *)gen->private_data;
    generator->bitmap = urpc_bitmap_alloc(size);
    if (generator->bitmap == NULL) {
        return -URPC_ERR_ENOMEM;
    }
    generator->total = size;
    generator->cur = 0;
    (void)pthread_spin_init(&generator->lock, PTHREAD_PROCESS_PRIVATE);
    return URPC_SUCCESS;
}

void urpc_bitmap_id_generator_uninit(urpc_id_generator_t *gen)
{
    urpc_bitmap_id_generator_t *generator = (urpc_bitmap_id_generator_t *)gen->private_data;
    if (generator != NULL && generator->bitmap != NULL) {
        (void)pthread_spin_destroy(&generator->lock);
        urpc_bitmap_free(generator->bitmap);
        urpc_dbuf_free(generator);
        gen->private_data = NULL;
    }
}

int urpc_bitmap_id_generator_alloc(urpc_id_generator_t *gen, unsigned int min, uint32_t *id)
{
    if ((int)min < 0) {
        return -ENOSPC;
    }

    urpc_bitmap_id_generator_t *generator = (urpc_bitmap_id_generator_t *)gen->private_data;
    unsigned int bit = min % generator->total;

    (void)pthread_spin_lock(&generator->lock);
    bit = (unsigned int)urpc_bitmap_find_next_zero_bit(generator->bitmap, generator->total, bit);
    if (bit >= generator->total) {
        (void)pthread_spin_unlock(&generator->lock);
        return -ENOSPC;
    }

    generator->cur = bit;
    urpc_bitmap_set(generator->bitmap, bit, true);
    (void)pthread_spin_unlock(&generator->lock);
    *id = bit;
    return 0;
}

int urpc_bitmap_id_generator_alloc_auto_inc(urpc_id_generator_t *gen, unsigned int min, uint32_t *id)
{
    if ((int)min < 0) {
        return -ENOSPC;
    }

    urpc_bitmap_id_generator_t *generator = (urpc_bitmap_id_generator_t *)gen->private_data;
    uint32_t min_bit = min % generator->total;
    uint32_t bit = min_bit < generator->cur ? generator->cur : min_bit;

    /* The search starts from MAX (min_bit, generator->cur).
     * If the ID is insufficient, the search starts again from min_bit. */
    (void)pthread_spin_lock(&generator->lock);
    bit = (unsigned int)urpc_bitmap_find_next_zero_bit(generator->bitmap, generator->total, bit);
    if (bit >= generator->total) {
        generator->cur = min_bit;
        bit = (unsigned int)urpc_bitmap_find_next_zero_bit(generator->bitmap, generator->total, generator->cur);
        if (bit >= generator->total) {
            (void)pthread_spin_unlock(&generator->lock);
            return -ENOSPC;
        }
    }
    generator->cur = bit;
    urpc_bitmap_set(generator->bitmap, bit, true);
    (void)pthread_spin_unlock(&generator->lock);
    *id = bit;
    return 0;
}

void urpc_bitmap_id_generator_free(urpc_id_generator_t *gen, uint32_t id)
{
    urpc_bitmap_id_generator_t *generator = (urpc_bitmap_id_generator_t *)gen->private_data;

    (void)pthread_spin_lock(&generator->lock);
    urpc_bitmap_set(generator->bitmap, id, false);
    (void)pthread_spin_unlock(&generator->lock);
}

static void set_id_generator_ops(urpc_id_generator_t *generator, urpc_id_generator_type_e type)
{
    if (type == URPC_ID_GENERATOR_TYPE_BITMAP) {
        generator->init = urpc_bitmap_id_generator_init;
        generator->uninit = urpc_bitmap_id_generator_uninit;
        generator->alloc = urpc_bitmap_id_generator_alloc;
        generator->free = urpc_bitmap_id_generator_free;
    } else if (type == URPC_ID_GENERATOR_TYPE_BITMAP_AUTO_INC) {
        generator->init = urpc_bitmap_id_generator_init;
        generator->uninit = urpc_bitmap_id_generator_uninit;
        generator->alloc = urpc_bitmap_id_generator_alloc_auto_inc;
        generator->free = urpc_bitmap_id_generator_free;
    }
}