#ifndef UMMU_API_H
#define UMMU_API_H

#include <stddef.h>
#include <stdint.h>

enum ummu_mapt_mode {
    MAPT_MODE_ENTRY = 0,
    MAPT_MODE_TABLE = 1,
};

enum ummu_mapt_perm {
    MAPT_PERM_R = 1,
    MAPT_PERM_RW = 2,
    MAPT_PERM_ATOMIC_RW = 3,
};

enum ummu_ebit_state {
    UMMU_EBIT_DISABLE = 0,
    UMMU_EBIT_ENABLE = 1,
};

struct ummu_tid_attr {
    enum ummu_mapt_mode mode;
};

struct ummu_token_info {
    uint32_t input;
    uint32_t tokenVal;
};

struct ummu_seg_attr {
    struct ummu_token_info *token;
    enum ummu_ebit_state e_bit;
    enum ummu_ebit_state p_bit;
};

int ummu_allocate_tid(struct ummu_tid_attr *tid_attr, uint32_t *tid);
int ummu_grant(uint32_t tid, void *data, size_t data_size,
               enum ummu_mapt_perm perm, struct ummu_seg_attr *seg_attr);
int ummu_ungrant(uint32_t tid, void *data, size_t size);
int ummu_ungrant_by_token(uint32_t tid, void *data, size_t size, uint32_t token_val);
int ummu_free_tid(uint32_t tid);

#endif
