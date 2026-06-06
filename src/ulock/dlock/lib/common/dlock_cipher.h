/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_cipher.h
 * Description   : dlock cipher class header
 * History       : create file & add functions
 * 1.Date        : 2022-09-20
 * Author        : wujie
 * Modification  : Created file
 */

#ifndef __DLOCK_CIPHER_H__
#define __DLOCK_CIPHER_H__

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "dlock_types.h"
#include "dlock_common.h"

namespace dlock {
constexpr unsigned int AES_KEY_BYTES = 32;
constexpr unsigned int AES_IV_LEN = 12;
constexpr unsigned int AES_GCM_TAG_LEN = 16;
constexpr unsigned int AES_EXTRA_LEN = AES_IV_LEN + AES_GCM_TAG_LEN;

struct dlock_key {
    unsigned char *key;
    unsigned int key_len;
};

class dlock_cipher {
    friend class jetty_mgr;
public:
    dlock_cipher() noexcept;
    ~dlock_cipher();

    dlock_status_t cipher_init(unsigned int key_len);
    void cipher_deinit() const;
    bool check_cipher_op_param(int op_type, const unsigned char *out, const int *out_len,
        const unsigned char *in, int in_len) const;
    dlock_status_t cipher_op(int op_type, unsigned char *out, int *out_len,
        const unsigned char *in, int in_len) const; // both encryption and decryption use this function
    dlock_status_t secure_rand_gen(unsigned char *rand_key, unsigned int key_len) const;
    struct dlock_key *m_key;
    EVP_CIPHER_CTX *m_ctx;
    /* m_data_offset is the start offset of actual msg */
    unsigned int m_data_offset;
private:
    dlock_status_t iv_gen(unsigned char *iv, size_t iv_len) const;
    dlock_status_t iv_get(int op_type, const unsigned char *in, unsigned char *out,
                          const unsigned char **iv, size_t iv_len) const;
    const EVP_CIPHER *m_cipher;
};

enum cipher_op_type {
    DECRYPTION = 0, // 1 for encryption, 0 for decryption, -1 not allowed in dlock now
    ENCRYPTION,
};
};
#endif
