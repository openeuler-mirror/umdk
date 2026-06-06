/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_cipher.cpp
 * Description   : dlock cipher class implemention
 * History       : create file & add functions
 * 1.Date        : 2022-09-20
 * Author        : wujie
 * Modification  : Created file
 */

#include <atomic>
#include <cstring>

#include "dlock_log.h"
#include "dlock_cipher.h"

namespace dlock {
dlock_cipher::dlock_cipher() noexcept
    : m_key(nullptr), m_ctx(nullptr), m_data_offset(0), m_cipher(nullptr)
{
    DLOCK_LOG_DEBUG("dlock cipher construct");
}

dlock_cipher::~dlock_cipher()
{
    uint32_t dlock_key_size = sizeof(struct dlock_key) + sizeof(unsigned char) * AES_KEY_BYTES;
    cipher_deinit();
    if (m_key != nullptr) {
        static_cast<void>(memset(m_key, 0, dlock_key_size));
        free(m_key);
        m_key = nullptr;
        DLOCK_LOG_INFO("data plane key deleted");
    }
    DLOCK_LOG_DEBUG("dlock cipher deconstruct");
}

dlock_status_t dlock_cipher::cipher_init(unsigned int key_len)
{
    uint32_t dlock_key_size = sizeof(struct dlock_key) + sizeof(unsigned char) * key_len;
    m_key = (struct dlock_key *)malloc(dlock_key_size);
    if (m_key == nullptr) {
        DLOCK_LOG_ERR("malloc dlock key failed");
        return DLOCK_ENOMEM;
    }
    static_cast<void>(memset(m_key, 0, dlock_key_size));
    m_key->key = reinterpret_cast<unsigned char *>(m_key) + sizeof(struct dlock_key);
    m_key->key_len = key_len;

    m_ctx = EVP_CIPHER_CTX_new();
    if (m_ctx == nullptr) {
        DLOCK_LOG_ERR("new cipher cxt failed");
        return DLOCK_FAIL;
    }

    m_cipher = EVP_aes_256_gcm(); // only aes_256_gcm now
    DLOCK_LOG_DEBUG("cipher cxt created");
    return DLOCK_SUCCESS;
}

void dlock_cipher::cipher_deinit() const
{
    if (m_ctx != nullptr) {
        EVP_CIPHER_CTX_free(m_ctx);
    }
    DLOCK_LOG_DEBUG("cipher cxt destroyed");
}

bool dlock_cipher::check_cipher_op_param(int op_type, const unsigned char *out, const int *out_len,
    const unsigned char *in, int in_len) const
{
    int block_size;

    if ((op_type != static_cast<int>(ENCRYPTION)) && (op_type != static_cast<int>(DECRYPTION))) {
        DLOCK_LOG_ERR("invalid cipher op type %d", op_type);
        return false;
    }
    if ((out == nullptr) || (out_len == nullptr) || (in == nullptr)) {
        DLOCK_LOG_ERR("invalid buffer params to be ciphered, pointer nullptr");
        return false;
    }
    if ((in_len <= 0) || ((static_cast<unsigned int>(in_len) + AES_EXTRA_LEN - m_data_offset) > URMA_MTU)) {
        DLOCK_LOG_ERR("invalid buffer len to be ciphered");
        return false;
    }
    if ((m_key->key == nullptr) || (m_key->key_len != AES_KEY_BYTES)) {
        DLOCK_LOG_ERR("invalid key");
        return false;
    }
    block_size = EVP_CIPHER_block_size(m_cipher);
    if (block_size != 1) {
        DLOCK_LOG_DEBUG("unexpected block_size:%d, op_type:%d", block_size, op_type);
    }

    return true;
}

/* Acording to NIST, there are two ways to generate iv, Deterministic Construction
*  and RBG-based Construction. We choose the former one, which behaves better
*  performance. RGB like RAND_priv_bytes will bring 100us+ cost.
*/
dlock_status_t dlock_cipher::iv_gen(unsigned char *iv, size_t iv_len) const
{
    static std::atomic<uint32_t> seed(1);
    static thread_local uint32_t fixed_field = 0; // thread unique
    static thread_local uint64_t counter = 0;

    /* fixed field, enough to identify the context for the instance of
    * the authenticated encryption function.
    */
    if (fixed_field == 0u) {
        fixed_field = seed.fetch_add(1, std::memory_order_relaxed);
    }
    if (sizeof(fixed_field) > iv_len) {
        DLOCK_LOG_ERR("IV generation failed, fixed_field length exceeds the limit.");
        return DLOCK_FAIL;
    }
    static_cast<void>(memcpy(iv, &fixed_field, sizeof(fixed_field)));

    // invocation field, usually implemented as counter
    ++counter;
    if (sizeof(counter) > (iv_len - sizeof(fixed_field))) {
        DLOCK_LOG_ERR("IV generation failed, counter length exceeds the limit.");
        return DLOCK_FAIL;
    }
    static_cast<void>(memcpy(iv + sizeof(fixed_field), &counter, sizeof(counter)));

    return DLOCK_SUCCESS;
}

dlock_status_t dlock_cipher::iv_get(int op_type, const unsigned char *in, unsigned char *out,
    const unsigned char **iv, size_t iv_len) const
{
    dlock_status_t ret = DLOCK_SUCCESS;

    if (op_type == static_cast<int>(ENCRYPTION)) {
        ret = iv_gen(out, iv_len);
        if (ret != DLOCK_SUCCESS) {
            return ret;
        }
	*iv = out;
    } else {
        *iv = in;
    }
    return ret;
}

// As we use API suite EVP_Cipher*, Enc and Dec ops take the same API
dlock_status_t dlock_cipher::cipher_op(int op_type, unsigned char *out, int *out_len,
    const unsigned char *in, int in_len) const
{
    dlock_status_t ret = DLOCK_SUCCESS;
    const unsigned char *iv;
    int padding_len = 0;

    if (!check_cipher_op_param(op_type, out, out_len, in, in_len)) {
        ret = DLOCK_EINVAL;
        goto err;
    }
    ret = iv_get(op_type, in, out, &iv, AES_IV_LEN);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Cipher get iv failed: %d", static_cast<int>(ret));
        goto err;
    }
    if (EVP_CipherInit_ex(m_ctx, m_cipher, nullptr, m_key->key, iv, op_type) == 0) {
        ret = DLOCK_FAIL;
        DLOCK_LOG_ERR("Cipher init failed: %d", op_type);
        goto err;
    }
    *out_len = 0;
    if (EVP_CipherUpdate(m_ctx, out + AES_EXTRA_LEN, out_len, in + m_data_offset,
        in_len - static_cast<int>(m_data_offset)) != 1) {
        ret = DLOCK_FAIL;
        goto err;
    }
    if (op_type == ENCRYPTION) {
        /* As default block size is 1 for EVP_aes_256_gcm(), EVP_CipherFinal will not add any padding.
        *  Call EVP_CipherFinal_ex only for TAG verification
        */
        if ((EVP_CipherFinal_ex(m_ctx, out + AES_EXTRA_LEN + (*out_len), &padding_len) != 1) || (padding_len != 0)) {
            ret = DLOCK_FAIL;
            DLOCK_LOG_ERR("Cipher final failed");
            goto err;
        }
        if (EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, out + AES_IV_LEN) != 1) {
            ret = DLOCK_FAIL;
            DLOCK_LOG_ERR("Cipher get tag failed");
            goto err;
        }
    } else {
        if (EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
            const_cast<unsigned char *>(in) + AES_IV_LEN) != 1) {
            ret = DLOCK_FAIL;
            DLOCK_LOG_ERR("Cipher set tag failed");
            goto err;
        }
        if ((EVP_CipherFinal_ex(m_ctx, out + AES_EXTRA_LEN + (*out_len), &padding_len) != 1) || (padding_len != 0)) {
            ret = DLOCK_FAIL;
            DLOCK_LOG_ERR("Cipher final failed");
            goto err;
        }
    }

    return DLOCK_SUCCESS;
err:
    if (EVP_CIPHER_CTX_reset(m_ctx) == 0) {
        EVP_CIPHER_CTX_free(m_ctx);
    }
    return ret;
}

dlock_status_t dlock_cipher::secure_rand_gen(unsigned char *rand_key, unsigned int key_len) const
{
    int ret;

    if (key_len != AES_KEY_BYTES) {
        DLOCK_LOG_ERR("Invalid key len for rand num generation");
        return DLOCK_EINVAL;
    }
    ret = RAND_priv_bytes(rand_key, static_cast<int>(key_len));
    if (ret != 1) {
        DLOCK_LOG_ERR("Random num generation failed, return: %d", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}
}
