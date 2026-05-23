/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : ssl_connection.cpp
 * Description   : SSL connection module
 * History       : create file & add functions
 * 1.Date        : 2022-09-15
 * Author        : huying
 * Modification  : Created file
 */

#include <cstdlib>
#include <string>
#include <fcntl.h>
#include <sys/time.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "utils.h"
#include "dlock_log.h"
#include "dlock_types.h"
#include "dlock_common.h"
#include "ssl_connection.h"

namespace dlock {
static const int PRKEY_PWD_MAX_LEN = 64;

ssl_connection::ssl_connection(int sockfd)
    : dlock_connection(), m_sockfd(sockfd), m_ssl_ctx(nullptr), m_ssl(nullptr),
      m_cert_verify_cb(nullptr), m_prkey_pwd_cb(nullptr), m_erase_prkey_cb(nullptr),
      m_socket_timeout(CONTROL_SOCKET_TIMEOUT)
{
    DLOCK_LOG_DEBUG("ssl_connection construct");
}

ssl_connection::~ssl_connection()
{
    DLOCK_LOG_DEBUG("ssl_connection deconstruct");
    if (m_ssl != nullptr) {
        static_cast<void>(SSL_shutdown(m_ssl));
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }

    if (m_sockfd > 0) {
        static_cast<void>(close(m_sockfd));
        m_sockfd = -1;
    }

    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
    }

    if (m_cert_verify_cb != nullptr) {
        m_cert_verify_cb = nullptr;
    }

    if (m_prkey_pwd_cb != nullptr) {
        m_prkey_pwd_cb = nullptr;
    }

    if (m_erase_prkey_cb != nullptr) {
        m_erase_prkey_cb = nullptr;
    }
}

static inline bool ssl_error_syscall_with_eagain(int sslError)
{
    return ((sslError == SSL_ERROR_SYSCALL) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)));
}

static inline bool ssl_r_unexpected_eof_while_reading(int sslError)
{
    /* openssl version >= OpenSSL 3.0.0 or openssl version == OpenSSL 1.1.1e */
#if ((OPENSSL_VERSION_NUMBER >= 0x30000000L) || (OPENSSL_VERSION_NUMBER == 0x1010105fL))
    unsigned long ec = ERR_peek_last_error();
    return ((sslError == SSL_ERROR_SSL) && (ERR_GET_REASON(ec) == SSL_R_UNEXPECTED_EOF_WHILE_READING));
#else
    return ((sslError == SSL_ERROR_SYSCALL) && (ERR_peek_last_error() == 0u));
#endif
}

bool ssl_connection::check_if_socket_timeout(const struct timeval &tv_start) const
{
    struct timeval tv_cur;
    double time_dif;

    static_cast<void>(gettimeofday(&tv_cur, nullptr));
    time_dif = (static_cast<double>(tv_cur.tv_usec - tv_start.tv_usec) / ONE_MILLION) +
        (tv_cur.tv_sec - tv_start.tv_sec);
    if (time_dif > static_cast<double>(m_socket_timeout)) {
        return true;
    }

    return false;
}

ssize_t ssl_connection::non_blocking_send(const void *buf, size_t len)
{
    int length = static_cast<int>(len);
    int ret = SSL_write(m_ssl, buf, length);
    int n_ret = SSL_get_error(m_ssl, ret);
    if (n_ret == SSL_ERROR_NONE) {
        return static_cast<ssize_t>(ret);
    }

    if ((n_ret == SSL_ERROR_WANT_WRITE) || ssl_error_syscall_with_eagain(n_ret)) {
        errno = EAGAIN;
        return -1;
    }

    if (n_ret == SSL_ERROR_ZERO_RETURN) {
        DLOCK_LOG_ERR("the SSL peer has closed the connection");
        return -1;
    }

    DLOCK_LOG_ERR("SSL_read failed! ret: %d, SSL_get_error: %d", ret, n_ret);
    return -1;
}

ssize_t ssl_connection::blocking_send(const void *buf, size_t len)
{
    int length = static_cast<int>(len);
    struct timeval tv_start;
    int ret;
    int n_ret;

    static_cast<void>(gettimeofday(&tv_start, nullptr));
    while (length > 0) {
        ret = SSL_write(m_ssl, buf, length);
        n_ret = SSL_get_error(m_ssl, ret);
        if (n_ret == SSL_ERROR_NONE) {
            length -= ret;
            buf = static_cast<char *>(const_cast<void *>(buf)) + ret;
            continue;
        }

        if ((n_ret == SSL_ERROR_WANT_WRITE) || ssl_error_syscall_with_eagain(n_ret)) {
            if (check_if_socket_timeout(tv_start)) {
                errno = EAGAIN;
                return -1;
            }
            continue;
        }

        if (n_ret == SSL_ERROR_ZERO_RETURN) {
            DLOCK_LOG_ERR("the SSL peer has closed the connection");
            return -1;
        }

        DLOCK_LOG_ERR("SSL_write() failed! ret: %d, SSL_get_error: %d", ret, n_ret);
        return -1;
    }

    return static_cast<ssize_t>(len);
}

ssize_t ssl_connection::send(const void *buf, size_t len, int flags)
{
    if (buf == nullptr || len == 0u || m_ssl == nullptr) {
        DLOCK_LOG_ERR("invalid SSL send parameter");
        return -1;
    }

    if ((static_cast<unsigned int>(flags) & static_cast<unsigned int>(MSG_DONTWAIT)) != 0) {
        return non_blocking_send(buf, len);
    }

    return blocking_send(buf, len);
}

ssize_t ssl_connection::non_blocking_recv(void *buf, size_t len)
{
    int length = static_cast<int>(len);
    int ret = SSL_read(m_ssl, buf, length);
    int n_ret = SSL_get_error(m_ssl, ret);
    if (n_ret == SSL_ERROR_NONE) {
        return static_cast<ssize_t>(ret);
    }

    if ((n_ret == SSL_ERROR_WANT_READ) || ssl_error_syscall_with_eagain(n_ret)) {
        errno = EAGAIN;
        return -1;
    }

    if (n_ret == SSL_ERROR_ZERO_RETURN) {
        DLOCK_LOG_ERR("the SSL peer has closed the connection");
        return 0;
    }

    if (ssl_r_unexpected_eof_while_reading(n_ret)) {
        DLOCK_LOG_ERR("non-blocking recv gets unexpected EOF from SSL peer while reading");
        return 0;
    }

    DLOCK_LOG_ERR("SSL_read failed! ret: %d, SSL_get_error: %d", ret, n_ret);
    return -1;
}

ssize_t ssl_connection::blocking_recv(void *buf, size_t len)
{
    int length = static_cast<int>(len);
    struct timeval tv_start;
    int ret;
    int n_ret;

    static_cast<void>(gettimeofday(&tv_start, nullptr));
    while (length > 0) {
        ret = SSL_read(m_ssl, buf, length);
        n_ret = SSL_get_error(m_ssl, ret);
        if (n_ret == SSL_ERROR_NONE) {
            length -= ret;
            buf = static_cast<char *>(buf) + ret;
            continue;
        }

        if ((n_ret == SSL_ERROR_WANT_READ) || ssl_error_syscall_with_eagain(n_ret)) {
            if (check_if_socket_timeout(tv_start)) {
                errno = EAGAIN;
                return -1;
            }
            continue;
        }

        if (n_ret == SSL_ERROR_ZERO_RETURN) {
            DLOCK_LOG_ERR("the SSL peer has closed the connection");
            return 0;
        }

        if (ssl_r_unexpected_eof_while_reading(n_ret)) {
            DLOCK_LOG_ERR("blocking recv gets unexpected EOF from SSL peer while reading");
            return 0;
        }

        DLOCK_LOG_ERR("SSL_read failed! ret: %d, SSL_get_error: %d", ret, n_ret);
        return -1;
    }

    return static_cast<ssize_t>(len);
}

ssize_t ssl_connection::recv(void *buf, size_t len, int flags)
{
    if (buf == nullptr || len == 0u || m_ssl == nullptr) {
        DLOCK_LOG_ERR("invalid SSL recv parameter");
        return -1;
    }

    if ((static_cast<unsigned int>(flags) & static_cast<unsigned int>(MSG_DONTWAIT)) != 0) {
        return non_blocking_recv(buf, len);
    }

    return blocking_recv(buf, len);
}

void ssl_connection::set_fd(int fd)
{
    m_sockfd = fd;
}

int ssl_connection::get_fd() const
{
    return m_sockfd;
}

bool ssl_connection::is_ssl_enabled() const
{
    return true;
}

void ssl_connection::tls_callback_register(const tls_cert_verify_callback_func_t cert_verify_cb,
    const tls_prkey_pwd_callback_func_t prkey_pwd_cb,
    const tls_erase_prkey_callback_func_t erase_prkey_cb)
{
    m_cert_verify_cb = cert_verify_cb;
    m_prkey_pwd_cb = prkey_pwd_cb;
    m_erase_prkey_cb = erase_prkey_cb;
}

int ssl_connection::ssl_init(bool is_primary, const ssl_init_attr_t &init_attr)
{
    int ret;

    ssl_load_path_init(init_attr.ca_path, init_attr.crl_path, init_attr.cert_path, init_attr.prkey_path);
    tls_callback_register(init_attr.cert_verify_cb, init_attr.prkey_pwd_cb, init_attr.erase_prkey_cb);

    /* Initialize SSL library */
    ret = SSL_library_init();
    if (ret <= 0) {
        DLOCK_LOG_ERR("initialize SSL library failed");
        return -1;
    }

    ret = OpenSSL_add_all_algorithms();
    if (ret <= 0) {
        DLOCK_LOG_ERR("OpenSSL_add_all_algorithms() failed");
        return -1;
    }

    ret = SSL_load_error_strings();
    if (ret <= 0) {
        DLOCK_LOG_ERR("SSL_load_error_strings() failed");
        return -1;
    }

    if (is_primary) {
        m_ssl_ctx = SSL_CTX_new(TLS_server_method());
        m_socket_timeout = PRIMARY_SERVER_CONTROL_SOCKET_TIMEOUT;
    } else {
        m_ssl_ctx = SSL_CTX_new(TLS_client_method());
    }
    if (m_ssl_ctx == nullptr) {
        DLOCK_LOG_ERR("SSL_CTX_new() failed");
        return -1;
    }

    ret = static_cast<int>(SSL_CTX_set_min_proto_version(m_ssl_ctx, TLS1_3_VERSION));
    if (ret == 0) {
        DLOCK_LOG_ERR("set min_proto_version failed");
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
        return -1;
    }
    ret = SSL_CTX_set_ciphersuites(m_ssl_ctx, "TLS_AES_256_GCM_SHA384");
    if (ret <= 0) {
        DLOCK_LOG_ERR("set ciphersuites failed");
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
        return -1;
    }

    ret = ssl_comm_load(is_primary);
    if (ret != 0) {
        DLOCK_LOG_ERR("SSL failed");
        SSL_CTX_free(m_ssl_ctx);
        m_ssl_ctx = nullptr;
        return -1;
    }

    return 0;
}

int ssl_connection::cert_verify_callback_wrapper(X509_STORE_CTX *ctx, void *arg)
{
    if (ctx == nullptr || arg == nullptr) {
        return 0;
    }

    const int checkSuccess = 1;
    const int checkFailed = -1;

    ssl_connection *conn = reinterpret_cast<ssl_connection *>(arg);

    int ret = conn->m_cert_verify_cb(ctx, conn->m_crl_path.c_str());
    if (ret < 0) {
        DLOCK_LOG_ERR("cert verify failed! ret: %d, please check CA", ret);
        return checkFailed;
    } else {
        return checkSuccess;
    }
}

void ssl_connection::ssl_load_path_init(const std::string &ca_path, const std::string &crl_path,
    const std::string &cert_path, const std::string &prkey_path)
{
    m_ca_path = ca_path;
    m_crl_path = crl_path;
    m_cert_path = cert_path;
    m_prkey_path = prkey_path;
}

int ssl_connection::ssl_comm_load(bool is_primary)
{
    int ret;
    int flags;
    char *prkey_pwd = nullptr;
    int prkey_pwd_len = 0;

    m_prkey_pwd_cb(&prkey_pwd, &prkey_pwd_len);
    int prkey_pwd_real_len = (prkey_pwd == nullptr) ? 0 : static_cast<int>(strnlen(prkey_pwd, PRKEY_PWD_MAX_LEN + 1));
    if ((prkey_pwd == nullptr) || (prkey_pwd_real_len > PRKEY_PWD_MAX_LEN) || (prkey_pwd_real_len != prkey_pwd_len)) {
        DLOCK_LOG_ERR("get private-key password error");
        return -1;
    }

    ret = ssl_verify_cfg(prkey_pwd);
    if (ret != 0) {
        DLOCK_LOG_ERR("SSL verify configure failed");
        m_erase_prkey_cb(reinterpret_cast<void *>(prkey_pwd), prkey_pwd_len);
        return -1;
    }

    m_ssl = SSL_new(m_ssl_ctx);
    if (m_ssl == nullptr) {
        DLOCK_LOG_ERR("SSL_new() failed");
        m_erase_prkey_cb(reinterpret_cast<void *>(prkey_pwd), prkey_pwd_len);
        return -1;
    }

    ret = SSL_set_fd(m_ssl, m_sockfd);
    if (ret <= 0) {
        DLOCK_LOG_ERR("SSL_set_fd() failed");
        static_cast<void>(SSL_shutdown(m_ssl));
        SSL_free(m_ssl);
        m_ssl = nullptr;
        m_erase_prkey_cb(reinterpret_cast<void *>(prkey_pwd), prkey_pwd_len);
        return -1;
    }

    ret = is_primary ? SSL_accept(m_ssl) : SSL_connect(m_ssl);
    if (ret <= 0) {
        DLOCK_LOG_ERR("TLS accept() or connect() failed");
        static_cast<void>(SSL_shutdown(m_ssl));
        SSL_free(m_ssl);
        m_ssl = nullptr;
        m_erase_prkey_cb(reinterpret_cast<void *>(prkey_pwd), prkey_pwd_len);
        return -1;
    }

    /* set socket to non-blocking mode */
    flags = fcntl(m_sockfd, F_GETFL, 0);
    static_cast<void>(fcntl(m_sockfd, F_SETFL, static_cast<unsigned int>(flags) | O_NONBLOCK));

    m_erase_prkey_cb(reinterpret_cast<void *>(prkey_pwd), prkey_pwd_len);
    return 0;
}

int ssl_connection::ssl_verify_cfg(char *prkey_pwd)
{
    int ret;

    SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    if (m_cert_verify_cb != nullptr) {
        SSL_CTX_set_cert_verify_callback(m_ssl_ctx, &ssl_connection::cert_verify_callback_wrapper, this);
    }

    ret = SSL_CTX_load_verify_locations(m_ssl_ctx, m_ca_path.c_str(), nullptr);
    if (ret <= 0) {
        DLOCK_LOG_ERR("TLS load verify file failed");
        return -1;
    }

    ret = SSL_CTX_use_certificate_file(m_ssl_ctx, m_cert_path.c_str(), SSL_FILETYPE_PEM);
    if (ret <= 0) {
        DLOCK_LOG_ERR("TLS use certification file failed");
        return -1;
    }

    SSL_CTX_set_default_passwd_cb_userdata(m_ssl_ctx, reinterpret_cast<void *>(prkey_pwd));
    ret = SSL_CTX_use_PrivateKey_file(m_ssl_ctx, m_prkey_path.c_str(), SSL_FILETYPE_PEM);
    if (ret <= 0) {
        DLOCK_LOG_ERR("TLS use private-key file failed");
        return -1;
    }

    ret = SSL_CTX_check_private_key(m_ssl_ctx);
    if (ret <= 0) {
        DLOCK_LOG_ERR("TLS check private-key failed");
        return -1;
    }

    return 0;
}
};
