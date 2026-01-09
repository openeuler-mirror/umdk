# Secure Transmission
When URPC Client and URPC Server communicate, encryption protection for the transmission content is supported.

Control plane: Encryption of transmissions via the SSL protocol is supported. TLS is used to establish a secure control plane transmission channel, enabling mutual authentication between client and server.

## Authentication
URPC supports control plane secure connection establishment authentication based on the TLS-PSK strategy. Users configure related functions via the `urpc_ssl_config_set` interface. The description of the corresponding configuration parameters is as follows:
```c
// Whether to enable the URPC SSL authentication and encryption feature. When enabled, URPC authentication is activated by default.
#define URPC_SSL_FLAG_ENABLE  (1U)
// Specifies the SSL module's control plane secure connection establishment method. Currently, only PSK is supported.
typedef enum urpc_ssl_mode {
    SSL_MODE_PSK = 0,
} urpc_ssl_mode_t;
typedef unsigned int (*urpc_ssl_psk_client_cb_func)(void *ssl, const char *hint, char *identity,
    unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
typedef unsigned int (*urpc_ssl_psk_server_cb_func)(
    void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
// Configuration interface input parameter
typedef struct urpc_ssl_config {
    uint32_t ssl_flag; // Indicates the SSL authentication/encryption switch
    urpc_ssl_mode_t ssl_mode; // Specifies the SSL mode
    urpc_tls_version_t min_tls_version; // Specifies the minimum TLS version
    urpc_tls_version_t max_tls_version; // Specifies the maximum TLS version, min_tls_version <= max_tls_version
    union {
        struct {
            // Selected TLS1.2 cipher suites, maximum length 4096 (including '\0')
            char *cipher_list;
            // Selected TLS1.3 cipher suites, maximum length 4096 (including '\0')
            char *cipher_suites;
            // Client PSK handshake callback function, not NULL in client/server_client mode
            urpc_ssl_psk_client_cb_func client_cb_func;
            // Server PSK handshake callback function, not NULL in server/server_client mode
            urpc_ssl_psk_server_cb_func server_cb_func;
        } psk;
    };
} urpc_ssl_config_t;
```
### Notes:
1. The `urpc_ssl_config_set` interface must be called after `urpc_init`; otherwise, it returns `-EPERM`;
2. The cipher_list/cipher_suites cipher suites are configured by the user. Their validity and security are guaranteed by the user. The user must configure effective cipher suites that meet security requirements;
3. After enabling the SSL module, URPC reads random seeds from the `/dev/random` device. If system entropy is insufficient, reading the `/dev/random` device may block due to insufficient random numbers. This issue can be resolved by enabling the `system start haveged.service` service.
