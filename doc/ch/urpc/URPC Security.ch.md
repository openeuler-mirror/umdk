# 安全传输
URPC Client和URPC Server之间通信时，支持对传输内容进行加密保护。

控制面：支持通过SSL协议对传输进行加密。利用TLS建立控制面安全传输通道，客户端与服务端进行双向认证。

## 认证
URPC支持基于TLS-PSK策略进行控制面安全建链认证，用户通过urpc_ssl_config_set接口配置相关功能，相应配置参数说明如下：
```c
// 开启控制面和数据面的安全能力
#define URPC_SSL_FLAG_ENABLE                    (1U)
// 数据面选项：禁用默认开启的URPC负载加密；URPC头加密仍保持开启
#define URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE       (1U << 1)
// 数据面选项：禁用默认开启的URPC头加密
#define URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE      (1U << 2)
// 两个禁用标志仅在设置URPC_SSL_FLAG_ENABLE时生效；仅支持单独设置
// URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE，或同时设置两个禁用标志
// 指定SSL模块控制面安全链接建立方式，目前仅支持PSK
typedef enum urpc_ssl_mode {
    SSL_MODE_PSK = 0,

    SSL_MODE_MAX,
} urpc_ssl_mode_t;
typedef unsigned int (*urpc_ssl_psk_client_cb_func)(void *ssl, const char *hint, char *identity,
    unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
typedef unsigned int (*urpc_ssl_psk_server_cb_func)(
    void *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
typedef enum urpc_tls_version {
    URPC_TLS_VERSION_1_2 = 0,
    URPC_TLS_VERSION_1_3,

    URPC_TLS_VERSION_MAX,
} urpc_tls_version_t;
// 配置接口入参
typedef struct urpc_ssl_config {
    uint32_t ssl_flag; // 指示SSL认证加密开关
    urpc_ssl_mode_t ssl_mode; // 指定SSL模式
    urpc_tls_version_t min_tls_version; // 指定tls最低版本
    urpc_tls_version_t max_tls_version; // 指定tls最高版本， min_tls_version<=max_tls_version
    union {
        struct {
            // 选定TLS1.2加密套件，最大长度4096（包含'\0'）
            char *cipher_list;
            // 选定TLS1.3加密套件，最大长度4096（包含'\0'）
            char *cipher_suites;
            // client psk握手回调函数，client/server_client模式下不为NULL
            urpc_ssl_psk_client_cb_func client_cb_func;
            // server psk握手回调函数，server/server_client模式下不为NULL
            urpc_ssl_psk_server_cb_func server_cb_func;
        } psk;
    };
} urpc_ssl_config_t;
```
### 说明:
1.urpc_ssl_config_set接口需要在urpc_init后调用，否则返回-EPERM；

2.cipher_list/cipher_suites密码套件由用户配置，有效性、安全性由用户保证，用户需配置符合安全要求的有效密码套件；

3.启用SSL模块后，URPC会从/dev/random设备读取随机种子，系统熵不足的情况下，读取/dev/random设备可能因没有足够随机数而阻塞。通过启用system start haveged.service服务可以解决此问题。
