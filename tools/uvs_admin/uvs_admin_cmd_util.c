/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs_admin common function
 * Author: Jilei
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14 Jilei Initial version
 */
#include <string.h>
#include <stdio.h>
#include <glib-object.h>
#include "uvs_admin_cmd_util.h"

#ifdef __cplusplus
extern "C"
{
#endif


static inline int char_is_valid_hex(const char input)
{
    if ((input >= '0' && input <= '9') ||
        (input >= 'a' && input <= 'f') ||
        (input >= 'A' && input <= 'F')) {
        return 0;
    }
    return -EINVAL;
}

int check_valid_mac(const char *mac)
{
    bool can_colon = false;
    int colon_count = 0;
    int hex_count_between_colon = 0;
    const char *p = mac;
    const int colon_len = 5;
    const int colon_between_len = 2;

    while (*p != '\0') {
        if (can_colon && (*p == ':')) {
            can_colon = false;
            hex_count_between_colon = 0;
            colon_count++;
            if (colon_count > colon_len) {
                return -EINVAL;
            }
            p++;
            continue;
        }

        hex_count_between_colon++;
        if (hex_count_between_colon > colon_between_len) {
            return -EINVAL;
        }

        if (char_is_valid_hex(*p)) {
            return -EINVAL;
        }
        can_colon = true;
        p++;
    }
    return 0;
}

int parse_mac(const char *mac, uint8_t *output_mac)
{
    int success_len;

    if (check_valid_mac(mac)) {
        return -EINVAL;
    }

    success_len = sscanf(mac, MAC_SCAN_FMT, MAC_SCAN_ARGS(output_mac));
    if (success_len != UVS_ADMIN_MAC_BYTES) {
        return -EINVAL;
    }
    return 0;
}

#define IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define EID_STR_MIN_LEN 3
static inline void ipv4_map_to_eid(uint32_t ipv4, urma_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int str_to_eid(const char *buf, urma_eid_t *eid)
{
    uint32_t ipv4;

    if (buf == NULL || strlen(buf) <= EID_STR_MIN_LEN || eid == NULL) {
        return -EINVAL;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        ipv4_map_to_eid(be32toh(ipv4), eid);
        return 0;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) <= 0) {
        return -EINVAL;
    }
    return 0;
}

int mac_n2p(char *str, size_t length, const uint8_t *bin)
{
    int ret;

    if (!str || !bin) {
        return -1;
    }

    ret = snprintf(str, length, "%02X:%02X:%02X:%02X:%02X:%02X",
        bin[MAC_FIRST], bin[MAC_SECOND], bin[MAC_THIRD],
        bin[MAC_FOURTH], bin[MAC_FIFTH], bin[MAC_SIXTH]);
    if (ret <= 0) {
        return -1;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
