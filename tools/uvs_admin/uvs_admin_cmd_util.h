/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs_admin common function
 * Author: Ji Lei
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14 Ji Lei Initial version
 */
#ifndef UVS_ADMIN_CMD_UTIL_H
#define UVS_ADMIN_CMD_UTIL_H

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

#include "ub_shash.h"
#include "urma_types.h"
#include "uvs_admin_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum MAC_PARM {
    MAC_FIRST = 0,
    MAC_SECOND,
    MAC_THIRD,
    MAC_FOURTH,
    MAC_FIFTH,
    MAC_SIXTH,
};

#define MAC_SCAN_FMT      "%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8
#define MAC_SCAN_ARGS(EA) &(EA)[MAC_FIRST], &(EA)[MAC_SECOND], \
    &(EA)[MAC_THIRD], &(EA)[MAC_FOURTH], &(EA)[MAC_FIFTH], &(EA)[MAC_SIXTH]

struct opt_arg {
    const char *arg_name;
    int arg_type;
};

enum arg_type {
    ARG_TYPE_NUM = 0,
    ARG_TYPE_STR = 1,
    ARG_TYPE_OTHERS = 2,
};

int parse_mac(const char *mac, uint8_t *output_mac);
int str_to_eid(const char *buf, urma_eid_t *eid);
int get_net_addr_type(const char *buf, urma_eid_t *eid,
    uvs_admin_net_addr_type_t *input_net_addr_type);
int mac_n2p(char *str, size_t length, const uint8_t *bin);

#ifdef __cplusplus
}
#endif

#endif /* UVS_ADMIN_CMD_UTIL_H */
