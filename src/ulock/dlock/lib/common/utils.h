/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : utils.h
 * Description   : utility function
 * History       : create file & add functions
 * 1.Date        : 2021-06-16
 * Author        : zhangjun
 * Modification  : Created file
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <arpa/inet.h>
#include <cstdlib>
#include <cctype>
#include <string>
#include <cstring>

#include "dlock_common.h"
#include "dlock_connection.h"
#include "jetty_mgr.h"

namespace dlock {
constexpr int  DLOCK_PORT_RANGE_MIN = 1024;
constexpr int  DLOCK_PORT_RANGE_MAX = 65535;

int check_ip_format(const char *ip_str, unsigned long len);

int convert_ip_addr(const char *ip_str,  struct in_addr *addr);

int set_send_recv_timeout(int sockfd);

int set_send_recv_timeout(int sockfd, int timeout_second);

int set_primary_keepalive(int sockfd);

uint8_t *construct_control_msg(enum dlock_control_msg type, uint8_t version,
    size_t hdr_len, size_t total_len, uint16_t message_id, int32_t value);

uint8_t* xchg_control_msg(dlock_connection *p_conn, uint8_t* buf, size_t send_len, size_t recv_len);

uint8_t* xchg_control_msg_by_time(dlock_connection *p_conn, uint8_t* buf,
    size_t send_len, size_t recv_len, unsigned int timeout);

unsigned int get_hash(unsigned int len, unsigned char *buf);

void flush_recv_buffer(dlock_connection *p_conn);

void flush_recv_buffer(dlock_connection *p_conn, unsigned int len);

bool get_cpuset(char *cpuset_token, int *range_start_id, int *range_end_id);

bool check_cpuset_valid(char *token, int *cpu_id);

bool check_server_id_invalid(int server_id);

bool check_primary_cfg_valid(const struct primary_cfg &primary);

bool check_ssl_cfg_valid(const struct ssl_cfg &cfg);

int set_ssl_init_attr(const struct ssl_cfg &cfg, bool &ssl_enable, ssl_init_attr_t &ssl_init_attr);

dlock_connection *create_connection(int sockfd, bool is_primary, bool ssl_enable, const ssl_init_attr_t &ssl_init_attr);

bool get_canonical_path(std::string &path);

void u32_to_eid(uint32_t ipv4, dlock_eid_t *eid);

int str_to_urma_eid(const char *buf, dlock_eid_t *eid);

bool check_if_eid_match(const urma_eid_t &eid1, const urma_eid_t &eid2);

jetty_mgr *create_jetty_mgr(urma_ctx *p_urma_ctx, urma_jfc_t *exe_jfc, new_jetty_t type, trans_mode_t tp_mode,
    dlock_server *p_server);

dlock_status_t set_jetty_connection(jetty_mgr *p_jetty_mgr, struct urma_init_body *jetty_info, trans_mode_t tp_mode);

inline bool check_port_range_invalid(int port)
{
    /* If the port is less than or equal to 0, the default port is used. */
    return ((port > DLOCK_PORT_RANGE_MAX) || ((port > 0) && (port < DLOCK_PORT_RANGE_MIN)));
}

inline bool check_msg_body_len_invalid(struct dlock_control_hdr *msg_hdr, uint16_t expected_msg_body_len)
{
    return ((msg_hdr->total_len - msg_hdr->hdr_len) != expected_msg_body_len);
}

#ifdef UB_AGG
inline bool check_if_ub_bonding_dev(const urma_device_t *urma_dev)
{
    /* If the device name contains "bonding", it is a ub bonding device.
     * Currently, there are no other attributes to distinguish between ub bonding devices and ub devices.
     */
    return ((strstr(urma_dev->name, "bonding") != NULL) &&
        (urma_dev->type == URMA_TRANSPORT_UB));
}
#endif /* UB_AGG */

};
#endif
