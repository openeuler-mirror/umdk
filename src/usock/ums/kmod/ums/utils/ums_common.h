/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS public functions header file
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s): Sunfang
 */

#ifndef UMS_COMMON_H
#define UMS_COMMON_H

#include <net/sock.h>
#include <net/tcp.h>
#include <linux/socket.h>

#include "ums_types.h"

static inline int ums_clcsock_enable_fastopen(struct ums_sock *ums, int is_server)
{
	int val = 1;

	return ums->clcsock->ops->setsockopt(ums->clcsock, SOL_TCP,
		is_server != 0 ? TCP_FASTOPEN : TCP_FASTOPEN_CONNECT, KERNEL_SOCKPTR(&val), sizeof(val));
}

#if IS_ENABLED(CONFIG_SMC)
static inline bool ums_get_syn_smc(struct ums_sock *ums)
{
#ifdef GET_SYN_SMC
	/* openEuler kernel 5.10 */
	return GET_SYN_SMC(tcp_sk(ums->clcsock->sk)->inet_conn.reuse);
#else
	/* openEuler kernel 6.6 and Ubuntu 22.04 kernel 5.15 */
	return tcp_sk(ums->clcsock->sk)->syn_smc;
#endif
}
 
static inline void ums_set_syn_smc(struct ums_sock *ums)
{
#ifdef SET_SYN_SMC
	/* openEuler kernel 5.10 */
	SET_SYN_SMC(tcp_sk(ums->clcsock->sk)->inet_conn.reuse, 1);
#else
	/* openEuler kernel 6.6 and Ubuntu 22.04 kernel 5.15 */
	tcp_sk(ums->clcsock->sk)->syn_smc = 1;
#endif
}
#endif /* IS_ENABLED(CONFIG_SMC) */

void ums_copy_sock_settings_to_clc(struct ums_sock *ums);
void ums_copy_conn_jetty_info(struct ums_sock *ums);
int ums_switch_to_fallback(struct ums_sock *ums, int reason_code);
void ums_conn_save_peer_info(struct ums_sock *ums, struct ums_clc_msg_accept_confirm *clc);
void ums_link_save_peer_info(struct ums_link *link,
	struct ums_clc_msg_accept_confirm *clc, struct ums_init_info *ini);
void ums_link_update_peer_jetty_token(struct ums_link *link,
	struct ums_token_xchg_ctx *token_ctx);
void ums_conn_abort(struct ums_sock *ums, int local_first);
void ums_copy_sock_settings(struct sock *dst_sk, struct sock *src_sk, unsigned long mask);
int ums_find_ism_device(struct ums_sock *ums, struct ums_init_info *ini);
int ums_find_ub_device(struct ums_sock *ums, struct ums_init_info *ini);
int ums_sock_get_peer_addr(struct socket *sock, struct ums_ip_addr *addr);
#endif /* UMS_COMMON_H */
