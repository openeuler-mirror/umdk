/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: communication header file for urma_tp_test
 * Author: Qian Guoxin
 * Create: 2024-01-31
 * Note:
 * History: 2024-01-31   create file
 */

#ifndef TP_TEST_COMM_H
#define TP_TEST_COMM_H

#include <stdint.h>

#include "tp_test_para.h"

int establish_connection(tp_test_config_t *cfg);
void close_connection(tp_test_config_t *cfg);
int sock_send_data(int sock_fd, int size, char *local_data);
int sock_recv_data(int sock_fd, int size, char *remote_data);
int sock_sync_data(int sock_fd, int size, char *local_data, char *remote_data);
int sync_time(int sock_fd, char *a);
#endif
