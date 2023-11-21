/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa socket service header file
 * Author: Ji Lei
 * Create: 2023-06-15
 * Note:
 * History: 2023-06-15 Ji lei Initial version
 */
#ifndef TPSA_SOCKET_SERVICE_H
#define TPSA_SOCKET_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MSG_LEN  1024

int tpsa_socket_service_init(void);
void tpsa_socket_service_uninit(void);

/* must same with UVS_COMMAND_TYPE */
enum COMMAND_TYPE {
    TPSA_SERVICE_SHOW = 0,
    VPORT_TABLE_SHOW,
    VPORT_TABLE_ADD,
    VPORT_TABLE_DEL,
    LIVE_MIGRATE_TABLE_SHOW,
    LIVE_MIGRATE_TABLE_ADD,
    LIVE_MIGRATE_TABLE_DEL,
    SIP_TABLE_SHOW,
    SIP_TABLE_ADD,
    SIP_TABLE_DEL,
    DIP_TABLE_SHOW,
    DIP_TABLE_ADD,
    DIP_TABLE_DEL,
    DIP_TABLE_MODIFY,
    VPORT_TABLE_SHOW_UEID,
    VPORT_TABLE_ADD_UEID,
    VPORT_TABLE_DEL_UEID,
    VPORT_TABLE_SET_UPI,
    VPORT_TABLE_SHOW_UPI,
    GLOBAL_CFG_SHOW,
    GLOBAL_CFG_SET,
    COMMAND_TYPE_MAX
};

typedef struct tpsa_request {
    uint32_t cmd_type;
    ssize_t req_len;
    char req[0];
} tpsa_request_t;

typedef struct tpsa_response {
    uint32_t cmd_type;
    ssize_t rsp_len;
    char rsp[0];
} tpsa_response_t;

typedef tpsa_response_t *(*tpsa_process_request)(tpsa_request_t *req, ssize_t read_len);

#ifdef __cplusplus
}

#endif

#endif /* TPSA_SOCKET_SERVICE_H */
