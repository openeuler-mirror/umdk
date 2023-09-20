/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: chag INI file interface
 * Author: Chen Wen
 * Create: 2022-08-25
 * Note:
 * History:
 */

#ifndef TPSA_INI_H
#define TPSA_INI_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_ETC_FILENOTFOUND        (-1)     /* brief No found etc file. */
#define TPSA_ETC_SECTIONNOTFOUND     (-2)     /* brief No found section in etc file. */
#define TPSA_ETC_KEYNOTFOUND         (-3)     /* brief No found key in etc file. */
#define TPSA_ETC_FILEIOFAILED        (-4)     /* brief IO operation failed to etc file. */
#define TPSA_ETC_INVALIDOBJ          (-5)     /* brief Invalid object to etc file. */
#define TPSA_ETC_EOF                 (-6)     /* brief End of etc file */
#define TPSA_ETC_OK                    0      /* brief Operate success to etc file. */

#define TPSA_MAX_FILE_LEN 128
#define TPSA_MAX_FILE_PATH 1024

typedef struct file_info {
    char path[TPSA_MAX_FILE_PATH];
    char section[TPSA_MAX_FILE_LEN];
    char key[TPSA_MAX_FILE_LEN];
} file_info_t;

typedef enum tpsa_map_table_field {
    TPSA_MAP_TBL_KEY = 0, /* EID */
    TPSA_MAP_TBL_PEER_TPS,
    TPSA_MAP_TBL_APRAY_EN,
    TPSA_MAP_TBL_OOR_EN,
    TPSA_MAP_TBL_SR_EN,
    TPSA_MAP_TBL_RCTP_START,
    TPSA_MAP_TBL_ACK_RCTP_START,
    TPSA_MAP_TBL_RMTP_START,
    TPSA_MAP_TBL_ACK_RMTP_START,
    TPSA_MAP_TBL_TP_RANGE,
    TPSA_MAP_TBL_TP_CC_EN,
    TPSA_MAP_TBL_UNDERLAY_EID,
    TPSA_MAP_TBL_NETADDR,
    TPSA_MAP_TBL_MAX
} tpsa_map_tbl_field_t;

int tpsa_read_value_by_etc_file(file_info_t *file, char *pValue, size_t len);
int tpsa_read_map_table(file_info_t *file);
#ifdef __cplusplus
}
#endif

#endif // _TPSA_INI_H
