/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file defines the error number of UBUS.
 * Author: Li Dongxu
 * Create: 2021-8-20
 * Note:
 * History: 2021-8-20 defines the error number of UBUS.
 */
#ifndef UB_ERRNO_H
#define UB_ERRNO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ubus_module {
    UBUS_MODULE_URMA = 0x0100,
    UBUS_MODULE_URPC = 0x0200,
    UBUS_MODULE_UOBJ = 0x0300,
    UBUS_MODULE_UTM = 0x0400,
    UBUS_MODULE_UTM_HOP_HASH = 0x0500,
    UBUS_MODULE_UTM_EXT_HASH = 0x0600,
    UBUS_MODULE_UTM_BPLUS_TREE = 0x0700,
} ubus_module_t;

typedef int ub_errno_t;

#define UBUS_MODULE_ID_SHIFT                  (16)
#define UBUS_ERRNO_BUILD(moudle_id, errno)    ((((ub_errno_t)(moudle_id)) << (UBUS_MODULE_ID_SHIFT)) | (errno))

/* All ubus modules share the UB_SUCCESS and UB_FAIL */
#define UB_SUCCESS                          (0)
#define UB_ERROR                         (1)
#define UB_FAIL                             (-1)

/* Define module specific error number here. */

/* UTM module error number definition. */
#define UTM_ERRNO_TX_READ                      UBUS_ERRNO_BUILD(UBUS_MODULE_UTM, 0x1)
#define UTM_ERRNO_TX_WRITE                     UBUS_ERRNO_BUILD(UBUS_MODULE_UTM, 0x2)
#define UTM_ERRNO_OBJ_SIZE_TOO_LARGE           UBUS_ERRNO_BUILD(UBUS_MODULE_UTM, 0x3)
#define UTM_ERRNO_ATOMIC_READ                  UBUS_ERRNO_BUILD(UBUS_MODULE_UTM, 0x4)

/* UTM_BPLUS_TREE module number definition */
#define UTM_BPLUS_TREE_TX_READ_ERR              UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x1)
#define UTM_BPLUS_TREE_TX_WRITE_ERR             UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x2)
#define UTM_BPLUS_TREE_TX_COMMIT_ERR            UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x3)
#define UTM_BPLUS_TREE_TX_MALLOC_ERR            UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x4)
#define UTM_BPLUS_TREE_TX_FREE_ERR              UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x5)
#define UTM_BPLUS_TREE_TX_CREATE_ERR            UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x6)
#define UTM_BPLUS_TREE_UNFOUND                  UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x7)
#define UTM_BPLUS_TREE_MALLOC_ERR               UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x8)
#define UTM_BPLUS_TREE_INPUT_INVALID            UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0x9)
#define UTM_BPLUS_TREE_ALREADY_HAVE             UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0xa)
#define UTM_BPLUS_TREE_FATAL_ERR                UBUS_ERRNO_BUILD(UBUS_MODULE_UTM_BPLUS_TREE, 0xb)

#ifdef __cplusplus
}
#endif

#endif