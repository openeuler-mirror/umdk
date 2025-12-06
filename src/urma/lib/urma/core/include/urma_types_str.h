/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: URMA type string header file
 * Author: Qian Guoxin
 * Create: 2022-10-18
 * Note:
 * History: 2022-10-18   Create File
 */

#ifndef URMA_TYPES_STR_H
#define URMA_TYPES_STR_H
#include "urma_types.h"

static const char *const g_urma_mtu_str[] = {
    [URMA_MTU_256] = "MTU_256",   //
    [URMA_MTU_512] = "MTU_512",   //
    [URMA_MTU_1024] = "MTU_1024", //
    [URMA_MTU_2048] = "MTU_2048", //
    [URMA_MTU_4096] = "MTU_4096", //
    [URMA_MTU_8192] = "MTU_8192", //
};

static inline const char *urma_mtu_to_string(urma_mtu_t mtu)
{
    if (mtu < URMA_MTU_256 || mtu > URMA_MTU_8192) {
        return "Invalid Value";
    }
    return g_urma_mtu_str[mtu];
}

static const char *const g_urma_port_state_str[] = {
    [URMA_PORT_NOP] = "NOP",                   //
    [URMA_PORT_DOWN] = "DOWN",                 //
    [URMA_PORT_INIT] = "INIT",                 //
    [URMA_PORT_ARMED] = "ARMED",               //
    [URMA_PORT_ACTIVE] = "ACTIVE",             //
    [URMA_PORT_ACTIVE_DEFER] = "ACTIVE_DEFER", //
};

static inline const char *urma_port_state_to_string(urma_port_state_t state)
{
    if (state > URMA_PORT_ACTIVE_DEFER) {
        return "Invalid Value";
    }
    return g_urma_port_state_str[state];
}

static const char *const g_urma_speed_str[] = {
    [URMA_SP_10M] = "SP_10M",   //
    [URMA_SP_100M] = "SP_100M", //
    [URMA_SP_1G] = "SP_1G",     //
    [URMA_SP_2_5G] = "SP_2.5G", //
    [URMA_SP_5G] = "SP_5G",     //
    [URMA_SP_10G] = "SP_10G",   //
    [URMA_SP_14G] = "SP_14G",   //
    [URMA_SP_25G] = "SP_25G",   //
    [URMA_SP_40G] = "SP_40G",   //
    [URMA_SP_50G] = "SP_50G",   //
    [URMA_SP_100G] = "SP_100G", //
    [URMA_SP_200G] = "SP_200G", //
    [URMA_SP_400G] = "SP_400G", //
    [URMA_SP_800G] = "SP_800G", //
};

static inline const char *urma_speed_to_string(urma_speed_t speed)
{
    if (speed > URMA_SP_800G) {
        return "Invalid Value";
    }
    return g_urma_speed_str[speed];
}

static const char *const g_urma_link_width_str[] = {
    [0] = "unknow",
    [URMA_LINK_X1] = "LINK_X1",
    [URMA_LINK_X2] = "LINK_X2",
    [URMA_LINK_X4] = "LINK_X4",
    [URMA_LINK_X8] = "LINK_X8",
    [URMA_LINK_X16] = "LINK_X16",
    [URMA_LINK_X32] = "LINK_X32",
};

static inline const char *urma_link_width_to_string(urma_link_width_t width)
{
    if (width > URMA_LINK_X32) {
        return "Invalid Value";
    }
    return g_urma_link_width_str[width];
}

#define URMA_DEVICE_FEAT_NUM 9

static const char *const g_urma_device_feat_str[URMA_DEVICE_FEAT_NUM] = {
    "OUT_OF_ORDER",      //
    "JFC_PER_WR",        //
    "STRIDE_OP",         //
    "LOAD_STORE_OP",     //
    "NON_PIN",           //
    "PERSISTENCE_MEM",   //
    "JFC_INLINE",        //
    "SPRAY_ENABLE",      //
    "SELECTIVE_RETRANS", //
};

static inline const char *urma_device_feat_to_string(uint8_t bit)
{
    if (bit >= URMA_DEVICE_FEAT_NUM) {
        return "Invalid Value";
    }
    return g_urma_device_feat_str[bit];
}

#define URMA_ATOMIC_FEAT_NUM 7

static const char *const g_urma_atomic_feat_str[URMA_ATOMIC_FEAT_NUM] = {
    "compare_and_swap", //
    "swap",             //
    "fetch_and_add",    //
    "fetch_and_sub",    //
    "fetch_and_and",    //
    "fetch_and_or",     //
    "fetch_and_xor",    //
};

static inline const char *urma_atomic_feat_to_string(uint8_t bit)
{
    if (bit >= URMA_ATOMIC_FEAT_NUM) {
        return "Invalid Value";
    }
    return g_urma_atomic_feat_str[bit];
}

static const char *const g_urma_trans_mode_str[] = {
    [URMA_TM_RM] = "RM(Reliable message)",
    [URMA_TM_RC] = "RC(Reliable connection)",
    [URMA_TM_UM] = "UM(Unreliable message)",
};

static inline const char *urma_trans_mode_to_string(urma_transport_mode_t mode)
{
    if (mode > URMA_TM_UM) {
        return "Invalid Value";
    }
    return g_urma_trans_mode_str[mode];
}

static const char *const g_urma_tp_type_str[] = {
    [URMA_TRANSPORT_UB] = "UB",
};

static inline const char *urma_tp_type_to_string(urma_transport_type_t type)
{
    if (type <= URMA_TRANSPORT_INVALID || type >= URMA_TRANSPORT_MAX) {
        return "Invalid Value";
    }
    return g_urma_tp_type_str[type];
}

static const char *const g_urma_congestion_ctrl_alg_str[] = {
    [URMA_TP_CC_NONE] = "NONE",
    [URMA_TP_CC_DCQCN] = "DCQCN",
    [URMA_TP_CC_DCQCN_AND_NETWORK_CC] = "DCQCN_AND_NETWORK_CC",
    [URMA_TP_CC_LDCP] = "LDCP",
    [URMA_TP_CC_LDCP_AND_CAQM] = "LDCP_AND_CAQM",
    [URMA_TP_CC_LDCP_AND_OPEN_CC] = "LDCP_AND_OPEN_CC",
    [URMA_TP_CC_HC3] = "HC3",
    [URMA_TP_CC_DIP] = "DIP",
    [URMA_TP_CC_ACC] = "ACC",
};

static inline const char *urma_congestion_ctrl_alg_to_string(uint8_t bit)
{
    if (bit > URMA_TP_CC_DIP) {
        return "Invalid Value";
    }
    return g_urma_congestion_ctrl_alg_str[bit];
}

static const char *const g_urma_jfc_state[] = {
    [URMA_JFC_STATE_INVALID] = "INVALID",
    [URMA_JFC_STATE_VALID] = "VALID",
    [URMA_JFC_STATE_ERROR] = "ERROR",
};

static inline const char *urma_jfc_state_to_string(uint8_t bit)
{
    if (bit > URMA_JFC_STATE_ERROR) {
        return "Invalid Value";
    }
    return g_urma_jfc_state[bit];
}

static const char *const g_urma_jetty_state[] = {
    [URMA_JETTY_STATE_RESET] = "RESET",
    [URMA_JETTY_STATE_READY] = "READY",
    [URMA_JETTY_STATE_SUSPENDED] = "SUSPENDED",
    [URMA_JETTY_STATE_ERROR] = "ERROR",
};

static inline const char *urma_jetty_state_to_string(uint8_t bit)
{
    if (bit > URMA_JETTY_STATE_ERROR) {
        return "Invalid Value";
    }
    return g_urma_jetty_state[bit];
}

static const char *const g_urma_jfr_state[] = {
    [URMA_JFR_STATE_RESET] = "RESET",
    [URMA_JFR_STATE_READY] = "READY",
    [URMA_JFR_STATE_ERROR] = "ERROR",
};

static inline const char *urma_jfr_state_to_string(uint8_t bit)
{
    if (bit > URMA_JFR_STATE_ERROR) {
        return "Invalid Value";
    }
    return g_urma_jfr_state[bit];
}

#endif
