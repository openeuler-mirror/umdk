#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#
set -e
if [ -z "$1" ]; then
    echo "Usage: $0 <ctp_sl_value>"
    exit 1
fi

echo "Stopping ubse service..."
systemctl stop ubse || {
    echo "Failed to stop ubse service"
    exit 1
}
sleep 1

rmmod ubagg || exit 1
rmmod uburma || exit 1
rmmod ipourma || exit 1
rmmod udma || exit 1
rmmod ubcore || exit 1
modprobe ubcore
modprobe uburma
modprobe ubagg
modprobe ipourma tx_ring_size=16 rx_ring_size=32 page_level=16 ctp_sl=$1
modprobe udma dfx_switch=1 jfc_arm_mode=2 well_known_jetty_pgsz_check=0
echo "Starting ubse service..."
systemctl start ubse || {
    echo "Failed to start ubse service"
    exit 1
}
sleep 1
echo "URMA drivers update installed successfully."
