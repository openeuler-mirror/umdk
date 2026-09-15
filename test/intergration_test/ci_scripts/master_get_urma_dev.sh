#! /bin/bash
# 查找urma设备和eid
port=`urma_admin show topo | grep "Connected" | cut -d':' -f1 | head -n1`
eid=`urma_admin show topo | grep "${port}" | grep "Connected" | head -n1 | awk '{print $3}'`
dev=`urma_admin show -a | grep "${eid}" | awk '{print $2}'`
eid_idx=`urma_admin show -a | grep "${eid}" | head -n1 | awk '{print $1}'`
ipv6=$eid


if `urma_admin show | grep -q "bonding_dev_0"`; then
    eid=`urma_admin show | grep "bonding_dev_0" | awk '{print $5}'`
    dev="bonding_dev_0"
fi

echo "$dev $bond_dev $eid $ipv6 $eid_idx"