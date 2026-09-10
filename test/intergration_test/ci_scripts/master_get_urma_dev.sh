#! /bin/bash
# 查找urma设备和eid
port=`urma_admin show topo | grep "Connected" | cut -d':' -f1 | head -n1`
eid=`urma_admin show topo | grep "${port}" | grep "Connected" | head -n1 | awk '{print $3}'`
dev=`urma_admin show -a | grep "${eid}" | awk '{print $2}'`
eid_idx=`urma_admin show -a | grep "${eid}" | head -n1 | awk '{print $1}'`
nic_name=""
ipv6=$eid

# 将eid转化为ip over urma eid格式
if ping -c 1 -W 1 "$eid" > /dev/null 2>&1; then
    urma_simple_eid=`ping "$eid" -c 1 -W 1 | sed -n 1p | awk -F"[()]" '{print $2}'`
    if ifconfig | grep -q "$urma_simple_eid"; then
        nic_name=`ip -o addr show | grep "$urma_simple_eid" | awk '{print $2}'`
    fi

else
    nic_name=$dev
fi

if `urma_admin show | grep -q "bonding_dev_0"`; then
    eid=`urma_admin show | grep "bonding_dev_0" | awk '{print $5}'`
    dev="bonding_dev_0"
fi

echo "$nic_name $dev $eid $ipv6"