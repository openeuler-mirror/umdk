#! /bin/bash
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

mkdir -p /var/log/CI/
exec 6>&1 7>&2
exec 1>/var/log/CI/$(basename $0)_$(date +"%Y%m%d%H%M%S").log 2>&1
set -x
find /var/log/CI/ -type f -mtime +5 | grep "$(basename $0)" | xargs -i rm -rf {}

###########################################################################################
# 生成yaml文件
###########################################################################################
HOST_IPS=${1}
USER=${2:-"root"}

arch=$(uname -m)
IFS=','
read -r host1 host2 <<< "$HOST_IPS"

mkdir -p ${conf_dir}

bash ${script_dir}/master_test_pre.sh

ssh -o StrictHostKeyChecking=no ${USER}@${host2} \
    "bash ${script_dir}/master_test_pre.sh"

nic_host1=$(ip -o addr show | awk -v ip=$host1 '$4 ~ ip {print $2}')
mac_host1=$(cat /sys/class/net/${nic_host1}/address)
nic_host2=$(ssh -o StrictHostKeyChecking=no ${USER}@${host2} \
    "ip -o addr show | awk -v ip=$host2 '\$4 ~ ip {print \$2}'" \
    2>/dev/null)
mac_host2=$(ssh -o StrictHostKeyChecking=no ${USER}@${host2} \
    "cat /sys/class/net/${nic_host2}/address" \
    2>/dev/null)

name_dev_eid_porteid_host1=`bash ${script_dir}/master_get_urma_dev.sh`
name_dev_eid_porteid_host2=$(ssh -o StrictHostKeyChecking=no ${USER}@${host2} "bash ${script_dir}/master_get_urma_dev.sh")
name_host1=`echo $name_dev_eid_porteid_host1 | awk '{print $1}'`
dev_host1=`echo $name_dev_eid_porteid_host1 | awk '{print $2}'`
eid_host1=`echo $name_dev_eid_porteid_host1 | awk '{print $3}'`
ipv6_host1=`echo $name_dev_eid_porteid_host1 | awk '{print $4}'`

name_host2=`echo $name_dev_eid_porteid_host2 | awk '{print $1}'`
dev_host2=`echo $name_dev_eid_porteid_host2 | awk '{print $2}'`
eid_host2=`echo $name_dev_eid_porteid_host2 | awk '{print $3}'`
ipv6_host2=`echo $name_dev_eid_porteid_host2 | awk '{print $4}'`

rm -rf ${configfile}

# 开始生成yaml文件
cat > ${configfile} << EOF

host_info:
  host1:
    user: ${USER}
    passwd: ${PASSWORD}
    manage_nic:
      name: ${nic_host1}
      ip: ${host1}
    test_nic1:
      dev: ${name_host1}
      name: ${name_host1}
      mac: ${mac_host1}
      eid: ${eid_host1}
      ipv6: ${ipv6_host1}
    arch: ${arch}
  host2:
    user: ${USER}
    passwd: ${PASSWORD}
    manage_nic:
      name: ${nic_host2}
      ip: ${host2}
    test_nic1:
      dev: ${name_host2}
      name: ${name_host2}
      mac: ${mac_host2}
      eid: ${eid_host2}
      ipv6: ${ipv6_host2}
    arch: ${arch}

EOF

scp -r ${conf_dir} ${USER}@${host2}:/etc/