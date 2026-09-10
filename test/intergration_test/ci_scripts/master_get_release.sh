#! /bin/bash
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

mkdir -p /var/log/CI/
exec 6>&1 7>&2
exec 1>/var/log/CI/$(basename $0)_$(date +"%Y%m%d%H%M%S").log 2>&1
set -x
find /var/log/CI/ -type f -mtime +5 | grep "$(basename $0)" | xargs -i rm -rf {}

###########################################################################################
# 多机下载umdk
# 默认下载最新的release版本
###########################################################################################

#下载本地host的umdk
sh ${script_dir}/master_get_umdk.sh

#下载其他host的umdk
    for ip in ${array_mgt_ip[@]}; do
        if [[ ${ip} != ${manage_ip} ]]; then
            echo "[Info] ${ip}: download umdk"
            ssh -o StrictHostKeyChecking=no root@${ip} "sh ${script_dir}/master_get_umdk.sh"
        fi
    done