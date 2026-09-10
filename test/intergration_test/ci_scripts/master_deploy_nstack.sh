#! /bin/bash
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

mkdir -p /var/log/CI/
exec 6>&1 7>&2
exec 1>/var/log/CI/$(basename $0)_$(date +"%Y%m%d%H%M%S").log 2>&1
set -x
find /var/log/CI/ -type f -mtime +5 | grep "$(basename $0)" | xargs -i rm -rf {}

###########################################################################################
# 卸载umdk
# 安装umdk
# 重启环境
###########################################################################################

function uninstall_umdk() {
    echo "[Info] ${manage_ip}: uninstall umdk"
    rpm -qa | grep 'umdk-' | xargs sudo rpm -e --nodeps
    for ip in ${array_mgt_ip[@]}; do
        if [[ ${ip} != ${manage_ip} ]]; then
            echo "[Info] ${ip}: uninstall umdk"
            ssh -o StrictHostKeyChecking=no root@${ip} "rpm -qa | grep 'umdk-' | xargs sudo rpm -e --nodeps"
        fi
    done
}

function install_umdk() {
    echo "[Info] ${manage_ip}: install umdk"
    sh ${script_dir}/master_deploy_umdk.sh

    for ip in ${array_mgt_ip[@]}; do
        if [[ ${ip} != ${manage_ip} ]]; then
            echo "[Info] ${ip}: install umdk"
            ssh -o StrictHostKeyChecking=no root@${ip} "sh ${script_dir}/master_deploy_umdk.sh"
        fi
    done
}

function restart_machine() {
    echo "[Info] ${manage_ip}: restart_machine"

    for ip in ${array_mgt_ip[@]}; do
        if [[ ${ip} != ${manage_ip} ]]; then
            echo "[Info] ${ip}: restart_machine"
            ssh -o StrictHostKeyChecking=no root@${ip} "ipmitool power reset 2>&1"
        fi
    done

    ipmitool power reset 2>&1
}

# 卸载umdk
uninstall_umdk

# 安装umdk
install_umdk

# 重启环境
restart_machine