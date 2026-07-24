#! /bin/bash
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/para_mark

###########################################################################################
# 公共变量、函数
###########################################################################################

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd -P)
conf_dir="/etc/ubus_ci"
conf_file="${conf_dir}/test_env.yaml"
http_ip="${archive_ip}"

# 获取系统所有接口ip
host_ip=($(ifconfig | awk '/inet / {print $2}'))
# 获取yaml里面所有的管理ip
yaml_ip=($(grep -r "manage_nic" -A 2 ${conf_file} | awk -F ': ' '/ip/ {print $2}' | sort -u))
# 两个数组取交集，得到本机管理ip
manage_ip=$(echo ${host_ip[@]} ${yaml_ip[@]} | tr ' ' '\n' | sort -n | uniq -d)

# 获取环境中所有host的ip
function get_array_mgt_ip() {
    array_mgt_ip=()

    array_host=($(cat ${conf_file} | shyaml keys host_info))

    for i in ${array_host[@]}; do
        ip=$(cat ${conf_file} | shyaml get-value host_info.${i}.manage_nic.ip)
        array_mgt_ip+=(${ip})
    done
}

get_array_mgt_ip