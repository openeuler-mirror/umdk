#! /bin/bash
set -x
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

###########################################################################################
# 单机下载umdk
###########################################################################################

function download_package() {
    echo "[Info] ${manage_ip}: cleanup /Images/download_umdk/"
    rm -rf /Images/download_umdk/
    mkdir -p /Images/download_umdk/
    cd /Images/download_umdk/

    echo "[Info] ${manage_ip}: et date of umdk version"
    if [[ ${umdk_date} == "latest" ]]; then
        wget "${http_ip}/${umdk_branch}/release_dir"
        umdk_date=$(cat release_dir)
    fi

    for i in ${seq 1 5}; do
        echo "[Info] ${manage_ip}: download umdk"
        wget -r -np -nH -e robots=off -A "TongTu_UMDK_*4k*" "${http_ip}/${umdk_branch}/${umdk_date}/software/"
        wget_ret=$?
        if ((${wget_ret} == 0)); then
            break
        else
            sleep 5
            continue
        fi
    done
}

# 下载版本
download_package