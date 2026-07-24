#! /bin/bash
set -x
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

###########################################################################################
# 单机部署umdk
###########################################################################################

cd /Images/download_umdk/
find ./ -type f -name "*.tar.gz" | xargs -i sh -c 'tar -zxvf {} -C $(dirname {})'
find ./ -type f -name "*.rpm" | xargs -i rpm -ivh {} --nodeps