#! /bin/bash
source $(cd $(dirname ${BASH_SOURCE[0]}) && pwd)/master_ci.sh

mkdir -p /var/log/CI/
exec 6>&1 7>&2
exec 1>/var/log/CI/$(basename $0)_$(date +"%Y%m%d%H%M%S").log 2>&1
set -x
find /var/log/CI/ -type f -mtime +5 | grep "$(basename $0)" | xargs -i rm -rf {}

SERVICE_FILE="/usr/lib/systemd/system/ums_agent.service"
UMS_CONFIG_DIR="/etc/ums_agent"
CERTS_DIR="${UMS_CONFIG_DIR}/certs"
HOST2=$1

echo "=== 脚本开始： $(date) ==="

log_step() {
    echo ""
    echo "======== $1 ========"
}

log_step "1.环境检查与初始化判断"
CERTS_CA_FILE="${CERTS_DIR}/ca.crt"

if [ ! -f "$CERTS_CA_FILE" ]; then
    echo "'${CERTS_CA_FILE}'不存在，判定为【初次部署】"
    IS_FIRST_DEPLOY="true"
else
    echo "'${CERTS_CA_FILE}'存在，判定为【已部署】"
    IS_FIRST_DEPLOY="false"
fi

log_step "2.查看urma设备"
urma_admin show 2>&1 || echo "警告: urma_admin 命令执行失败或不存在"

log_step "3.插入ums模块"
modprobe ums 2>&1

ssh -o StrictHostKeyChecking=no root@${HOST2} 'modprobe ums'

if [ "$IS_FIRST_DEPLOY" == "true" ]; then
    log_step "4. 初次部署，生成证书"

    mkdir -p "$CERTS_DIR"

    cd "$CERTS_DIR"

    openssl req -newkey rsa:2048 -passout pass:123456 -keyout ca_rsa_private.pem -x509 -days 365 -out ca.crt -subj "/C=CN/ST=GD/L=SZ/O=COM/OU=NSP/CN=CA/emailAddress=xxxx@xxx.com"

    openssl req -newkey rsa:2048 -passout pass:srv123 -keyout server_rsa_private.pem -out server.csr -subj "/C=CN/ST=GD/L=SZ/O=COM/OU=NSP/CN=SERVER/emailAddress=xxxx@xxx.com"

    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca_rsa_private.pem -passin pass:123456 -CAcreateserial -out server.crt

    openssl req -newkey rsa:2048 -passout pass:clnt123 -keyout client_rsa_private.pem -out client.csr -subj "/C=CN/ST=GD/L=SZ/O=COM/OU=NSP/CN=CLIENT/emailAddress=xxxx@xxx.com"

    openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca_rsa_private.pem -passin pass:123456 -CAcreateserial -out client.crt

    log_step "5.证书赋权"
    chown root:ums "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/ca.srl" "${CERTS_DIR}/client.crt" "${CERTS_DIR}/client.csr" "${CERTS_DIR}/server.crt" "${CERTS_DIR}/server.csr" "${CERTS_DIR}/ca_rsa_private.pem" 2>&1
    chown ums:ums "${CERTS_DIR}/client_rsa_private.pem" "${CERTS_DIR}/server_rsa_private.pem" 2>&1

    chmod 644 "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/ca.srl" "${CERTS_DIR}/client.crt" "${CERTS_DIR}/client.csr" "${CERTS_DIR}/server.crt" "${CERTS_DIR}/server.csr" "${CERTS_DIR}/ca_rsa_private.pem" 2>&1
    chmod 600 "${CERTS_DIR}/client_rsa_private.pem" "${CERTS_DIR}/server_rsa_private.pem" 2>&1
    echo "证书赋权完成"

    scp -r "${CERTS_DIR}/" "root@${HOST2}:${UMS_CONFIG_DIR}/"

    ssh -o StrictHostKeyChecking=no root@${HOST2} \
    "chown root:ums "/etc/ums_agent/certs/ca.crt" "/etc/ums_agent/certs/ca.srl" "/etc/ums_agent/certs/client.crt" "/etc/ums_agent/certs/client.csr" "/etc/ums_agent/certs/server.crt" "/etc/ums_agent/certs/server.csr" "/etc/ums_agent/certs/ca_rsa_private.pem" 2>&1"

    ssh -o StrictHostKeyChecking=no root@${HOST2} \
    "chown ums:ums "/etc/ums_agent/certs/client_rsa_private.pem" "/etc/ums_agent/certs/server_rsa_private.pem" 2>&1"

    ssh -o StrictHostKeyChecking=no root@${HOST2} \
    "chmod 644 "/etc/ums_agent/certs/ca.crt" "/etc/ums_agent/certs/ca.srl" "/etc/ums_agent/certs/client.crt" "/etc/ums_agent/certs/client.csr" "/etc/ums_agent/certs/server.crt" "/etc/ums_agent/certs/server.csr" "/etc/ums_agent/certs/ca_rsa_private.pem" 2>&1"

    ssh -o StrictHostKeyChecking=no root@${HOST2} \
    "chmod 600 "/etc/ums_agent/certs/client_rsa_private.pem" "/etc/ums_agent/certs/server_rsa_private.pem" 2>&1"

    echo "${HOST2}证书设置完成"

else
    echo "跳过生成证书步骤"
fi

log_step "6.注入私钥解密口令至密钥环"
sudo -u ums keyctl add user server_private_key_passphrase "srv123" @u 2>&1
sudo -u ums keyctl add user client_private_key_passphrase "clnt123" @u 2>&1
echo "密钥环注入完成"

ssh -o StrictHostKeyChecking=no root@${HOST2} 'sudo -u ums keyctl add user server_private_key_passphrase "srv123" @u 2>&1'
ssh -o StrictHostKeyChecking=no root@${HOST2} 'sudo -u ums keyctl add user client_private_key_passphrase "clnt123" @u 2>&1'
echo "${HOST2}密钥环注入完成"

log_step "7.更新配置文件"
rm -rf "${UMS_CONFIG_DIR}/ums_agent.conf" 2>&1
cp -r "${script_dir}/ums_agent.conf" "${UMS_CONFIG_DIR}/ums_agent.conf" 2>&1
echo "完成配置文件部署"

ssh -o StrictHostKeyChecking=no root@${HOST2} 'rm -rf /etc/ums_agent/ums_agent.conf'
scp -r "${script_dir}/ums_agent.conf" "root@${HOST2}:${UMS_CONFIG_DIR}/"
echo "${HOST2}"完成配置文件部署

if [ ! -f "$SERVICE_FILE" ]; then
    echo "错误，找不到文件 $SERVICE_FILE"
else
    echo "正在修改 $SERVICE_FILE"
    sed -i -E 's/^StartLimitIntervalSec=60s$/StartLimitIntervalSec=0/' "$SERVICE_FILE"
    sed -i -E 's/^StartLimitBurst=5$/StartLimitBurst=0/' "$SERVICE_FILE"
    ssh -o StrictHostKeyChecking=no root@${HOST2} "sed -i -E 's/^StartLimitIntervalSec=60s$/StartLimitIntervalSec=0/' '/usr/lib/systemd/system/ums_agent.service'"
    ssh -o StrictHostKeyChecking=no root@${HOST2} "sed -i -E 's/^StartLimitBurst=5$/StartLimitBurst=0/' '/usr/lib/systemd/system/ums_agent.service'"
fi

if grep -q "StartLimitIntervalSec=0" "$SERVICE_FILE" && grep -q "StartLimitBurst=0" "$SERVICE_FILE"; then
    echo "修改成功"
else
    echo "[error]修改未生效"
fi

echo "正在调整inotify限制"
sudo sysctl fs.inotify.max_user_instances=1024

echo "正在调整${HOST2}inotify限制"
ssh -o StrictHostKeyChecking=no root@${HOST2} 'sudo sysctl fs.inotify.max_user_instances=1024'

echo "正在重载systemd守护进程"
sudo systemctl daemon-reload

echo "正在重载${HOST2}systemd守护进程"
ssh -o StrictHostKeyChecking=no root@${HOST2} 'sudo systemctl daemon-reload'

log_step "8.拉起ums_agent服务"
sudo systemctl start ums_agent
ssh -o StrictHostKeyChecking=no root@${HOST2} 'sudo systemctl start ums_agent'

sudo service ums_agent status

echo ""
echo "=== 脚本结束： $(date) ==="