#! /bin/bash
python_mirror="mirrors.tools.huawei.com"

dnf install -y umdk-* libcdma-devel libummu-devel python3-devel python-pip gcc gcc-c++ openssl-devel glib2-devel qperf expect rsync kernel-devel iperf3 libstdc++-devel glib2-devel --skip-broken

export no_proxy=$no_proxy,${python_mirror}
if [[ "$python_mirror" == *".com" ]]; then
    base_path="https://${python_mirror}/pypi/simple"
else
    base_path="https://${python_mirror}/mirrors/pypi/simple"
fi

pip config set global.index-url "${base_path}"
pip config set install.trusted-host "${python_mirror}"
pip install pytest==8.0.2 pytest-timeout paramiko==3.1.0 fun_timeout fabric==2.7.1 PyYAML --timeout 600
pip install shyaml