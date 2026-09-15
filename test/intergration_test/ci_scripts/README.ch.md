# UMDK Integration Testing Deploy Scripts
#### 1. Test Directory
1. ci_scripts: all the scripts in this directory is for insider's testing preparation only.

#### 2. Test Dependencies
1. Test Environment Requirements
- You need to prepare 2 test environments.
- Meanwhile, you need to install the following dependency packages:

```bash
  yum install -y python3-devel
  yum install -y python-pip
  yum install -y gcc
  yum install -y gcc-c++
  yum install -y openssl-devel
  yum install -y glib2-devel
  yum install -y iperf3
  pip install pytest==8.0.2
  pip install pytest-timeout=2.4.0
  pip install fabric==2.7.1
  pip install paramiko==3.1.0
  pip install func_timeout
  pip install PyYAML
```

#### 3. Running Scripts
1. Run the master_create_yaml.sh on both sides of host1 and host2
  bash -x master_create_yaml.sh host1,host2
2. Run the master_get_release.sh on both sides of host1 and host2
  bash -x master_get_release.sh
3. (Do not do this step if have download test cases)Run the master_get_scripts.sh on both sides of host1 and host2
  bash -x master_get_scripts.sh
4. (Do not do this step if have installed and deployed UMDK)Run the master_deploy_nstack.sh on both sides of host1 and host2
  bash -x master_deploy_nstack.sh
5. (Do not do this step if have installed and deployed UMS with its UMS_AGENT)Run the master_deploy_ums_agent.sh on both sides of host1 only
  bash -x master_deploy_ums_agent.sh host2

**Precautions:**
- `host1` and `host2` represent 2 test environments' ip


#### 4. License

For details on the license used by the code, see[LICENSES](./LICENSES/README)

For details on the license for documentation in the doc directory, see[LICENSE](./doc/LICENSE)