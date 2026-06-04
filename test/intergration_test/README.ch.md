# UMDK Integration Testing
#### 1. Test Directory
1. test_framework: UMDK integration testing framework, using the pytest framework.

2. test_suites: UMDK component test suites and cases.

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
  pip install pytest-timeout
  pip install fabric==2.7.1
  pip install paramiko==3.1.0
  pip install func_timeout
  pip install PyYAML
```

2. Environment YAML File Preparation
- YAML format requirements are as follows:
  - host1 and host2 represent 2 test environments
  - user and passed are the username and password for logging into the environment
  - manage_nic represents the management network interface card (NIC)
  - name and ip represent the NIC name and IP address of the management NIC
  - test_nic1 represents the test NIC
  - name, ip, and eid represent the device name, IP address, and EID information of the test NIC respectively

- YAML file path: /etc/ubus_ci/test_env.yaml, needs to be stored on both hosts

```yaml
  host_info:
      host1:
          user: root
          passwd: xxx
          manage_nic:
              name: xxx
              ip: x.x.x.x
          test_nic1:
              name: xxx
              dev: xxx
              ip: x.x.x.x
              ipv6: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
              eid: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
      host2:
          user: root
          passwd: xxx
          manage_nic:
              name: xxx
              ip: x.x.x.x
          test_nic1:
              name: xxx
              dev: xxx
              ip: x.x.x.x
              ipv6: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
              eid: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
```
**Notes:** 
- For `test_nic1`, fill in the `name` and `eid` with the device name and EID queried by the `urma_admin show` command. It is recommended to use the `bonding_dev_0` device.
- The `ip` for `test_nic1` is currently unused; you can fill in the IP of `manage_nic`.

#### 3. Running Test Cases
1. The UMDK integration testing framework depends on the pytest framework; use pytest to run test cases.
- Run a single test case:
```bash
  pytest ./umdk/test/intergration_test/test_suites/UMQ/test_umq_demo_pro/test.py
```

- Run all integration test cases:
```bash
  cd ./umdk/test/intergration_test
  find ./ -name test.py | xargs -i pytest {}
```
**Precautions:**
- The test code needs to be stored on both hosts, and the directory structure must remain consistent.
- Please execute the test cases on host1.
- Log check: By default, rsyslog is used to record logs, archived in the /var/log/umdk/ directory. The log file name is: binary_name.log.


#### 4. License

For details on the license used by the code, see[LICENSES](./LICENSES/README)

For details on the license for documentation in the doc directory, see[LICENSE](./doc/LICENSE)