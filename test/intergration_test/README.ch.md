# UMDK集成测试
#### 一、测试目录
1. test_framework：UMDK集成测试框架，使用pytest框架

2. test_suites：UMDK各组件测试套、用例

#### 二、测试依赖
1. 测试环境要求
- 你需要准备2台测试环境
- 同时你需要安装以下依赖包：

```bash
  yum install -y python3-devel
  yum install -y python-pip
  yum install -y gcc
  yum install -y gcc-c++
  yum install -y openssl-devel
  yum install -y glib2-devel
  pip install pytest==8.0.2
  pip install pytest-timeout
  pip install fabric==2.7.1
  pip install paramiko==3.1.0
  pip install func_timeout
  pip install PyYAML
```

2. 环境yaml文件准备
- yaml格式要求如下：
  - host1、host2代表2台测试环境
  - user、passed为登录环境的用户名、密码
  - manage_nic表示管理网卡
  - name、ip表示管理网卡的网卡名称、ip地址
  - test_nic1表示测试网卡
  - name、ip、eid分别表示测试网卡的网卡设备名称、ip地址、eid信息

- yaml文件路径：/etc/ubus_ci/test_env.yaml，2台host都需要存放

```yaml
  host_info:
      host1:
          user: root
          passed: xxx
          manage_nic:
              name: xxx
              ip: x.x.x.x
          test_nic1:
              name: xxx
              ip: x.x.x.x
              eid: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
      host2:
          user: root
          passed: xxx
          manage_nic:
              name: xxx
              ip: x.x.x.x
          test_nic1:
              name: xxx
              ip: x.x.x.x
              eid: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
```
**说明：** 
- test_nic1的name、eid分别填写urma_admin show命令查询出来的设备名称和eid，比如bonding_dev_0设备，eid为4245:4944:0000:0000:0000:0000:0200:0000
- test_nic1的ip现在未使用，填写manage_nic的ip即可

#### 三、用例运行
1. UMDK集成测试框架依赖pytest测试框架，使用pytest来运行用例
- 运行单条用例
```bash
  pytest ./umdk/test/intergration_test/test_suites/UMQ/test_umq_demo_pro/test.py
```

- 运行所有集成测试用例
```bash
  cd ./umdk/test/intergration_test
  find ./ -name test.py | xargs -i pytest {}
```
**注意事项：**
- 请在host1上来执行用例
- 日志检查：默认采用rsyslog记录日志，归档在/var/log/umdk/目录，日志文件名称为：二进制名称.log


#### 四、许可

代码使用的许可证详见[LICENSES](./LICENSES/README)

doc目录下的文档使用许可证详见[LICENSE](./doc/LICENSE)