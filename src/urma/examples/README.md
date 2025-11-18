# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

# UBus

===============================================================================
Notes on running urma sample
===============================================================================

You can run urma sample programs on two hosts the following steps:

1. Build and install
- You can build and install the urma_sample as follows:
  $ cd src
  $ mkdir build
  $ cd build
  $ cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable
  $ make install -j


2. Check Local Device
You need to ensure that the urma environment has been correctly configured.

- check Local Device by:
$ urma_admin show

3. Start urma sample program
- The sample program exist in UMDK/src/build/urma/examples.
 You can run the "server command" at the first server and run the client command at the second server.
 The ip of the first server is 192.168.100.100 in our test.

Usage:
  -m, --trans-mode <mode>    urma mode: 0 for RM, 1 for RC, 2 for UM, 3 for RS (default 0)
  -d, --dev-name <dev>       device name, e.g. udma for UB
  -i, --server-ip <ip>       server ip address given only by client
  -p, --server-port <port>   listen on/connect to port <port> (default 18515)
  -t, --tp-type <type>       0 for URMA_RTP, 1 for URMA_CTP, 2 for URMA_UTP
  -u, --multi-path           use multipath instead of single path (default false)
  -e, --event-mode           demo jfc event (default false)
  -c, --cs-coexist           client and server coexist in a process (default false)


- The transmode of RS and UM is not support in urma_sample.c!

- Here are the supported use cases:
| **device**  | **trnas_mode(m)** | **multi_path(u)**      | **tp_type(t)**             | **server command**                     | **client command**                                        |
|-------------|-------------------|------------------------|----------------------------|----------------------------------------|-----------------------------------------------------------|
| **bonding** | RM（0）           | TRUE                   | unsupported param,warnning | ./urma_sample -m 0 -u -d bonding_dev_0 | ./urma_sample -m 0 -u -d bonding_dev_0 -i 192.168.100.100 |
| **bonding** | RC（1）           | TRUE                   | unsupported param,warnning | ./urma_sample -m 1 -u -d bonding_dev_0 | ./urma_sample -m 1 -u -d bonding_dev_0 -i 192.168.100.100 |
| **bonding** | RC（1）           | FALSE                  | unsupported param,warnning | ./urma_sample -m 1 -d bonding_dev_0    | ./urma_sample -m 1 -d bonding_dev_0 -i 192.168.100.100    |
| **udma**    | RM（0）           | unsupported param,err! | URMA_RTP(0)                | ./urma_sample -m 0 -t 0 -d udma2       | ./urma_sample -m 0 -t 0 -d udma2 -i 192.168.100.100       |
| **udma**    | RC（1）           | unsupported param,err! | URMA_RTP(0)                | ./urma_sample -m 1 -t 0 -d udma2       | ./urma_sample -m 1 -t 0 -d udma2 -i 192.168.100.100       |
| **udma**    | RM（0）           | unsupported param,err! | URMA_CTP(1)                | ./urma_sample -m 0 -t 1 -d udma2       | ./urma_sample -m 0 -t 1 -d udma2 -i 192.168.100.100       |
| **udma**    | RC（1）           | unsupported param,err! | URMA_CTP(1)                | ./urma_sample -m 1 -t 1 -d udma2       | ./urma_sample -m 1 -t 1 -d udma2 -i 192.168.100.100       |

