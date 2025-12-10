## 概述

URPC是统一远程过程调用协议，其基于UB事务层提供的能力，支持任意UB设备之间直接发起对等函数调用。URPC职能角色和协议流程如下：

![](./figures/URPC_Functional_Roles.png)

**URPC职能角色**
-   <u>**Client**</u>：URPC的发起端和调用者，向Server发送URPC Request，等待URPC Ack和URPC Response的返回；
-   <u>**Server**</u>：URPC的接收端和分配者，接收URPC Request，调用Worker执行，向Client回复URPC Ack和URPC Response；
-   <u>**Worker**</u>：URPC的执行者，专注执行URPC调用的函数、功能、服务。

*注1：URPC Ack将在之后版本提供服务。* \
*注2：Caller：基于 URPC 协议发起远程过程调用的用户。* \
*注3：Callee：URPC 函数的具体实现方，根据需求可以与 Worker 合并。*

**URPC Message类型**
- **URPC Request**：由 Client 发送给 Server，用于发起函数调用行为；
- **URPC Ack**：由 Server 返回给 Client，表示参数传递完成，并触发 Client 释放参数的内存空间；
- **URPC Response**：由 Server 返回给 Client，表示函数执行完成并返回结果。

**URPC协议流程**
- 用户Caller触发Client发起远程函数调用；
- Client向Sevrer发送URPC Request消息，携带函数唯一标识和参数信息；
- Server接收到函数唯一标识和参数信息，向Client回复URPC Ack通知其参数传递完成；
- Server将函数分配给某一Worker执行；
- Worker基于函数唯一标识触发Callee执行对应函数，在函数执行完毕后将结果通过URPC Response返回给Client；
- Client收到URPC Response，将远程函数调用结果返回给用户Caller；

*注1：URPC Ack是否需要由Client决定。* \
*注2：URPC Ack与URPC Response是否合并由Server决定。如果合并，函数执行完毕后Server将结果通过URPC Ack&Resonse合并消息返回Client，通知其参数传递完毕，同时一并将结果返回。*

**URPC创新特性**
- 对等函数调用：任意UB设备之间可以直接发起函数调用；
- 引用传参：支持Worker基于参数引用（参数数据地址）发起参数数据搬移；

## 对等函数调用

![](./figures/URPC_Peer-to-Peer_Protocol_Architecture.png)

基于URPC协议，Client/Server/Worker可根据场景的诉求，实现为UB设备实体。
受益于UB对等互访的架构设计，在任意UB设备上实现的Client，都可以通过发送URPC Message，向其它UB设备上实现的Server/Worker发起远程函数调用。

典型应用如：UB设备（NPU）直接向UB设备（SSU）发起远程存储写的函数调用，采用此方式，AI训练或推理数据从NPU直接发到SSU上执行存储。


## 引用传参
URPC支持如下三种参数传递方式：

![](./figures/URPC_Parameter_Passing_Method.png)

- 值传递（内联）：参数数据和URPC协议头合并到一条URPC Request消息，由Client发送给Server；
- 值传递（外联）：参数数据地址和URPC协议头合并到一条URPC Request消息，由Client发送给Server，Server在收到参数数据地址后通过Read或者Load语义向Client拉取完整的参数数据；
- 引用传递：参数数据地址和URPC协议头合并到一条URPC Request消息，由Client发送给Server，Server将参数数据地址传递给Worker，由Worker通过Read或者Load语义向Client拉取完整的参数数据；

相较于值传递的方式，引用传递将参数传递的时机开放给Worker控制，从而让其有更大的灵活性协调参数传递和函数执行时机。

更多URPC参数传递方式的特点以及适用场景如下：

| 参数传递方式     | 特点 | 适用场景 |
|------------------|------|----------|
| 值传递（内联）   | ● 参数数据大小受 URPC Request 的大小上限约束；<br>● 参数数据随 URPC Request 传递，参数传递需 0.5 个 RTT；<br>● 参数数据从 Client 传递给 Server，再传递给 Worker | 参数数据小，内存资源充足<br>例如：存储场景，数据大小 40K 以下 |
| 值传递（外联）   | ● 参数数据大小不受 URPC Request 的大小上限约束；<br>● Server 接收 URPC Request 后，再发起参数传输，参数传递需 1.5 个 RTT；<br>● 参数数据从 Client 传递给 Server，再传递给 Worker；<br>● Server 拉取参数数据后，Worker 开始执行函数时，Client 即可释放参数的内存资源 | 参数数据大，内存资源不足<br>例如：存储场景，数据大小 40K 以上 |
| 引用传递         | ● 参数数据大小不受 URPC Request 的大小上限约束；<br>● Worker 开始执行函数后，发起参数传输，参数传递需 1.5 个 RTT；<br>● 参数数据从 Client 直接传递给 Worker，传递时机由 Worker 灵活可控；<br>● Worker 执行函数拉取参数数据后，Client 才可释放参数的内存资源 | 参数传递和函数执行时间较接近<br>例如：AI 训练/推理场景，数据传输和 NPU 运算需相互掩盖执行时间 |

*注：RTT（Round-Trip Time）表示往返时间。*
