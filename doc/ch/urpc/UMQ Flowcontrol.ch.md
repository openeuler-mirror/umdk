# UMQ Flowcontrol

## 功能简介
UMQ支持在UB模式下启用流量控制功能，根据对端UMQ的接收队列实时可用深度确定本端UMQ是否可执行发包。

启用流量控制时，UMQ会使用IO立即数交换接收队列的可用深度，并且在IO立即数中占用1bit位（LSB）用于区分该立即数是应用IO，还是UMQ内部流程使用的。因此，该场景下应用需关注，最多只能使用63bit立即数空间。

UMQ流量控制维护了local_rx_posted和remote_rx_window两个计数，分别表示本端接收队列中下发的接收缓存数（在本端UMQ执行umq_post填充接收缓存时增加计数），以及本端接收到对端通告的对端接收队列可用深度（在接收到对端通告的接收缓存数时增加计数）。

在UMQ初始化阶段，当第一次填充接收缓存数满足initial_window（默认为接收队列深度的一半）时，UMQ内部会将该初始值设置到可供对端UMQ读取的内存中，用于remote_rx_window初值更新。后续每当local_rx_posted计数更新间隔满足notify_interval后，UMQ会尝试在应用IO的立即数中携带本端接收队列可用深度（如果应用未使用立即数），或者直接发送一个立即数，表示本端接收队列的可用深度，以向对端通告本端的接收队列可用深度。

对端UMQ接收到该通告立即数以后，增加remote_rx_window计数，并在umq_buf_t中设置status为UMQ_BUF_FLOW_CONTROL_UPDATE，应用可根据该状态确定继续发包的时机。

当发送IO时，如果需要消耗对端的接收队列缓存，如UMQ_OPC_SEND/UMQ_OPC_SEND_IMM/UMQ_OPC_WRITE_IMM，UMQ内部会尝试根据发送wr的数量申请remote_rx_window，如果remote_rx_window不足，则返回-UMQ_ERR_EAGAIN，并且将bad_qbuf指向未成功发送的qbuf处。

## 使用说明
可配置参数说明：
* initial_window: 提供远端读取的窗口初始值，默认设置为接收队列深度的一半
* notify_interval: 向对端通告本端接收队列可用深度的间隔，默认设置为接收队列的十六分之一
* use_atomic_window: 流量控制相关计数是否采用原子变量维护，在同一个UMQ收发包存在并发的场景需设置为true

统计信息查询：
* local_rx_posted: 当前本端接收队列中下发的接收缓存数
* remote_rx_window: 当前对端通告的对端接收队列可用深度
* total_local_rx_posted: 本端接收队列中下发的接收缓存总数
* total_local_rx_notified: 本端发出通告的本端接收队列可用深度总数
* total_local_rx_posted_error: 不合法（会导致统计溢出）的本端接收队列可用深度统计
* total_remote_rx_received: 接收到对端通告的对端接收队列可用深度总数
* total_remote_rx_consumed: 发包流程中消耗的对端接收队列可用深度总数
* total_remote_rx_received_error: 接收到不合法（会导致统计溢出）的对端接收队列深度通告数
* total_flow_controlled_wr: 本端发包由于对端接收队列可用深度不足失败的wr数量

统计查询接口使用示例如下：
```
umq_flow_control_stats_t s = {0};
umq_user_ctl_in_t in = {.opcode = UMQ_OPCODE_FLOW_CONTROL_STATS_QUERY};
umq_user_ctl_out_t out = {.addr = &s, .len = sizeof(s)};
int ret = umq_user_ctl(umqh, &in, &out);
...
```
