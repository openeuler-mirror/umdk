# UMQ Flowcontrol

## 功能简介
UMQ支持在UB模式下启用流量控制功能，根据对端UMQ的接收队列实时可用深度确定本端UMQ是否可执行发包。

## 使用说明
可配置参数说明：
* initial_credit：设置首次向对端请求的信用数量
* max_credits_request：本端每次请求信用的最大值，当持有的对端信用低于阈值时，本端会再次发起请求，但每次请求量不超过该值
* use_atomic_window：流量控制相关计数是否采用原子变量维护，在同一个UMQ收发包存在并发的场景需设置为true
* credit_multiple：自适应调整请求量的倍数，若对端实际授予的信用等于本次请求的数量，则下次请求量乘以该倍数，否则除以该倍数
* return_ratio：归还credit的比例
* min_reserved_credit：当持有的对端信用低于或者等于此值时，本端会再次发起请求
* timeout_ms：超时时间，若本端在timeout_ms内未发送I/O，则主动归还持有的对端信用

统计信息查询：
主UMQ信用池统计信息结构体umq_credit_pool_stats有以下关键信息：
* pool_idle：当前Pool可用的信用数量，指当前本端主UMQ接收缓存队列中可用的缓存数
* pool_be_allocated：当前被分配取走的信用数量,指当前从主UMQ接收缓存队列中被分配走的缓存数
* total_pool_idle：当前可用信用累计总数
* total_pool_be_allocated：当前累计被分配取走的信用总数
* total_pool_post_rx_err：不合法（会导致pool_idle统计溢出）信用总数

子UMQ信用统计信息结构体umq_credit_private_stats_t主要有以下关键信息：
* queue_idle：保留字段，始终为0
* queue_be_allocted：当前本端作为接收方，为该队列已分配给对端的信用数
* queue_acquired：当前本端作为发送方，为该队列持有的对端信用数
* total_queue_idle：保留字段，始终为0
* total_queue_acquired：从启动至今，本端为该队列累计持有的对端信用总数
* total_queue_be_allocated：从启动至今，本端为该队列累计被分配的信用总数
* total_queue_post_tx_success：本端作为发送方，成功发送I/O请求（WR）累计次数
* total_queue_post_tx_err：本端作为发送方，因持有的对端信用不足而发送失败的I/O请求累计次数
* total_queue_acquired_err：因非法操作导致信用计数异常（如溢出）的累计值

子UMQ流控报文统计信息结构体umq_packet_stats_t主要有以下关键信息：
* send_cnt：流控报文发送的次数
* send_success：流控报文成功发送的次数
* recv_cnt：流控请求接收的次数
* send_error_cnt：流控报文发送失败的次数
* recv_error_cnt：流控请求接收失败的次数

统计查询接口使用示例如下：
```
umq_flow_control_stats_t flow_control_stats = {0};
int ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
...
```