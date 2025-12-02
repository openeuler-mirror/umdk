# UMQ Flowcontrol

## Overview
UMQ supports enabling flow control in UB mode, which determines whether the local UMQ can send packets based on the real-time rx-depth of the peer UMQ.

When flow control is enabled, UMQ uses IO immediate data ​​to exchange the available rx-depth of the UMQ, and occupies 1 bit (LSB) in the IO immediate data to distinguish whether the immediate data is used by application IO or by an internal UMQ process. Therefore, in this scenario, applications need to be aware that they can only use a maximum of 63 bits of immediate data space.

UMQ flow control maintains two counters: local_rx_posted and remote_rx_window. These counters represent the number of receive buffers posted to the local UMQ (incremented when umq_post is executed on the local UMQ to fill the receive buffers), and the available depth of the peer UMQ when the local UMQ receives a notification from the peer (incremented when the number of receive buffers is received from the peer).

During the UMQ initialization phase, when the receive buffer count is filled to the initial_window (which defaults to half the rx-depth), UMQ internally sets this initial value to memory available for the peer UMQ to read, for updating the remote_rx_window initial value. Subsequently, whenever the local_rx_posted count update interval meets the notify_interval, UMQ attempts to send the available depth of the local UMQ in the application I/O immediate data (if the application does not use immediate data), or directly sends an immediate data indicating the available depth of the local UMQ.

After the peer UMQ receives the notification, it increments the remote_rx_window counter and sets the status in umq_buf_t to UMQ_BUF_FLOW_CONTROL_UPDATE. The application can determine when to continue sending packets based on this status.

When sending I/O, if it needs to consume the peer UMQ's receive queue buffer, such as UMQ_OPC_SEND/UMQ_OPC_SEND_IMM/UMQ_OPC_WRITE_IMM, UMQ will internally attempt to allocate a remote_rx_window based on the number of WRs sent. If the remote_rx_window is insufficient, it will return -UMQ_ERR_EAGAIN and set bad_qbuf to point to the qbuf where the transmission failed.

**Instructions for Use**:

Configurable Parameter Description
* initial_window: Provides the initial window value for remote reading, which is set to half of the rx-depth by default
* notify_interval: The interval at which the local UMQ notifies the peer UMQ is set to one-sixteenth of the rx-depth by default
* use_atomic_window: Whether flow control related counters are maintained using atomic variables should be set to true in scenarios where there is concurrency in sending and receiving packets within the same UMQ

Statistical Information Query
* local_rx_posted: The number of receive buffers currently posted to the local UMQ
* remote_rx_window: The current available depth of the peer UMQ announced
* total_local_rx_posted: Total number of receive buffers posted in the local UMQ
* total_local_rx_notified: The total number of receive buffers that was notified by this end
* total_local_rx_posted_error: Total number of receive buffers posted which will cause overflow
* total_remote_rx_received: Total available depth announced from the peer UMQ
* total_remote_rx_consumed: Total available depth consumed during the packet sending process
* total_remote_rx_received_error: Received an invalid peer available depth notification which will cause overflow
* total_flow_controlled_wr: The number of packets failed to send due to insufficient depth of the peer UMQ

The following is an example of using the statistical query interface：
```
umq_flowcontrol_stats_t s = {0};
umq_user_ctl_in_t in = {.opcode = UMQ_OPCODE_FLOW_CONTROL_STATS_QUERY};
umq_user_ctl_out_t out = {.addr = &s, .len = sizeof(s)};
int ret = umq_user_ctl(umqh, &in, &out);
...
```
