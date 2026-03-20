# UMQ Flowcontrol

## Overview
UMQ supports enabling flow control in UB mode, which determines whether the local UMQ can send packets based on the real-time rx-depth of the peer UMQ.

**Instructions for Use**:

Configurable Parameter Description
* initial_credit: Sets the initial amount of credit requested from the peer
* max_credits_request: The interval at which the local UMQ notifies the peer UMQ is set to one-sixteenth of the rx-depth by default
* use_atomic_window: Whether flow control related counters are maintained using atomic variables should be set to true in scenarios where there is concurrency in sending and receiving packets within the same UMQ
* credit_multiple: Adaptive multiplier for request adjustment. If the credit granted by the peer equals the requested amount, the next request is multiplied by this value; otherwise, it is divided by this value
* return_ratio: Ratio for returning credit
* min_reserved_credit: When the held peer credit is less than or equal to this value, the local side will initiate another credit request
* timeout_ms: Timeout period. If no I/O is sent within timeout_ms, the local side will actively return the held peer credit

Statistical Information Query
The main UMQ credit pool statistics structure umq_credit_pool_stats contains the following key information:
* pool_idle: Currently available credit in the pool, indicating the available buffers in the local main queue's receive buffer queue
* pool_be_allocated: Currently allocated credit, indicating buffers allocated from the main queue's receive buffer queue
* total_pool_idle: Cumulative total of currently available credit
* total_pool_be_allocated: Cumulative total of allocated credit
* total_pool_post_rx_err: Total amount of invalid credit (which would cause pool_idle statistics overflow)

The sub-UMQ credit statistics structure umq_credit_private_stats_t mainly contains the following key information:
* queue_idle: Reserved field, always 0
* queue_be_allocted: Current amount of credit allocated to the peer for this queue when acting as receiver
* queue_acquired: Current amount of peer credit held for this queue when acting as sender
* total_queue_idle: Reserved field, always 0
* total_queue_acquired: Cumulative total of peer credit held for this queue since startup
* total_queue_be_allocated: Cumulative total of credit allocated for this queue since startup
* total_queue_post_tx_success: Cumulative count of successfully sent I/O requests (WRs) when acting as sender
* total_queue_post_tx_err: Cumulative count of failed I/O requests due to insufficient peer credit when acting as sender
* total_queue_acquired_err: Cumulative count of credit count anomalies (e.g., overflow) caused by illegal operations

The sub-UMQ flow control packet statistics structure umq_packet_stats_t mainly contains the following key information:
* send_cnt: Number of times flow control packets are sent
* send_success: Number of times flow control packets are successfully sent
* recv_cnt: Number of times flow control requests are received
* send_error_cnt: Number of times flow control packet sending fails
* recv_error_cnt: Number of times flow control request reception fails

The following is an example of using the statistics query interface:
```
umq_flow_control_stats_t flow_control_stats = {0};
int ret = umq_stats_flow_control_get((uint64_t)(uintptr_t)(&umq), &flow_control_stats);
...
```