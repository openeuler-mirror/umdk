# UMQ Trace Description

## 1. Log Output Format

The log output by `umq_trace_output_single` consists of three parts:

### Main Record Line
```
#<index> type=<type> umq_id=<id> umq_start=<start_time> umq_end=<end_time> umq_exec=<exec_time> item_cnt=<item_count> ts=<timestamp> tag_ts=<tag_timestamp>;
```

### Item Line (per-buffer metadata)
```
 item[<index>] umq_id=<id> sub_umq_id=<sub_umq_id> msn=<imm_user_data> size=<data_size>;
```

### Sub-time Line (URMA call sub-timing)
```
 sub[<index>] umq_id=<id> func=<URMA_function_name> start=<start_time> exec=<exec_time>;
```

## 2. type Field Values

| Enum Value | Output String | Description |
|------------|---------------|-------------|
| `UMQ_TRACE_TYPE_POST` | POST | umq_post operation |
| `UMQ_TRACE_TYPE_POLL` | POLL | umq_poll operation |
| `UMQ_TRACE_TYPE_WAIT` | WAIT | umq_wait_interrupt operation |
| `UMQ_TRACE_TYPE_REARM` | REARM | umq_rearm_interrupt operation |

## 3. func Field Values

| Enum Value | Output String | URMA API |
|------------|---------------|----------|
| `UMQ_URMA_FUNC_POST_TX` | urma_post_jetty_send_wr | urma_post_jetty_send_wr (IO TX) |
| `UMQ_URMA_FUNC_POST_RX` | urma_post_jetty_recv_wr | urma_post_jetty_recv_wr / urma_post_jfr_wr (IO RX) |
| `UMQ_URMA_FUNC_POLL_TX` | urma_poll_jfc(tx) | urma_poll_jfc (IO TX completion) |
| `UMQ_URMA_FUNC_POLL_RX` | urma_poll_jfc(rx) | urma_poll_jfc (IO RX completion) |
| `UMQ_URMA_FUNC_WAIT_TX_JFC` | urma_wait_jfc(tx) | urma_wait_jfc (TX interrupt wait) |
| `UMQ_URMA_FUNC_WAIT_RX_JFC` | urma_wait_jfc(rx) | urma_wait_jfc (RX interrupt wait) |
| `UMQ_URMA_FUNC_ACK_TX_JFC` | urma_ack_jfc(tx) | urma_ack_jfc (TX interrupt ack) |
| `UMQ_URMA_FUNC_ACK_RX_JFC` | urma_ack_jfc(rx) | urma_ack_jfc (RX interrupt ack) |
| `UMQ_URMA_FUNC_REARM_JFC` | urma_rearm_jfc | urma_rearm_jfc (IO rearm) |
| `UMQ_URMA_FUNC_FC_REARM_JFC` | urma_rearm_jfc(fc) | urma_rearm_jfc (FC rearm) |
| `UMQ_URMA_FUNC_FC_POST_TX` | urma_post_jetty_send_wr(fc) | urma_post_jetty_send_wr (FC credit send) |
| `UMQ_URMA_FUNC_FC_POLL_TX` | urma_poll_jfc(fc tx) | urma_poll_jfc (FC TX completion) |
| `UMQ_URMA_FUNC_FC_POST_RX` | urma_post_jetty_recv_wr(fc) | urma_post_jetty_recv_wr / urma_post_jfr_wr (FC RX post) |
| `UMQ_URMA_FUNC_FC_POLL_RX` | urma_poll_jfc(fc rx) | urma_poll_jfc (FC RX completion) |

---

## 4. Complete Trace Data → Source Function Mapping

### 4.1 type=POST

#### 4.1.1 type=POST, func=urma_post_jetty_send_wr

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_post_tx` | umq_pro_ub.c | IO jetty send data WR |
| `umq_ub_send_imm` | umq_ub.c | IO jetty send data WR |

**Log Example:**
```
#0 type=POST umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=N ts=... tag_ts=0;
 item[0] umq_id=X sub_umq_id=0 msn=<user_data> size=<total_data_size>;
 ...
 sub[0] umq_id=X func=urma_post_jetty_send_wr start=... exec=...;
```

#### 4.1.2 type=POST, func=urma_post_jetty_send_wr(fc)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_shared_credit_req_send` | umq_ub_flow_control.c | FC credit request send |
| `umq_ub_shared_credit_resp_send` | umq_ub_flow_control.c | FC credit response send |
| `umq_ub_shared_credit_return_req_send` | umq_ub_flow_control.c | FC credit return request send |
| `umq_ub_shared_credit_return_ack` | umq_ub_flow_control.c | FC credit return acknowledgment |

**Log Example:**
```
#0 type=POST umq_id=X ...;
 sub[0] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
```

#### 4.1.3 type=POST, func=urma_post_jetty_recv_wr

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_post_rx_inner_impl` | umq_pro_ub.c | IO jetty/jfr post RX WR |

**Log Example:**
```
#0 type=POST umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=0 ts=... tag_ts=<tag_timestamp>;
 sub[0] umq_id=X func=urma_post_jetty_recv_wr start=... exec=...;
```

---

### 4.2 type=POLL

#### 4.2.1 type=POLL, func=urma_poll_jfc(rx)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_poll_rx` | umq_pro_ub.c | IO jfr poll RX completion |

**Log Example:**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
 ...
```

#### 4.2.2 type=POLL, func=urma_poll_jfc(tx)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_poll_tx_single` | umq_pro_ub.c | IO jfs poll TX completion |

**Log Example:**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(tx) start=... exec=...;
```

#### 4.2.3 type=POLL, func=urma_poll_jfc(fc rx)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `main_umq_ub_poll_fc_rx` | umq_pro_ub.c | FC jfr poll RX completion |
| `umq_ub_poll_fc_rx` | umq_pro_ub.c | FC jfr poll RX completion |

**Log Example (within umq_ub_poll_rx POLL record):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
```

#### 4.2.4 type=POLL, func=urma_poll_jfc(fc tx)

| Source Function | Source File | sub_time Context | Call Scenario |
|-----------------|-------------|------------------|---------------|
| `umq_ub_poll_fc_tx` | umq_pro_ub.c | FC jfs poll TX completion | Called within umq_ub_poll_tx_single |

**Log Example (within umq_ub_poll_tx_single POLL record):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc tx) start=... exec=...;
```

#### 4.2.5 type=POLL, func=urma_post_jetty_recv_wr(fc)

| Source Function | Source File | sub_time Context | Call Scenario |
|-----------------|-------------|------------------|---------------|
| `umq_ub_fill_fc_rx_buf` | umq_pro_ub.c | FC RX buffer refill (post recv WR) | Called after umq_ub_poll_fc_rx / main_umq_ub_poll_fc_rx processes FC messages to replenish RX buffers |

**Log Example (within umq_ub_poll_rx POLL record):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_recv_wr(fc) start=... exec=...;
```

#### 4.2.6 type=POLL, func=urma_post_jetty_send_wr(fc)

| Source Function | Source File | sub_time Context | Call Scenario |
|-----------------|-------------|------------------|---------------|
| `umq_ub_shared_credit_resp_send` | umq_ub_flow_control.c | FC credit response send | Sends credit response after umq_ub_poll_rx processes FC credit request |
| `umq_ub_shared_credit_return_req_send` | umq_ub_flow_control.c | FC credit return request send | Sends credit return request when umq_ub_poll_tx_single detects credits need to be returned |
| `umq_ub_shared_credit_return_ack` | umq_ub_flow_control.c | FC credit return acknowledgment send | Sends credit return ack after umq_ub_poll_rx processes credit return request |

**Log Example (credit response, within umq_ub_poll_rx POLL record):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
 sub[2] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
```

**Log Example (credit return request, within umq_ub_poll_tx_single POLL record):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc tx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
 sub[2] umq_id=X func=urma_poll_jfc(tx) start=... exec=...;
```

---

### 4.3 type=WAIT

#### 4.3.1 type=WAIT, func=urma_wait_jfc(rx) + urma_ack_jfc(rx)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_wait_rx_interrupt` | umq_ub.c | RX direction wait + ack |

**Log Example:**
```
#0 type=WAIT umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=0 ts=... tag_ts=<tag_timestamp>;
 sub[0] umq_id=X func=urma_wait_jfc(rx) start=... exec=...;
 sub[1] umq_id=X func=urma_ack_jfc(rx) start=... exec=...;
```

#### 4.3.2 type=WAIT, func=urma_wait_jfc(tx) + urma_ack_jfc(tx)

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_wait_tx_interrupt` | umq_ub.c | TX direction wait + ack |
| `umq_ub_wait_tp_handle_tx_interrupt` | umq_ub.c | TP handle TX direction wait + ack |

**Log Example:**
```
#0 type=WAIT umq_id=X ...;
 sub[0] umq_id=X func=urma_wait_jfc(tx) start=... exec=...;
 sub[1] umq_id=X func=urma_ack_jfc(tx) start=... exec=...;
```

---

### 4.4 type=REARM

#### 4.4.1 type=REARM, func=urma_rearm_jfc

| Source Function | Source File | sub_time Context |
|-----------------|-------------|------------------|
| `umq_ub_rearm_impl` (tp_handle path) | umq_ub_impl.c | IO JFC rearm (tp_handle) |
| `umq_ub_rearm_impl` (TX direction) | umq_ub_impl.c | IO JFC rearm (TX) |
| `umq_ub_rearm_impl` (RX direction) | umq_ub_impl.c | IO JFC rearm (RX) |

**Log Example (TX rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
 sub[1] umq_id=X func=urma_rearm_jfc(fc) start=... exec=...;
```

**Log Example (RX rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
```

#### 4.4.2 type=REARM, func=urma_rearm_jfc(fc)

| Source Function | Source File | sub_time Context | Call Scenario |
|-----------------|-------------|------------------|---------------|
| `umq_ub_rearm_impl` (tp_handle path) | umq_ub_impl.c | FC JFC rearm (tp_handle) | TP handle scenario + FC enabled |
| `umq_ub_rearm_impl` (TX direction) | umq_ub_impl.c | FC jfs_jfc rearm (TX) | direction == UMQ_IO_TX + FC enabled |
| `umq_ub_rearm_impl` (RX direction) | umq_ub_impl.c | FC jfr_jfc rearm (RX) | direction == UMQ_IO_RX + FC enabled |

**Log Example (TX rearm + FC rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
 sub[1] umq_id=X func=urma_rearm_jfc(fc) start=... exec=...;
```

> Note: `umq_ub_rearm_impl` is the outer function that calls `start_record(UMQ_TRACE_TYPE_REARM)` and `end_record`; the inner URMA rearm calls execute `sub_record`.
