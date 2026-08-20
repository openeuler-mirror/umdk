# UMQ Trace Description

## 1. 日志输出格式

`umq_trace_output_single` 输出的日志由三部分组成：

### 主记录行
```
#<序号> type=<类型> umq_id=<id> umq_start=<起始时间> umq_end=<结束时间> umq_exec=<执行时间> item_cnt=<项数> ts=<时间戳> tag_ts=<标签时间戳>;
```

### item 行（每个 buffer 的元数据）
```
 item[<序号>] umq_id=<id> sub_umq_id=<子umq id> msn=<即时数据用户数据> size=<数据大小>;
```

### sub_time 行（URMA 调用的子计时）
```
 sub[<序号>] umq_id=<id> func=<URMA函数名> start=<起始时间> exec=<执行时间>;
```

## 2. type 字段取值

| 枚举值 | 输出字符串 | 含义 |
|--------|-----------|------|
| `UMQ_TRACE_TYPE_POST` | POST | umq_post 操作 |
| `UMQ_TRACE_TYPE_POLL` | POLL | umq_poll 操作 |
| `UMQ_TRACE_TYPE_WAIT` | WAIT | umq_wait_interrupt 操作 |
| `UMQ_TRACE_TYPE_REARM` | REARM | umq_rearm_interrupt 操作 |

## 3. func 字段取值

| 枚举值 | 输出字符串 | URMA API |
|--------|-----------|----------|
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

## 4. 完整 trace 数据 → 源函数映射表

### 4.1 type=POST

#### 4.1.1 type=POST, func=urma_post_jetty_send_wr

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_post_tx` | umq_pro_ub.c | IO jetty 发送数据 wr |
| `umq_ub_send_imm` | umq_ub.c | IO jetty 发送数据wr |

**日志示例:**
```
#0 type=POST umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=N ts=... tag_ts=0;
 item[0] umq_id=X sub_umq_id=0 msn=<user_data> size=<total_data_size>;
 ...
 sub[0] umq_id=X func=urma_post_jetty_send_wr start=... exec=...;
```

#### 4.1.2 type=POST, func=urma_post_jetty_send_wr(fc)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_shared_credit_req_send` | umq_ub_flow_control.c | FC credit 请求发送 |
| `umq_ub_shared_credit_resp_send` | umq_ub_flow_control.c | FC credit 响应发送 |
| `umq_ub_shared_credit_return_req_send` | umq_ub_flow_control.c | FC credit 归还请求发送 |
| `umq_ub_shared_credit_return_ack` | umq_ub_flow_control.c | FC credit 归还确认 |

**日志示例:**
```
#0 type=POST umq_id=X ...;
 sub[0] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
```

#### 4.1.3 type=POST, func=urma_post_jetty_recv_wr

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_post_rx_inner_impl` | umq_pro_ub.c | IO jetty/jfr post RX wr |

**日志示例:**
```
#0 type=POST umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=0 ts=... tag_ts=<tag_timestamp>;
 sub[0] umq_id=X func=urma_post_jetty_recv_wr start=... exec=...;
```

---

### 4.2 type=POLL

#### 4.2.1 type=POLL, func=urma_poll_jfc(rx)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_poll_rx` | umq_pro_ub.c | IO jfr poll RX completion |

**日志示例:**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
 ...
```

#### 4.2.2 type=POLL, func=urma_poll_jfc(tx)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_poll_tx_single` | umq_pro_ub.c | IO jfs poll TX completion |

**日志示例:**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(tx) start=... exec=...;
```


#### 4.2.3 type=POLL, func=urma_poll_jfc(fc rx)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `main_umq_ub_poll_fc_rx` | umq_pro_ub.c | FC jfr poll RX completion |
| `umq_ub_poll_fc_rx` | umq_pro_ub.c | FC jfr poll RX completion |

**日志示例 (在 umq_ub_poll_rx 的 POLL record 内):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
```

#### 4.2.4 type=POLL, func=urma_poll_jfc(fc tx)

| 源函数 | 源文件 | sub_time 上下文 | 调用场景 |
|--------|--------|----------------|----------|
| `umq_ub_poll_fc_tx` | umq_pro_ub.c | FC jfs poll TX completion | 在 umq_ub_poll_tx_single 内被调用 |

**日志示例 (在 umq_ub_poll_tx_single 的 POLL record 内):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc tx) start=... exec=...;
```

#### 4.2.5 type=POLL, func=urma_post_jetty_recv_wr(fc)

| 源函数 | 源文件 | sub_time 上下文 | 调用场景 |
|--------|--------|----------------|----------|
| `umq_ub_fill_fc_rx_buf` | umq_pro_ub.c | FC RX buffer 回填 (post recv wr) | 在 umq_ub_poll_fc_rx / main_umq_ub_poll_fc_rx 处理 FC 消息后补充 RX buffer |

**日志示例 (在 umq_ub_poll_rx 的 POLL record 内):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_recv_wr(fc) start=... exec=...;
```

#### 4.2.6 type=POLL, func=urma_post_jetty_send_wr(fc)

| 源函数 | 源文件 | sub_time 上下文 | 调用场景 |
|--------|--------|----------------|----------|
| `umq_ub_shared_credit_resp_send` | umq_ub_flow_control.c | FC credit 响应发送 | 在 umq_ub_poll_rx 处理 FC credit req 后发送 credit resp |
| `umq_ub_shared_credit_return_req_send` | umq_ub_flow_control.c | FC credit 归还请求发送 | 在 umq_ub_poll_tx_single 检测到需要归还 credit 时发送 |
| `umq_ub_shared_credit_return_ack` | umq_ub_flow_control.c | FC credit 归还确认发送 | 在 umq_ub_poll_rx 处理 credit return req 后发送 ack |

**日志示例 (credit resp，在 umq_ub_poll_rx 的 POLL record 内):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc rx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
 sub[2] umq_id=X func=urma_poll_jfc(rx) start=... exec=...;
```

**日志示例 (credit return req，在 umq_ub_poll_tx_single 的 POLL record 内):**
```
#0 type=POLL umq_id=X ...;
 sub[0] umq_id=X func=urma_poll_jfc(fc tx) start=... exec=...;
 sub[1] umq_id=X func=urma_post_jetty_send_wr(fc) start=... exec=...;
 sub[2] umq_id=X func=urma_poll_jfc(tx) start=... exec=...;
```

---

### 4.3 type=WAIT

#### 4.3.1 type=WAIT, func=urma_wait_jfc(rx) + urma_ack_jfc(rx)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_wait_rx_interrupt` | umq_ub.c | RX 方向 wait + ack |

**日志示例:**
```
#0 type=WAIT umq_id=X umq_start=... umq_end=... umq_exec=... item_cnt=0 ts=... tag_ts=<tag_timestamp>;
 sub[0] umq_id=X func=urma_wait_jfc(rx) start=... exec=...;
 sub[1] umq_id=X func=urma_ack_jfc(rx) start=... exec=...;
```

#### 4.3.2 type=WAIT, func=urma_wait_jfc(tx) + urma_ack_jfc(tx)

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_wait_tx_interrupt` | umq_ub.c | TX 方向 wait + ack |
| `umq_ub_wait_tp_handle_tx_interrupt` | umq_ub.c | TP handle TX 方向 wait + ack |

**日志示例:**
```
#0 type=WAIT umq_id=X ...;
 sub[0] umq_id=X func=urma_wait_jfc(tx) start=... exec=...;
 sub[1] umq_id=X func=urma_ack_jfc(tx) start=... exec=...;
```

---

### 4.4 type=REARM

#### 4.4.1 type=REARM, func=urma_rearm_jfc

| 源函数 | 源文件 | sub_time 上下文 |
|--------|--------|----------------|
| `umq_ub_rearm_impl` (tp_handle path) | umq_ub_impl.c | IO jfc rearm (tp_handle) |
| `umq_ub_rearm_impl` (TX direction) | umq_ub_impl.c | IO jfc rearm (TX) |
| `umq_ub_rearm_impl` (RX direction) | umq_ub_impl.c | IO jfc rearm (RX) |

**日志示例 (TX rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
 sub[1] umq_id=X func=urma_rearm_jfc(fc) start=... exec=...;
```

**日志示例 (RX rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
```

#### 4.4.2 type=REARM, func=urma_rearm_jfc(fc)

| 源函数 | 源文件 | sub_time 上下文 | 调用场景 |
|--------|--------|----------------|----------|
| `umq_ub_rearm_impl` (tp_handle path) | umq_ub_impl.c | FC jfc rearm (tp_handle) | TP handle 场景 + FC 开启 |
| `umq_ub_rearm_impl` (TX direction) | umq_ub_impl.c | FC jfs_jfc rearm (TX) | direction == UMQ_IO_TX + FC 开启 |
| `umq_ub_rearm_impl` (RX direction) | umq_ub_impl.c | FC jfr_jfc rearm (RX) | direction == UMQ_IO_RX + FC 开启 |

**日志示例 (TX rearm + FC rearm):**
```
#0 type=REARM umq_id=X ...;
 sub[0] umq_id=X func=urma_rearm_jfc start=... exec=...;
 sub[1] umq_id=X func=urma_rearm_jfc(fc) start=... exec=...;
```

> 注意：`umq_ub_rearm_impl` 是外层函数，执行 `start_record(UMQ_TRACE_TYPE_REARM)` 和 `end_record`；内部 URMA rearm 调用执行 `sub_record`。
