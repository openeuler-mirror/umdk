# UMQ IO

## 功能简介
UMQ IO 是 UMQ 组件体系中的数据面IO处理引擎，专门负责高效、异步的数据面IO操作管理. 它提供了umq_post/umq_poll接口进行IO处理

**概述**:
    (1) post/poll方式更灵活，用户可以通过poll tx感知到post tx的完成事件，同时需要用户调用post rx 补充接收数据的buffer

**应用场景**：
    post/poll处理IO

**使用说明**：
```mermaid
%% 时序图例子,-> 直线，-->虚线，->>实线箭头
sequenceDiagram
    participant Client as app client
    participant Server as app server

    Note over Client,Server: 1. initialization phase
    Client->>Client: umq_init initializes umq resources
    Server->>Server: umq_init initializes umq resources

    Note over Client,Server: 2. create a UMQ instance
    Client->>Client: umq_create creates umqh
    Client->>Client: `umq_bind_info_get` retrieves the local bindinfo information.
    Server->>Server: umq_create creates umqh
    Server->>Server: `umq_bind_info_get` retrieves the local bindinfo information.

    Note over Client,Server: 3. Information Exchange Phase
    Client->>Server: send bindinfo information and request bindinfo information from the peer.
    Server-->>Client: Send bindinfo information

    Note over Client,Server: 4. bind phase
    Client->>Client: umq_bind
    Server->>Server: umq_bind

    Note over Client,Server: UMQ connection established

    Note over Client,Server: 5. Data plane transmit IO phase

    loop continuous data transfer
        Note over Client: apply preparation data
        Client->>Client: umq_buf_alloc allocates memory in preparation for sending data.
        Client->>Client: umq_post, io_direction = UMQ_IO_TX, prepare to send data
        Client->>Server: Data packet
        Client->>Client: umq_poll, io_direction = UMQ_IO_TX, confirm sending completed

        Note over Server: Application polling waits for data
        loop Until the return value of umq_poll is greater than 0
            Server->>Server: umq_poll, io_direction = UMQ_IO_RX receive data
        end
        Server->>Server: Process data
        Server->>Server: umq_buf_free releases data
        Server->>Server: umq_buf_alloc allocates a new buffer
        Server->>Server: umq_post,io_direction = UMQ_IO_RX, supplemental receive buffer
    end

    Note over Client,Server: 6. disconnect phase
    Client->>Client: umq_unbind
    Server->>Server: umq_unbind
    Client->>Client: umq_destroy destroys umqh
    Server->>Server: umq_destroy destroys umqh
    Client->>Client: umq_uninit is used for initialization.
    Server->>Server: umq_uninit is used for initialization.
```


