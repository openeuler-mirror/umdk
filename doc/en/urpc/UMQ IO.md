# UMQ IO

## Function Introduction
UMQ IO is the data plane I/O processing engine in the UMQ component system, specifically responsible for efficient, asynchronous data plane I/O operation management. It provides the umq_post/umq_poll interfaces for I/O processing.

**Overview**:
    (1) the post/poll method is more flexible. Users can detect the completion event of post tx through poll tx, and at the same time, users need to call post rx to replenish the buffer for receiving data.

**Application Scenarios**:
    post/poll handles I/O.

**Instructions for Use**:
```mermaid
%% Example of a timing diagram, -> straight line, --> dashed line, ->-> solid arrow
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