Release Notes
===================
Version
------------
*   v25.12.0 - 2026/06/30
New Features
------------
* URMA
* UMQ
  * Support CTP transport mode
  * Support time-division multiplexing of jetty pool
  * Support application layer transmission order
  * Support latency statistics in detail
  * Support small memory pool
* UMS
  * Support UB TokenValue secure transmission
    UMS provides ums_agent to exchange tokenValue through TLS channel to provide strict security solution.
    Recommend to use only in cases with extreme security requirement. For performance critical cases please turn off the config for this feature.
Version
------------
*   v25.12.0 - 2025/12/30

New Features
------------
* URMA
  * Bonding Device Characteristics
  (1) Jetty Multipath Mode:
      1. Uses CTP transmission channels with two modes: RM and RC. Local loopback transmission is not supported.
      2. Maximum message size: 4KB.
      3. RM Mode: Provides TAACK reliability guarantee but lacks retransmission mechanisms. Applicable to hot migration and HCOM scenarios (self-establishing jetty links).

  (2) Jetty Single-Path Mode:
      1. Uses TP transmission channels with RC mode only. Supports local loopback transmission.
      2. Maximum message size: 64KB.
      3. RC Mode: Applicable to URPC, dlock, and HCOM (standard jetty) scenarios.

  (3) JFS/JFR Multipath Mode:
      1. Uses CTP transmission channels with RM mode only. Local loopback transmission is not supported.
      2. Maximum message size: 4KB.
      3. RM Mode: Provides TAACK reliability guarantee but lacks retransmission mechanisms.

* URPC
  * Timeout Mechanism
    Performs timeout detection and control on request/response operations to avoid infinite waiting.
  * Disable Statistics
    Turns off URPC statistics to reduce performance overhead. Used in performance-sensitive or memory-constrained scenarios.
  * Connection Keep-Alive Mechanism
    Sends heartbeats periodically to check the liveness of the client and server, preventing dead connections.
  * Retrieve Function Information
    Allows clients to obtain server-side function information for easier dynamic discovery and invocation.
  * Channel Many-to-One
    Multiple channels from a single client can share the same server channel.
  * UMQ Message Queue
    Provides two programming models: 1. Message enqueue/dequeue capability; 2. Post/Poll.
  * UMQ Security Verification
    Supports enabling token-based security verification for messages.

* DLock
  * Client Management
    The DLock client process can create multiple client instances to connect to the DLock server. Applications can use the client management APIs provided by DLock to perform operations such as initializing/deinitializing the client library context and registering/deregistering client instances.
  * Server Management
    Applications can use the server management APIs provided by DLock to perform operations such as initializing/deinitializing the server library context and creating/destroying the Primary Server.
  * Distributed Lock Management
    Supports basic and batch operations for atomic locks, fair locks and read-write locks, including fundamental distributed lock operations such as get_lock, release_lock, trylock, unlock, lock, and lock_extend, and etc.
  * Distributed Object Management
    Supports operations such as creating, destroying, getting and releasing distributed objects. Also supports atomic FAA/CAS operations on distributed objects and snapshot retrieval.
  * Heartbeat Detection
    DLock supports heartbeat detection between client and server.
  * Failure Recovery
    In the event of a DLock Primary Server failure, a new Primary Server can be created to restore the global lock state from the clients.
  * Secure Transmission
    Communication between DLock Client and DLock Server supports encryption for content protection.
  * DFX Functionality
    DLock provides DFX features such as log printing and querying of exception statistics.

* UMS
  * Compatible with standard socket APIs
    UMS maintains compatibility with standard Socket APIs. Users can seamlessly utilize standard socket APIs over the UB network simply by setting the protocol family type of the socket.
  * Device Discovery
    Find network devices supporting UMDK
  * Link Management
    Full lifecycle management of underlay UB links, including creation and destruction.
  * Connection Management
    Full lifecycle management of UMS socket, including creation and destruction.
  * Data Transmission and Reception
    Data sending and receiving based on UMS sockets.
  * DFX Capability
    Provides DFX capabilities, including link interruption detection and real-time status monitoring of UMS socket.
  * Transparent Replacement Tool:ums_run
    Provides the ums_run tool, enabling users to activate UMS without modifying application code.