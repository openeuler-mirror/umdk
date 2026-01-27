# DLock API Guide

API lists:
Server APIs：[dlock_server_api.h](../../../../src/ulock/dlock/lib/include/dlock_server_api.h) 
Client APIs：[dlock_client_api.h](../../../../src/ulock/dlock/lib/include/dlock_client_api.h) 
External Data Structures：[dlock_types.h](../../../../src/ulock/dlock/lib/include/dlock_types.h)


## Server APIs
1. Use "dserver_lib_init" to initialize the DLock server library context.
2. Call "server_start" to launch the primary server, initialize server resources, and create server management plane and data plane request processing threads.
3. Use "server_stop" to destroy a server instance, terminate its associated threads, and release its allocated resources.
4. Call "dserver_lib_deinit" to deinitialize the DLock server library context. This function iterates through all server instances, terminates their service threads, and releases corresponding resources.
5. To retrieve debug statistics, call "get_server_debug_stats" to obtain data plane exception statistics for the server instance identified by server_id. Use "clear_server_debug_stats" to clear these statistics for server instance, resetting all exception counters to zero.

## Client APIs
### Control Plane APIs:
1. Call "dclient_lib_init" to initialize the DLock client library context.
2. Use "client_init" to create a client instance and connect it to the server. The server will assign a unique client ID.
3. Call "client_deinit" to de-register a created client instance, sending a client de-registration request to the server.
4. To re-register an existing client instance with the server, use the "client_reinit" interface. This recreates the client instance with the same client_id, preserves its previous lock state, and reconnects to the primary server.
5. After calling "client_reinit", the "client_reinit_done" interface must be used to notify the server that the client instance re-registration process is complete. In failure recovery scenarios, this informs the server that all lock states for this client have been synchronized.
6. Use "client_heartbeat" for a specific client instance to perform a heartbeat check with the server.
7. Call "dclient_lib_deinit" to deinitialize the DLock client library context.

### Basic Lock Operation APIs:
1. The client calls "get_lock" to create or acquire a distributed lock from the server. It calls "release_lock" to release an acquired distributed lock back to the server. Before performing lock operations (e.g., "trylock", "unlock", "lock", "lock_extend") on a distributed lock, the client must have successfully acquired that lock via "get_lock". After completing all lock operations, the lock must be released using "release_lock".
2. The client calls "trylock" to perform a non-blocking lock acquisition operation on a lock and returns the operation result.
3. The client calls "lock" to perform a blocking lock acquisition operation on a lock, which continues until the lock is acquired or the operation times out.
4. The client calls "unlock" to perform an unlock operation on a lock.
5. The client calls "lock_request_async" to make an asynchronous lock operation request, and then uses "lock_result_check" to query the result of that request. This pair of interfaces provides asynchronous functionality, while "trylock", "unlock", "lock", and "lock_extend" are synchronous interfaces. Users can choose according to their needs.
6. To prevent a client from holding a lock indefinitely and blocking others, a validity period is set upon successful lock acquisition. Locks expire automatically after this period. A client holding a lock can call "lock_extend" to request an extension of the lock's validity period. The server decides whether to grant the extension based on the lock's status and returns the result. Read-write locks do not have a validity period and do not support the "lock_extend" operation.
7.In failure recovery scenarios, a client instance must synchronize its local distributed lock state with the server. After a Primary Server failure and subsequent restart of a new Primary Server, the "update_all_locks" interface can be used to synchronize the lock state information cached locally by the client to the new Primary Server. This process uses batch updates and may require multiple rounds of data exchange to complete the synchronization of all lock states. This interface creates a separate thread for sending the "update_all_locks" request messages, while the main thread is used for receiving and processing the replies.

### Batch Lock Operation APIs:
1. "batch_get_lock" is used by a client instance to batch create or acquire distributed locks from the server.
2. "batch_release_lock" is used by a specified client instance to batch release acquired distributed locks to the server.
3. "batch_trylock" is used by a client instance to batch perform non-blocking lock acquisition operations on specified locks from the server and returns lock statuses.
4. "batch_unlock" is used by a client instance to batch perform unlock operations on specified locks from the server and returns lock statuses.
5. "batch_lock_extend" is used by a client instance to batch request lock validity period extensions from the server.

### Distributed Object Operation APIs:
1. The client uses "umo_atomic64_create" to create a distributed object, assigning it an initial value init_val.
2. The client uses "umo_atomic64_destroy" to destroy a distributed object.
3. The client uses "umo_atomic64_get" to acquire a created distributed object.
4. After acquiring the distributed object, the client can call "umo_atomic64_faa" to request the server to perform an atomic Fetch and Add operation on the object, returning the original value.
5. After acquiring the distributed object, the client can call "umo_atomic64_cas" to request the server to perform an atomic Compare and Swap operation on the object, returning the new value after modification.
6. After acquiring the distributed object, the client can call "umo_atomic64_get_snapshot" to request the server to get the current value of the object.
7. The client uses "umo_atomic64_release" to release an acquired distributed object.

### Client Statistics APIs:
1. "get_client_debug_stats" is used to obtain data plane exception statistics for the client instance identified by client_id.
2. "clear_client_debug_stats" is used to clear these statistics for the client instance identified by client_id, resetting all exception counters to zero.

### Failure Recovery Scenario APIs:
1. The server calls "server_start" to launch a new Primary Server, assigns it a server_id, and recovers the lock state based on the number of existing Clients.
2. The client then calls "client_reinit". The client_id remains unchanged, the current lock state is preserved, the client is recreated, and it connects to the new Primary Server.
3. The client calls "update_all_locks" to synchronize its lock state with the new Primary Server.
4. After lock state synchronization is complete, the client calls "client_reinit_done" to inform the Primary Server that all its lock states have been synchronized, concluding the client instance re-registration process.
5. The client calls "lock_extend" to check the current lock state at the server and update its local state accordingly.
6. After server failure recovery, distributed state object information becomes invalid and is cleared. If necessary, the application must use the DLock client interfaces "umo_atomic64_create" and "umo_atomic64_get" to recreate and reacquire the respective objects, providing the initial value during object creation.