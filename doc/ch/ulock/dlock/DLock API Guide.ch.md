# DLock相关对外接口指南

接口文件列表： 
服务端对外接口：[dlock_server_api.h](../../../../src/ulock/dlock/lib/include/dlock_server_api.h) 
客户端对外接口：[dlock_client_api.h](../../../../src/ulock/dlock/lib/include/dlock_client_api.h) 
对外数据结构列表：[dlock_types.h](../../../../src/ulock/dlock/lib/include/dlock_types.h)

## 服务端对外接口
1. 使用dserver_lib_init初始化DLock服务端库上下文；
2. 调用server_start来启动primary server，初始化服务端资源，创建服务端管理面和数据面请求处理线程；
3. 使用server_stop销毁server，结束server对应的线程，并释放其占用的资源；
4. 调用dserver_lib_deinit反初始化DLock服务端库上下文，遍历所有server，结束每个server创建的服务线程，并释放相应资源；
5. 如需获取统计信息，可以调用get_server_debug_stats获取服务端实例server_id的数据面异常统计信息；使用clear_server_debug_stats可以清理服务端实例server_id的数据面异常统计信息，将异常统计项计数清零。

## 客户端对外接口
### 管理面API：
1. 调用dclient_lib_init初始化DLock客户端库上下文；
2. 使用client_init创建一个客户端实例并连接到服务端，服务端会分配一个唯一的客户端编号；
3. 调用client_deinit注销已创建的客户端实例，向服务端发送客户端反注册请求；
4. 如果需要将已创建的客户端实例重新注册到服务端，则需使用client_reinit接口，此时会重新创建client_id对应的客户端实例，保留原来的客户端锁状态，并重新连接到primary server;
5. 在client_reinit接口被调用后，需使用client_reinit_done接口通知服务端：客户端实例重新注册流程结束。故障恢复场景下，通知服务端本客户端实例的所有锁状态都已同步到服务端；
6. 使用client_heartbeat接口可以指定客户端实例向服务端进行心跳检测；
7. 调用dclient_lib_deinit来反初始化DLock客户端库上下文。

### 锁的基本操作API：
1. 客户端调用get_lock接口，向服务端创建或获取分布式锁对象；调用release_lock接口，向服务端释放已获取的分布式锁对象；对分布式锁对象进行trylock/unlock/lock/lock_extend等锁操作时，需保证已提前通过get_lock操作成功获取相应锁对象，结束所有锁操作后，需要通过release_lock释放相应锁对象；
3. 客户端调用trylock接口对锁对象进行非阻塞加锁操作，并返回操作结果；
4. 客户端调用lock接口对锁对象进行阻塞加锁操作，直到加锁成功或者操作超时；
5. 客户端调用unlock接口对锁对象进行解锁操作；
6. 客户端调用lock_request_async接口进行异步锁操作请求，再调用lock_result_check接口进行该请求的结果查询。此组接口为异步接口，trylock/unlock/lock/lock_extend为同步接口，由使用者按需选择；
7. 为避免出现一个客户端一直持有锁，导致其他客户端无法获得锁的情况，加锁成功后会设置一个有效期，超过有效期的锁自动失效。持有锁的客户端可以调用lock_extend接口请求延长锁有效期，服务端根据锁的请求状况决定是否延长，并返回结果。读写锁没有加锁有效期，也不支持lock_extend操作；
8. 在故障恢复场景下，客户端实例需向服务端同步本地分布式锁对象状态。当Primary Server故障后，重新拉起一个Primary Server，通过update_all_locks接口可以将client本地缓存的锁状态信息同步到Primary Server，过程采用batch更新，可能需要多轮收发数据才能完成所有锁状态的同步工作。本接口会单独创建一个线程用于发送update_all_locks请求消息，主线程用于接收回复并处理。

### 锁的批量操作API：
1. batch_get_lock用于客户端实例向服务端批量创建或获取分布式锁对象；
2. batch_release_lock用于指定客户端实例向服务端批量释放获取的分布式锁对象；
3. batch_trylock用于客户端实例向服务端批量对指定锁对象进行非阻塞加锁操作，并返回锁状态数据；
4. batch_unlock用于客户端实例向服务端批量对指定锁对象进行解锁操作，并返回锁状态数据；
5. batch_lock_extend用于客户端实例向服务端批量进行延长用锁时限操作。

### 分布式对象操作API：
1. 客户端使用umo_atomic64_create接口创建分布式状态对象，并赋予初始值init_val；
2. 客户端使用umo_atomic64_destroy接口销毁创建的分布式状态对象；
3. 客户端使用umo_atomic64_get接口可获取创建的分布式状态对象；
4. 客户端获取分布式状态对象后，可调用umo_atomic64_faa接口，向服务端请求对该对象做原子Fetch and Add操作，返回原值；
5. 客户端获取分布式状态对象后，可调用umo_atomic64_cas接口，向服务端请求对该对象做原子Compare and Swap操作，返回修改后的新值；
6. 客户端获取分布式状态对象后，可调用umo_atomic64_get_snapshot接口，向服务端请求获取该对象当前值。
7. 客户端使用umo_atomic64_release接口可以释放已获取的分布式状态对象。

### 客户端统计API：
1. get_client_debug_stats用于获取客户端实例client_id的数据面异常统计信息；
2. clear_client_debug_stats用于清理客户端实例client_id的数据面异常统计信息，将异常统计项计数清零。

### 故障恢复场景API：
1. 服务端调用server_start接口启动一个新Primary Server，分配一个server_id，根据现存的Client数目恢复锁状态；
2. 客户端调用client_reinit接口，client_id不变，保留当前锁状态，重新创建该client，并连接到新Primary Server；
3. 客户端调用update_all_locks接口，同步锁状态到新Primary Server；
4. 锁状态同步完成后，客户端调用client_reinit_done接口，告知Primary Server，本Client的所有锁状态都已同步完成，客户端实例重新注册流程结束；
5. 客户端调用lock_extend去服务端检查当前锁状态并更新到本地；
6. Server故障恢复后，分布式状态对象信息会全部失效清空，若有必要，则需应用调用DLock客户端umo_atomic64_create和umo_atomic64_get接口，重新创建和获取相应对象，在创建对象时，传入初始值。