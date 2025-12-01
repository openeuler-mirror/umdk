# UMQ Abnormal Event

## 功能简介
UMQ Abnormal Event作为UMQ组件提供的上报异步事件的能力。

**概述**:
    (1) 应用发生端口状态异常等情况下，硬件将上报异常事件。
    (2) 应用获取发生的异常类型、具体的异常的对象：umqh 或者port。应用处理完异常后，向umq确认已经完成异常处理。

**应用场景**：
    umq异常场景

**注意事项**：
    如果获得过对象产生的异常事件时，必须调用确认异常接口（umq_ack_async_event），然后才能删除该对象。

**使用说明**：
    (1) 用户调用umq_async_event_fd_get, 输入设备的trans_info（需要与umq_init传入的trans_info要一致）获取监听异常事件的fd
    (2) 用户使用epoll机制监听异常事件上fd的可读事件，一旦有可读事件可以使用umq_get_async_event接口获取异常事件
    (3) 用户调用umq_get_async_event接口获取异常事件；
    (4) 用户根据异常事件类型，进行分类处理，例如打印log信息；
    (5) 用户调用umq_ack_async_event接口，通知umq已经处理完异常。

**上报异常事件后，用户恢复故障参考流程**：
    (1) 当上报UMQ_EVENT_QH_ERR异常事件后，表示umqh对象出现了错误，可以在日志里打印下original_code(原始的底层组件上报的事件码)
        找到对应umqh，事件对象element.umqh可以获取到对象的句柄，根据业务需要隔离掉出故障的umqh，或者销毁umqh，重新建新的umqh。

