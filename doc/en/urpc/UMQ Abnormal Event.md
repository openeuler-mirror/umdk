# UMQ Abnormal Event

## Overview
UMQ Abnormal Event is the ability provided by UMQ components to report asynchronous events.

**Overview**:
    (1) If the application experiences port status abnormalities, the hardware will report the abnormal event.
    (2) The application retrieves the type of exception and the specific exception object: umqh or port. After handling the exception, the application confirms with umq that exception handling has been completed.

**Application Scenarios**:
    An anomaly occurred inside umq.

**Note**:
    If an exception event occurs that occurred with an object, the exception acknowledgment interface (umq_ack_async_event) must be called before the object can be deleted.

**Instructions for Use**:
    (1) The user calls `umq_async_event_fd_get`, inputting the device's `trans_info` (which must match the `trans_info` passed to `umq_init`) to obtain the file descriptor (fd) for the exception event being monitored.

    (2) The user uses the epoll mechanism to monitor the readable events of the fd for the exception event. Once a readable event is available, the user can use the `umq_get_async_event` interface to retrieve the exception event.

    (3) The user calls the `umq_get_async_event` interface to retrieve the exception event.

    (4) The user performs categorized processing based on the exception event type, such as printing log information.

    (5) The user calls the `umq_ack_async_event` interface to notify Umq that the exception has been processed.

**Reference procedure for users to recover from faults after reporting abnormal events**:
    (1) When the UMQ_EVENT_QH_ERR exception event is reported, it indicates that the umqh object has encountered an error. The original_code (the event code reported by the original underlying component) can be printed in the log. Find the corresponding umqh. The handle of the event object element.umqh can be obtained. The faulty umqh can be isolated according to business needs, or the umqh can be destroyed and a new umqh can be recreated.

