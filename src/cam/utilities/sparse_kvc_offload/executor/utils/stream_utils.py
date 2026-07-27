# coding=utf-8
# Copyright (c) 2026 Huawei Technologies Co., Ltd. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional, Union

import torch
import torchair as tng


class FakeContextManager:
    def __init__(self) -> None:
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        pass


def create_stream(stream_tag: str, exe_mode: Optional[str] = None) -> Union[str, torch.npu.Stream]:
    if exe_mode == "ge_graph":
        return stream_tag
    return torch.npu.Stream()


def use_native_stream_api(switch_flag: bool, exe_mode: Optional[str] = None):
    return switch_flag and exe_mode != "ge_graph"


def create_event(exe_mode: Optional[str] = None, switch_flag: bool = True):
    if use_native_stream_api(switch_flag, exe_mode):
        return torch.npu.Event()
    return None


def npu_stream_switch(
    switch_flag: bool,
    stream: Union[str, torch.npu.Stream],
    stream_priority: int = 0,
    exe_mode: Optional[str] = None,
):
    if not switch_flag:
        return FakeContextManager()

    if exe_mode == "ge_graph":
        return tng.scope.npu_stream_switch(stream, stream_priority)
    return torch.npu.stream(stream)


def npu_stream_switch_gegraph(switch_flag: bool, stream_tag: str, stream_priority: int = 0):
    '''Switch stream using tng.scope.npu_stream_switch on GE Graph.'''
    if switch_flag:
        return tng.scope.npu_stream_switch(stream_tag, stream_priority)
    else:
        return FakeContextManager()


def record_event(switch_flag: bool, events: tuple, idx: int, exe_mode: Optional[str] = None):
    """Records the specified NPU event if switch_flag is True."""
    if use_native_stream_api(switch_flag, exe_mode):
        events[idx].record()


def wait_event(switch_flag: bool, events: tuple, idx: int, exe_mode: Optional[str] = None):
    """
    Waits for the specified NPU event to complete if switch_flag is True.

    Note: torch.npu.Event.wait() does NOT support passing a stream explicitly now.
    Internally, it uses torch.npu.current_stream().
    """
    if use_native_stream_api(switch_flag, exe_mode):
        events[idx].wait()


def record_stream(
    switch_flag: bool,
    out: torch.Tensor,
    stream: Union[str, torch.npu.Stream],
    exe_mode: Optional[str] = None,
):
    """
    Conditionally tracks the tensor's lifecycle on a specific NPU stream
    to prevent premature memory deallocation during asynchronous operations.
    """
    if use_native_stream_api(switch_flag, exe_mode):
        out.record_stream(stream)


def wait_tensor(
    switch_flag: bool,
    self: torch.Tensor,
    dependency: Union[str, torch.npu.Stream],
    exe_mode: Optional[str] = None,
):
    """
    Controls multi-stream execution synchronization during graph execution.
    Forces the consumer op (associated with 'self') to wait for the completion 
    of the producer op (associated with 'dependency') to ensure correct temporal ordering.
    """
    if switch_flag and exe_mode == "ge_graph":
        tng.scope.npu_wait_tensor(self, dependency)