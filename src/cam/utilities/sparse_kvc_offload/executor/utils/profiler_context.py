# coding=utf-8
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

"""Profiler context manager for NPU profiling using torch_npu.profiler.

This module provides a context manager for profiling NPU operations during
inference. When profiling is disabled, the context manager becomes a no-op.
"""

import os
import torch_npu


class FakeContextManager:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    @staticmethod
    def step():
        return

    @staticmethod
    def stop():
        return


def create_profiler(enable_profiler=False, profile_save_path="prof", active=3, repeat=1, skip_first=3):
    if enable_profiler:
        os.makedirs(profile_save_path, exist_ok=True)
        experimental_config = torch_npu.profiler._ExperimentalConfig(
            profiler_level=torch_npu.profiler.ProfilerLevel.Level1,
            aic_metrics=torch_npu.profiler.AiCMetrics.PipeUtilization
        )
        profiler = torch_npu.profiler.profile(
            activities=[
                torch_npu.profiler.ProfilerActivity.NPU,
                torch_npu.profiler.ProfilerActivity.CPU,
            ],
            with_stack=False,
            record_shapes=False,
            profile_memory=False,
            experimental_config=experimental_config,
            schedule=torch_npu.profiler.schedule(
                wait=0,
                warmup=0,
                active=active,
                repeat=repeat,
                skip_first=skip_first
            ),
            on_trace_ready=torch_npu.profiler.tensorboard_trace_handler(profile_save_path)
        )
    else:
        profiler = FakeContextManager()

    return profiler


class ProfilerManager:
    """
    Profiler manager for profiling using torch_npu.profiler.
    This class provides a manager for profiling NPU operations during inference. 
    """
    def __init__(self, enable_profiler, profile_save_path):
        self.enable_profiler = enable_profiler
        self.profile_save_path = profile_save_path
        self.status = None
        self.current_profiler = FakeContextManager()

    def set_status(self, is_prefill):
        if not self.enable_profiler:
            return
        if self.status is None and is_prefill:
            self.status = "prefill"
            self.current_profiler = create_profiler(
                enable_profiler=self.enable_profiler,
                profile_save_path=os.path.join(self.profile_save_path, "prof", "prefill"), 
                active=1, repeat=1, skip_first=0)
            self.current_profiler.start()
        elif self.status == "prefill" and not is_prefill:
            self.status = "decode"
            self.current_profiler.stop()
            self.current_profiler = create_profiler(
                enable_profiler=self.enable_profiler, 
                profile_save_path=os.path.join(self.profile_save_path, "prof", "decode"))
            self.current_profiler.start()
        return

    def step(self):
        self.current_profiler.step()
    
    def __del__(self):
        if self.enable_profiler:
            self.current_profiler.stop()
