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

from dataclasses import dataclass, replace
from typing import Optional, Dict
import torch


@dataclass
class ForwardMetaData:
    """Metadata passed during model forward pass"""
    is_prefill: bool = False
    attention_mask: Optional[torch.Tensor] = None
    kv_len: Optional[torch.Tensor] = None
    actual_seq_lengths_kv: Optional[torch.Tensor] = None
    actual_seq_lengths_q: Optional[torch.Tensor] = None
    actual_seq_lengths_cu_kv: Optional[torch.Tensor] = None
    actual_seq_lengths_cu_q: Optional[torch.Tensor] = None
    actual_seq_lengths_cu_list_kv: Optional[list] = None
    actual_seq_lengths_cu_list_q: Optional[list] = None
    actual_seq_lengths_list_kv: Optional[list] = None
    actual_seq_lengths_list_q: Optional[list] = None
    prompt_tokens: int = 0
    block_table: Optional[Dict[str, torch.Tensor]] = None
    slot_mapping: Optional[Dict[str, torch.Tensor]] = None

_forward_metadata = ForwardMetaData()


def get_forward_metadata():
    return _forward_metadata


def set_forward_metadata(**kwargs):
    global _forward_metadata
    _forward_metadata = replace(_forward_metadata, **kwargs)


def reset_forward_metadata():
    global _forward_metadata
    _forward_metadata = ForwardMetaData()
