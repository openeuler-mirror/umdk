# coding=utf-8
# This code is copied from vllm implementations.
# (https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/model_loader/utils.py)
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
"""Utilities for selecting and loading models."""
import contextlib
import warnings
from contextlib import contextmanager
from transformers.utils import logging

import torch
logger = logging.get_logger(__name__)


@contextlib.contextmanager
def set_default_torch_dtype(dtype: torch.dtype):
    """Sets the default torch dtype to the given dtype."""
    old_dtype = torch.get_default_dtype()
    torch.set_default_dtype(dtype)
    yield
    torch.set_default_dtype(old_dtype)
