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

"""Centralized logging configuration for the executor.

Single source of truth for log format and level.  Library modules must use
``logger = logging.getLogger(__name__)`` and never call ``basicConfig``;
entry points (server.py, model_runner.py, offline infer.py) call
``setup_logging()`` once at process start.
"""

from __future__ import annotations

import logging
import os
from typing import Optional


LOG_FORMAT = "[%(levelname)s][%(asctime)s.%(msecs)03d][%(filename)s:%(lineno)d] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Third-party libraries whose default INFO/DEBUG output is too chatty for the
# foreground process logs.  Pinned to WARNING regardless of the executor level.
_NOISY_LOGGERS = ("paramiko", "httpx", "httpcore", "urllib3")


def _resolve_level(level: Optional[str | int]) -> int:
    if level is None:
        level = os.environ.get("CANN_RECIPES_LOG_LEVEL", "INFO")
    if isinstance(level, int):
        return level
    resolved = getattr(logging, level.upper(), None)
    if not isinstance(resolved, int):
        raise ValueError(f"Unknown log level: {level!r}")
    return resolved


def setup_logging(level: Optional[str | int] = None) -> None:
    """Configure the root logger.  Safe to call from each entry point.

    Args:
        level: Override level. If None, reads ``CANN_RECIPES_LOG_LEVEL`` env
               (default INFO).  Accepts level name ("INFO", "DEBUG", ...) or
               an int.
    """
    resolved = _resolve_level(level)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))

    root = logging.getLogger()
    # Replace any existing handlers so multiple calls don't double-print and
    # so a stale ``basicConfig`` from elsewhere can't override the format.
    root.handlers = [handler]
    root.setLevel(resolved)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
