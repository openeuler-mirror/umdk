"""Task base for Phase 3 fault-injection agent harness (Group B1).

A `Task` materializes a mini repo (setup) the agent must work in, and judges
pass/fail by inspecting observable artifacts (files / test exit codes) — NOT
LLM prose (spec risk R5 mitigation). The agent's ReAct loop is driven by
mock_vllm's scripted solution per task name; the judge is the ground truth.
"""

from __future__ import annotations

import abc
import os


class Task(abc.ABC):
    name: str

    @abc.abstractmethod
    def prompt(self) -> str:
        """The task brief given to the agent (system-prompt content)."""

    @abc.abstractmethod
    def setup(self, workspace_dir: str) -> None:
        """Materialize the mini repo the agent works in."""

    @abc.abstractmethod
    def judge(self, workspace_dir: str) -> tuple[bool, str]:
        """Inspect artifacts; return (pass, reason). MUST NOT parse LLM prose."""
