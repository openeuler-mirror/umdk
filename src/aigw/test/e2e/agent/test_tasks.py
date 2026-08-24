"""Judge unit tests (Phase 3 Group B5) — prove each judge catches pass AND fail
(spec R5: judges must check observable artifacts, and must fail when the agent
didn't actually do the work). No AIGW / no agent loop needed."""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from tasks.add_docstring import AddDocstringTask
from tasks.fix_failing_test import FixFailingTestTask
from tasks.refactor_func import RefactorFuncTask


@pytest.fixture
def workspace():
    d = tempfile.mkdtemp(prefix="phase3-task-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---- fix_failing_test ----
def test_fix_failing_test_judge_pass(workspace):
    t = FixFailingTestTask()
    t.setup(workspace)
    # the fix: overwrite calc.py with the correct add
    with open(os.path.join(workspace, "calc.py"), "w") as f:
        f.write("def add(a, b):\n    return a + b\n")
    ok, reason = t.judge(workspace)
    assert ok, reason


def test_fix_failing_test_judge_fail_when_broken(workspace):
    t = FixFailingTestTask()
    t.setup(workspace)  # leaves calc.py broken (a - b)
    ok, _ = t.judge(workspace)
    assert not ok


# ---- add_docstring ----
def test_add_docstring_judge_pass(workspace):
    t = AddDocstringTask()
    t.setup(workspace)
    with open(os.path.join(workspace, "mod.py"), "w") as f:
        f.write(
            '"""mod doc."""\n'
            'def f():\n    """f doc."""\n    return 1\n'
            'def g():\n    """g doc."""\n    return 2\n'
            'def h():\n    """h doc."""\n    return 3\n'
        )
    ok, reason = t.judge(workspace)
    assert ok, reason


def test_add_docstring_judge_fail_when_missing(workspace):
    t = AddDocstringTask()
    t.setup(workspace)  # all funcs undocumented
    ok, _ = t.judge(workspace)
    assert not ok


# ---- refactor_func ----
def test_refactor_judge_pass(workspace):
    t = RefactorFuncTask()
    t.setup(workspace)
    with open(os.path.join(workspace, "mod.py"), "w") as f:
        f.write("def new_name():\n    return 42\n")
    ok, reason = t.judge(workspace)
    assert ok, reason


def test_refactor_judge_fail_when_not_renamed(workspace):
    t = RefactorFuncTask()
    t.setup(workspace)  # still old_name
    ok, _ = t.judge(workspace)
    assert not ok


def test_refactor_judge_fail_when_both_present(workspace):
    """Edge: agent added new_name but left old_name too."""
    t = RefactorFuncTask()
    t.setup(workspace)
    with open(os.path.join(workspace, "mod.py"), "w") as f:
        f.write(
            "def new_name():\n    return 42\n\n"
            "def old_name():\n    return 42\n"
        )
    ok, _ = t.judge(workspace)
    assert not ok
