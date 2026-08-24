"""Task: refactor a function (Group B4).

setup materializes mod.py with old_name() + caller; agent renames to new_name().
judge: grep def new_name present, def old_name absent, and the module imports +
calls new_name() without error.
"""

from __future__ import annotations

import os
import subprocess

from .base import Task

_BROKEN_MOD = (
    "def old_name():\n"
    "    return 42\n"
)


class RefactorFuncTask(Task):
    name = "refactor_func"

    def prompt(self) -> str:
        return (
            "TASK: refactor_func\n"
            "mod.py defines old_name(). Rename it to new_name() (keep behavior). "
            "The module must import and new_name() must be callable."
        )

    def setup(self, workspace_dir: str) -> None:
        os.makedirs(workspace_dir, exist_ok=True)
        with open(os.path.join(workspace_dir, "mod.py"), "w") as f:
            f.write(_BROKEN_MOD)

    def judge(self, workspace_dir: str) -> tuple[bool, str]:
        path = os.path.join(workspace_dir, "mod.py")
        if not os.path.exists(path):
            return False, "mod.py missing"
        with open(path) as f:
            content = f.read()
        if "def new_name" not in content:
            return False, "def new_name missing"
        if "def old_name" in content:
            return False, "def old_name still present"
        r = subprocess.run(
            ["python3", "-c", "import mod; assert mod.new_name() == 42"],
            cwd=workspace_dir, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True, "renamed + callable"
        return False, f"import/call failed: {r.stderr[-300:]}"
