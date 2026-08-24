"""Task: add docstrings to a module (Group B3).

setup materializes mod.py with 3 undocumented funcs; agent adds docstrings.
judge uses python3 -m py_compile + an AST check (ast.get_docstring non-null for
each top-level func) — no external linter dependency.
"""

from __future__ import annotations

import ast
import os
import subprocess

from .base import Task

_BROKEN_MOD = (
    "def f():\n    return 1\n\n"
    "def g():\n    return 2\n\n"
    "def h():\n    return 3\n"
)


class AddDocstringTask(Task):
    name = "add_docstring"

    def prompt(self) -> str:
        return (
            "TASK: add_docstring\n"
            "mod.py has three undocumented functions. Add a docstring to "
            "the module and to each function."
        )

    def setup(self, workspace_dir: str) -> None:
        os.makedirs(workspace_dir, exist_ok=True)
        with open(os.path.join(workspace_dir, "mod.py"), "w") as f:
            f.write(_BROKEN_MOD)

    def judge(self, workspace_dir: str) -> tuple[bool, str]:
        path = os.path.join(workspace_dir, "mod.py")
        if not os.path.exists(path):
            return False, "mod.py missing"
        r = subprocess.run(
            ["python3", "-m", "py_compile", "mod.py"],
            cwd=workspace_dir, capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return False, f"py_compile failed: {r.stderr[-300:]}"
        with open(path) as f:
            tree = ast.parse(f.read())
        if ast.get_docstring(tree) is None:
            return False, "module docstring missing"
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and ast.get_docstring(node) is None:
                return False, f"func {node.name} missing docstring"
        return True, "all docstrings present"
