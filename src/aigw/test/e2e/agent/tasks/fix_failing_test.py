"""Task: fix a failing test (Group B2).

setup materializes a 2-file mini Python repo with a bug in calc.py; the agent
must locate + fix it. judge runs pytest; pass iff exit 0. The mock_vllm stub
script (`fix_failing_test`) writes the corrected calc.py, so a healthy agent
loop drives judge to pass; a halted agent (fault scenario) leaves calc.py
broken and judge fails.
"""

from __future__ import annotations

import os
import subprocess

from .base import Task

# The broken mini repo. The agent (driven by mock_vllm's scripted solution)
# overwrites calc.py with the fixed version; judge then sees green.
_BROKEN_CALC = "def add(a, b):\n    return a - b\n"
_TEST_CALC = "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"


class FixFailingTestTask(Task):
    name = "fix_failing_test"

    def prompt(self) -> str:
        return (
            "TASK: fix_failing_test\n"
            "The repo has a failing test. Read calc.py and test_calc.py, "
            "fix the bug, then run pytest to confirm."
        )

    def setup(self, workspace_dir: str) -> None:
        os.makedirs(workspace_dir, exist_ok=True)
        with open(os.path.join(workspace_dir, "calc.py"), "w") as f:
            f.write(_BROKEN_CALC)
        with open(os.path.join(workspace_dir, "test_calc.py"), "w") as f:
            f.write(_TEST_CALC)

    def judge(self, workspace_dir: str) -> tuple[bool, str]:
        if not os.path.exists(os.path.join(workspace_dir, "test_calc.py")):
            return False, "test_calc.py missing"
        r = subprocess.run(
            ["python3", "-m", "pytest", "test_calc.py", "-q"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode == 0:
            return True, "pytest green"
        return False, f"pytest failed (rc={r.returncode}):\n{r.stdout[-400:]}"
