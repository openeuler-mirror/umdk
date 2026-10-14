#!/usr/bin/env python3
"""Check relative Markdown links in Agent assets and repository entry docs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

AGENT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = AGENT_ROOT.parent
SCAN_DIRS = ("skills", "knowledge", "cases", "workflows")
AGENT_ROOT_FILES = ("README.md", "AGENTS.md")
REPOSITORY_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "src/cam/AGENTS.md",
    "src/cam/README.md",
)
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def iter_md() -> list[Path]:
    files = [
        AGENT_ROOT / name
        for name in AGENT_ROOT_FILES
        if (AGENT_ROOT / name).is_file()
    ]
    for name in SCAN_DIRS:
        root = AGENT_ROOT / name
        if root.is_dir():
            files.extend(sorted(root.rglob("*.md")))
    files.extend(
        REPO_ROOT / name
        for name in REPOSITORY_FILES
        if (REPO_ROOT / name).is_file()
    )
    claude_root = REPO_ROOT / ".claude"
    if claude_root.is_dir():
        files.extend(sorted(claude_root.rglob("*.md")))
    return sorted(set(files))


def targets(href: str) -> str | None:
    href = href.strip().strip("<>")
    if not href or href.startswith(SKIP_PREFIXES):
        return None
    if "://" in href:
        return None
    return href.split("#", 1)[0]


def main() -> int:
    broken: list[str] = []
    for path in iter_md():
        text = path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            rel = targets(match.group(1))
            if not rel:
                continue
            dest = (path.parent / rel).resolve()
            if not dest.exists():
                broken.append(f"{path.relative_to(REPO_ROOT)} -> {rel}")
    if broken:
        print(f"{len(broken)} broken relative links:")
        for item in broken:
            print(f"  {item}")
        return 1
    print("0 broken relative links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
