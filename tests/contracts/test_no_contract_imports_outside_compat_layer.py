from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

SCOPED_ROOTS = [
    REPO_ROOT / "activities",
    REPO_ROOT / "connectors",
    REPO_ROOT / "shared",
    REPO_ROOT / "workers",
    REPO_ROOT / "workflows",
    REPO_ROOT / "tests",
    REPO_ROOT / "terraform" / "modules" / "ingress" / "src",
]

IMPORT_PATTERN = re.compile(r"^\s*(from|import)\s+contracts(\.|\b)", re.MULTILINE)


def test_no_runtime_imports_from_legacy_contracts() -> None:
    violations: list[str] = []

    for root in SCOPED_ROOTS:
        if not root.exists():
            continue
        for py_file in root.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            if IMPORT_PATTERN.search(content):
                violations.append(str(py_file.relative_to(REPO_ROOT)).replace("\\", "/"))

    assert not violations, "Legacy contracts imports are forbidden: " + ", ".join(sorted(violations))
