from __future__ import annotations

import ast
from pathlib import Path


def test_run_worker_module_has_main_entrypoint() -> None:
    source_path = Path("workers/run_worker.py")
    module = ast.parse(source_path.read_text(encoding="utf-8"))

    has_main_guard = False
    for node in module.body:
        if not isinstance(node, ast.If):
            continue

        test = node.test
        if not isinstance(test, ast.Compare):
            continue
        if not isinstance(test.left, ast.Name) or test.left.id != "__name__":
            continue
        if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
            continue
        if len(test.comparators) != 1:
            continue

        comparator = test.comparators[0]
        if isinstance(comparator, ast.Constant) and comparator.value == "__main__":
            has_main_guard = True
            break

    assert has_main_guard, "workers.run_worker must expose a __main__ entrypoint for Docker startup."