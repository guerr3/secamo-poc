from __future__ import annotations

import sys
from pathlib import Path


# Ensure project-root imports resolve before any similarly named vendored layer packages.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_LAYER_FRAGMENT = "terraform/modules/ingress/layers/ingress/python"


def _normalize(path_value: str) -> str:
    return path_value.replace("\\", "/").lower()


# Remove vendored lambda-layer path if present in environment-specific startup hooks.
sys.path[:] = [
    path_entry
    for path_entry in sys.path
    if _LAYER_FRAGMENT not in _normalize(path_entry)
]

# Prepend repository root so imports like "shared" and "activities" always map to source tree.
repo_root_str = str(_REPO_ROOT)
if repo_root_str not in sys.path:
    sys.path.insert(0, repo_root_str)
